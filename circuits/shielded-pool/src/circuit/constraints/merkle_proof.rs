use crate::circuit::consts::TEST_TREE_DEPTH;
use crate::circuit::{
    constraints::poseidon::solana_poseidon_chip::SolanaPoseidonChip, consts::MAX_CHUNKS,
};
use crate::imt::off_chain_imt::MerkleProof;
use crate::Fr;
use halo2_base::{
    gates::{circuit::builder::BaseCircuitBuilder, GateChip, GateInstructions},
    AssignedValue, Context,
};

/// NOTE:
/// TREE_DEPTH is the depth of the tree and we start counting from 0 (leaf level is 0)
pub struct MerkleProofChip<const TREE_DEPTH: usize> {
    gate: GateChip<Fr>,
}

impl<const TREE_DEPTH: usize> MerkleProofChip<TREE_DEPTH> {
    pub fn new() -> Self {
        Self {
            gate: GateChip::default(),
        }
    }

    /// leaf - we prove that this leaf node is part of the tree
    /// siblings_path - merkle proof path
    /// siblings_side - side on which node on the path is (0 for left, 1 for right)
    pub fn calculate_root_from_proof(
        &self,
        ctx: &mut Context<Fr>,
        leaf: AssignedValue<Fr>, // in circuit we can only operate on AssignedValues
        siblings_path: &[AssignedValue<Fr>; TREE_DEPTH],
        siblings_side: &[AssignedValue<Fr>; TREE_DEPTH],
        solana_poseidon_chip: &SolanaPoseidonChip<MAX_CHUNKS>,
    ) -> AssignedValue<Fr> {
        let mut current_node = leaf;
        for i in 0..TREE_DEPTH {
            let sibling = siblings_path[i];
            // make sure side is 0 or 1 so that we can use it as boolean in gate.select
            self.gate.assert_bit(ctx, siblings_side[i]);
            // normally we would have:
            // left = siblings_side[i] == 0 ? sibling : current_node;
            // but in circuit we can not do simple == 0, and siblings_side[i] will be treated as boolean
            // where 0 - false and 1 - true
            // with boolean it would be:
            // left = !siblings_side[i] ? sibling : current_node;
            // but to avoid additional negation gate we need to invert it:
            // left = siblings_side[i] ? current_node : sibling;
            let left = self
                .gate
                .select(ctx, current_node, sibling, siblings_side[i]); // under the hood:  sel * (a - b) + b
            let right = self
                .gate
                .select(ctx, sibling, current_node, siblings_side[i]);

            current_node = solana_poseidon_chip.hash_2_inputs(ctx, left, right);
        }

        // last calculated node is root
        current_node
    }
}

/*
 * Notes:
 *
 * Q1: can I invert the 0/1 value, basically get the result of !sibling_side[i] ?
 * -> Yes, using not gate:
 * let is_left = self.gate.not(ctx, siblings_side[i]);  // under the hood it simply returns:  1 - x
 */

pub fn build_pool_membership_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    // private witness(advice) values
    merkle_proof: MerkleProof,
) {
    let poseidon_chip = SolanaPoseidonChip::<MAX_CHUNKS>::new();
    let merkle_proof_chip = MerkleProofChip::<TEST_TREE_DEPTH>::new();
    let ctx = builder.main(0);

    // load witnesses (advice columns)
    let leaf_witness = ctx.load_witness(merkle_proof.leaf);
    let siblings_path_witness =
        std::array::from_fn(|i| ctx.load_witness(merkle_proof.siblings_path[i]));
    let siblings_side_witness =
        std::array::from_fn(|i| ctx.load_witness(Fr::from(merkle_proof.siblings_side[i] as u64)));

    let root_from_merkle_proof = merkle_proof_chip.calculate_root_from_proof(
        ctx,
        leaf_witness,
        &siblings_path_witness,
        &siblings_side_witness,
        &poseidon_chip,
    );

    builder.assigned_instances[0].push(root_from_merkle_proof);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native;
    use crate::imt::off_chain_imt::OffChainImt;
    use halo2_base::halo2_proofs::dev::{MockProver, VerifyFailure};
    use halo2_base::halo2_proofs::halo2curves::ff::Field;

    // Build the membership circuit for a given proof + expected root and run the MockProver.
    fn run_circuit(merkle_proof: MerkleProof, expected_root: Fr) -> Result<(), Vec<VerifyFailure>> {
        let k: usize = 16;
        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);
        build_pool_membership_circuit(&mut builder, merkle_proof);
        builder.calculate_params(Some(9));
        MockProver::run(k as u32, &builder, vec![vec![expected_root]])
            .unwrap()
            .verify()
    }

    // Full depth-3 tree with commitment leafs hash1(1..=8).
    fn create_test_imt_tree() -> OffChainImt {
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=8 {
            off_chain_imt
                .insert_leaf_lazy(solana_poseidon_native::hash1(i))
                .unwrap();
        }
        off_chain_imt.build_tree();
        off_chain_imt
    }

    // Simple test, prove leaf hash1(5) is in the full tree, assert ok
    #[test]
    fn test_pool_membership_ok() {
        let imt_tree = create_test_imt_tree();
        let merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(5))
            .unwrap();
        assert!(run_circuit(merkle_proof, imt_tree.root()).is_ok());
    }

    // Loop 1..=8, build proof for each leaf, assert ok
    #[test]
    fn test_pool_membership_all_leaves_ok() {
        let imt_tree = create_test_imt_tree();
        for i in 1..=8 {
            let merkle_proof = imt_tree
                .merkle_proof(solana_poseidon_native::hash1(i))
                .unwrap();
            assert!(
                run_circuit(merkle_proof, imt_tree.root()).is_ok(),
                "leaf {i} failed"
            );
        }
    }

    // Insert 3 leaves into a depth-3 tree, prove one of them (siblings are zero-values), assert ok
    #[test]
    fn test_pool_membership_partial_tree_ok() {
        let mut imt_tree = OffChainImt::new(3);
        for i in 1..=3 {
            imt_tree
                .insert_leaf_lazy(solana_poseidon_native::hash1(i))
                .unwrap();
        }
        imt_tree.build_tree();
        let merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(2))
            .unwrap();
        assert!(run_circuit(merkle_proof, imt_tree.root()).is_ok());
    }

    // Real proof, pass tampered expected_root (root + 1), assert err
    #[test]
    fn test_pool_membership_wrong_root_fails() {
        let imt_tree = create_test_imt_tree();
        let merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(5))
            .unwrap();
        let wrong_root = imt_tree.root() + Fr::ONE;
        assert!(run_circuit(merkle_proof, wrong_root).is_err());
    }

    // Valid proof, swap proof.leaf to a different value, assert err
    #[test]
    fn test_pool_membership_wrong_leaf_fails() {
        let imt_tree = create_test_imt_tree();
        let mut merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(5))
            .unwrap();
        merkle_proof.leaf = solana_poseidon_native::hash1(99); // not the proven leaf
        assert!(run_circuit(merkle_proof, imt_tree.root()).is_err());
    }

    // Corrupt siblings_path[k], loop k over every position, assert err for each
    #[test]
    fn test_pool_membership_tampered_sibling_fails() {
        let imt_tree = create_test_imt_tree();
        for k in 0..imt_tree.tree_depth as usize {
            let mut merkle_proof = imt_tree
                .merkle_proof(solana_poseidon_native::hash1(5))
                .unwrap();
            merkle_proof.siblings_path[k] += Fr::ONE; // tamper one sibling on the path
            assert!(
                run_circuit(merkle_proof, imt_tree.root()).is_err(),
                "sibling at position {k} is not constrained into the root"
            );
        }
    }

    // Flip siblings_side[k] (0↔1) at a level with distinct siblings (full tree), assert err
    #[test]
    fn test_pool_membership_flipped_side_fails() {
        let imt_tree = create_test_imt_tree();
        let mut merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(5))
            .unwrap();
        // leaf-level siblings are distinct in a full tree, so swapping order changes the hash
        merkle_proof.siblings_side[0] ^= 1;
        assert!(run_circuit(merkle_proof, imt_tree.root()).is_err());
    }

    // Set siblings_side[k] = 2, assert err (triggers assert_bit violation)
    #[test]
    fn test_pool_membership_non_bit_side_fails() {
        let imt_tree = create_test_imt_tree();
        let mut merkle_proof = imt_tree
            .merkle_proof(solana_poseidon_native::hash1(5))
            .unwrap();
        merkle_proof.siblings_side[0] = 2; // not a bit (0/1) -> assert_bit fails
        assert!(run_circuit(merkle_proof, imt_tree.root()).is_err());
    }
}
