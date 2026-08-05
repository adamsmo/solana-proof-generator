use crate::circuit::constraints::additional_constraints::AdditionalConstraintsChip;
use crate::circuit::constraints::merkle_proof::MerkleProofChip;
use crate::circuit::constraints::poseidon::solana_poseidon_chip::{
    user_deposit_commitment_inputs, SolanaPoseidonChip,
};
use crate::circuit::constraints::poseidon::solana_poseidon_native;
use crate::circuit::consts::{MAX_CHUNKS, TEST_TREE_DEPTH};
use crate::imt::off_chain_imt::OffChainImt;
use crate::Fr;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::AssignedValue;

pub fn build_full_circuit<const TREE_DEPTH: usize>(
    builder: &mut BaseCircuitBuilder<Fr>,
    // private witness(advice) values
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
    merkle_proof_siblings_path: &[Fr; TREE_DEPTH], // merkle proof path - nodes
    merkle_proof_siblings_side: &[u8; TREE_DEPTH], // merkle proof path - nodes sides
    // public instances and also witnesses (advice columns)
    step: Fr,
    chunk_amount: Fr,
    dest_address: Fr,
    nullifier: Fr,
) {
    let solana_poseidon = SolanaPoseidonChip::<MAX_CHUNKS>::new();
    let range: RangeChip<Fr> = builder.range_chip();
    let additional_constraints = AdditionalConstraintsChip::new(range, &solana_poseidon);
    let pool_membership_proof = MerkleProofChip::<TREE_DEPTH>::new();
    let ctx = builder.main(0);

    // load witnesses
    let s_w = ctx.load_witness(s);
    let total_amount_w = ctx.load_witness(total_amount);
    let chunks_w: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_w: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));
    let step_w = ctx.load_witness(step);
    let chunk_amount_w = ctx.load_witness(chunk_amount);
    let dest_address_w = ctx.load_witness(dest_address);
    let nullifier_w = ctx.load_witness(nullifier);

    let siblings_path_witness: [AssignedValue<Fr>; TREE_DEPTH] =
        std::array::from_fn(|i| ctx.load_witness(merkle_proof_siblings_path[i]));
    let siblings_side_witness: [AssignedValue<Fr>; TREE_DEPTH] =
        std::array::from_fn(|i| ctx.load_witness(Fr::from(merkle_proof_siblings_side[i] as u64)));

    // input hash constraints
    let poseidon_user_hash = solana_poseidon.hash_7_inputs(ctx, s_w, &chunks_w, &addresses_w);
    let poseidon_final_hash =
        solana_poseidon.hash_2_inputs(ctx, poseidon_user_hash, total_amount_w);

    // additional constraints
    additional_constraints.step_in_range(ctx, step_w);
    additional_constraints.chunk_selection_and_amount_in_range(
        ctx,
        &chunks_w,
        chunk_amount_w,
        step_w,
    );
    additional_constraints.destination_selection(ctx, &addresses_w, dest_address_w, step_w);
    additional_constraints.chunks_sum_to_total(ctx, &chunks_w, total_amount_w);
    additional_constraints.nullifier_derivation(ctx, s_w, nullifier_w, step_w);
    additional_constraints.chunks_in_range(ctx, &chunks_w);

    // pool membership (merkle proof)
    let leaf_witness = poseidon_final_hash; // leaf in merkle proof is deposit commitment hash
    let root_from_merkle_proof = pool_membership_proof.calculate_root_from_proof(
        ctx,
        leaf_witness,
        &siblings_path_witness,
        &siblings_side_witness,
        &solana_poseidon,
    );

    // set public instances
    builder.assigned_instances[0].push(step_w);
    builder.assigned_instances[0].push(chunk_amount_w);
    builder.assigned_instances[0].push(dest_address_w);
    builder.assigned_instances[0].push(nullifier_w);
    builder.assigned_instances[0].push(root_from_merkle_proof);
}

// Depth-3 tree with filler leafs hash1(1..=4) and our commitment as the 5th leaf.
// Deterministic: same commitment always produces the same tree.
pub fn build_test_tree(commitment_hash: Fr) -> OffChainImt {
    let mut imt = OffChainImt::new(TEST_TREE_DEPTH as u32);
    for i in 1..=4 {
        imt.insert_leaf_lazy(solana_poseidon_native::hash1(i))
            .unwrap();
    }
    imt.insert_leaf_lazy(commitment_hash).unwrap();
    imt.build_tree();
    imt
}

pub fn user_commitment_hash(s: Fr, chunks: &[Fr; MAX_CHUNKS], addresses: &[Fr; MAX_CHUNKS]) -> Fr {
    solana_poseidon_native::hash7(&user_deposit_commitment_inputs(s, chunks, addresses))
}

pub fn deposit_commitment_hash(user_hash: Fr, total_amount: Fr) -> Fr {
    solana_poseidon_native::hash2(&[user_hash, total_amount])
}

pub fn calculate_user_and_deposit_commitment_hash(
    s: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
    total_amount: Fr,
) -> Fr {
    let user_hash = user_commitment_hash(s, chunks, addresses);
    deposit_commitment_hash(user_hash, total_amount)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native;
    use crate::circuit::consts::{PROD_TREE_DEPTH, TEST_TREE_DEPTH};
    use crate::imt::imt_utils::{generate_zero_values_for_levels, poseidon_hash};
    use crate::imt::off_chain_imt::OffChainImt;
    use halo2_base::halo2_proofs::dev::{MockProver, VerifyFailure};
    use halo2_base::halo2_proofs::halo2curves::ff::Field;

    const K: usize = 16;

    // Everything one full-circuit run needs: private witnesses, merkle proof, public instances.
    // Tests start from a consistent case and tamper single fields to hit specific constraints.
    struct TestCase<const TREE_DEPTH: usize> {
        // private witness values
        s: Fr,
        total_amount: Fr,
        chunks: [Fr; MAX_CHUNKS],
        addresses: [Fr; MAX_CHUNKS],
        siblings_path: [Fr; TREE_DEPTH],
        siblings_side: [u8; TREE_DEPTH],
        // public instance values
        step: Fr,
        chunk_amount: Fr,
        dest_address: Fr,
        nullifier: Fr,
        root: Fr,
    }

    impl TestCase<TEST_TREE_DEPTH> {
        fn new(chunks: [Fr; MAX_CHUNKS], total_amount: Fr, step_idx: usize) -> Self {
            let s = Fr::from(1234567890);
            let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];
            let step = Fr::from(step_idx as u64);
            let commitment =
                calculate_user_and_deposit_commitment_hash(s, &chunks, &addresses, total_amount);
            let imt = build_test_tree(commitment);
            let proof = imt.merkle_proof(commitment).unwrap();
            Self {
                s,
                total_amount,
                chunks,
                addresses,
                siblings_path: proof.siblings_path.try_into().unwrap(),
                siblings_side: proof.siblings_side.try_into().unwrap(),
                step,
                chunk_amount: chunks[step_idx],
                dest_address: addresses[step_idx],
                nullifier: solana_poseidon_native::hash2(&[s, step]),
                root: imt.root(),
            }
        }

        // Distinct chunks and addresses so selection-by-step is actually exercised.
        fn new_with_step(step_idx: usize) -> Self {
            Self::new(
                [Fr::from(2), Fr::from(3), Fr::from(4)],
                Fr::from(9),
                step_idx,
            )
        }
    }

    fn run_test_case<const TREE_DEPTH: usize>(
        tc: &TestCase<TREE_DEPTH>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(K)
            .use_instance_columns(1);
        builder.set_lookup_bits(K - 1);

        build_full_circuit::<TREE_DEPTH>(
            &mut builder,
            tc.s,
            tc.total_amount,
            &tc.chunks,
            &tc.addresses,
            &tc.siblings_path,
            &tc.siblings_side,
            tc.step,
            tc.chunk_amount,
            tc.dest_address,
            tc.nullifier,
        );
        builder.calculate_params(Some(9)); // blinding factor

        let public_instances = vec![vec![
            tc.step,
            tc.chunk_amount,
            tc.dest_address,
            tc.nullifier,
            tc.root,
        ]];
        MockProver::run(K as u32, &builder, public_instances)
            .unwrap()
            .verify()
    }

    // --- A. happy paths ---

    #[test]
    fn test_full_circuit_ok_all_steps() {
        for step_idx in 0..MAX_CHUNKS {
            let tc = TestCase::new_with_step(step_idx);
            assert!(run_test_case(&tc).is_ok());
        }
    }

    // Commitment as the only leaf in the tree; all path siblings are zero-subtree values.
    #[test]
    fn test_full_circuit_one_leaf_tree_ok() {
        let mut tc = TestCase::new_with_step(0);
        let commitment = calculate_user_and_deposit_commitment_hash(
            tc.s,
            &tc.chunks,
            &tc.addresses,
            tc.total_amount,
        );
        let mut imt = OffChainImt::new(TEST_TREE_DEPTH as u32);
        imt.insert_leaf_lazy(commitment).unwrap();
        imt.build_tree();
        let proof = imt.merkle_proof(commitment).unwrap();
        tc.siblings_path = proof.siblings_path.try_into().unwrap();
        tc.siblings_side = proof.siblings_side.try_into().unwrap();
        tc.root = imt.root();
        assert!(run_test_case(&tc).is_ok());
    }

    // --- B. failed results tests ---

    // Public step says 1, but nullifier/chunk_amount/destination were derived for step 0.
    #[test]
    fn test_full_circuit_wrong_step_fails() {
        let mut tc = TestCase::new_with_step(0);
        tc.step = Fr::from(1);
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    fn test_full_circuit_wrong_chunk_amount_fails() {
        let mut tc = TestCase::new_with_step(0);
        tc.chunk_amount = tc.chunks[1]; // real chunk value, but not chunks[step]
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    fn test_full_circuit_wrong_dest_address_fails() {
        let mut tc = TestCase::new_with_step(0);
        tc.dest_address = tc.addresses[2]; // real deposit address, but not addresses[step]
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    fn test_full_circuit_wrong_nullifier_fails() {
        // right secret, wrong step
        let mut tc = TestCase::new_with_step(0);
        tc.nullifier = solana_poseidon_native::hash2(&[tc.s, Fr::from(2)]);
        assert!(run_test_case(&tc).is_err());

        // arbitrary value
        let mut tc = TestCase::new_with_step(0);
        tc.nullifier = Fr::from(424242);
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    fn test_full_circuit_step_out_of_range_fails() {
        let mut tc = TestCase::new_with_step(0);
        tc.step = Fr::from(MAX_CHUNKS as u64);
        // keep the nullifier consistent with the forged step so step_in_range
        // is the constraint under test, not nullifier_derivation
        tc.nullifier = solana_poseidon_native::hash2(&[tc.s, tc.step]);
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    fn test_full_circuit_wrong_root_fails() {
        let mut tc = TestCase::new_with_step(0);
        tc.root += Fr::ONE;
        assert!(run_test_case(&tc).is_err());
    }

    // Proof generated against an older tree state; verifier expects the current root.
    // (This is why the on-chain program must keep a window of recent roots.)
    #[test]
    fn test_full_circuit_stale_root_fails() {
        let mut tc = TestCase::new_with_step(0);
        let commitment = calculate_user_and_deposit_commitment_hash(
            tc.s,
            &tc.chunks,
            &tc.addresses,
            tc.total_amount,
        );
        let mut imt = build_test_tree(commitment);
        imt.insert_leaf_lazy(solana_poseidon_native::hash1(99))
            .unwrap(); // deposit after proof generation
        imt.build_tree();
        tc.root = imt.root();
        // will fail because we recorded tree state for proof generation at earlier time before 99 was inserted
        assert!(run_test_case(&tc).is_err());
    }

    // Deposit committed with total 8 while chunks sum to 9: merkle proof and
    // nullifier are consistent, only chunks_sum_to_total must reject.
    #[test]
    fn test_full_circuit_sum_mismatch_fails() {
        let tc = TestCase::new([Fr::from(2), Fr::from(3), Fr::from(4)], Fr::from(8), 0);
        assert!(run_test_case(&tc).is_err());
    }

    // -1 + 4 + 4 == 7 in the field, so the sum check alone would pass;
    // chunks_in_range must catch the wrap-around chunk.
    #[test]
    fn test_full_circuit_chunk_overflow_fails() {
        let tc = TestCase::new([-Fr::ONE, Fr::from(4), Fr::from(4)], Fr::from(7), 1);
        assert!(run_test_case(&tc).is_err());
    }

    // Valid merkle path, but it belongs to a different leaf of the same tree:
    // proves the path is bound to the in-circuit commitment.
    #[test]
    fn test_full_circuit_proof_for_different_leaf_fails() {
        let mut tc = TestCase::new_with_step(0);
        let commitment = calculate_user_and_deposit_commitment_hash(
            tc.s,
            &tc.chunks,
            &tc.addresses,
            tc.total_amount,
        );
        let imt = build_test_tree(commitment);
        let other_proof = imt.merkle_proof(solana_poseidon_native::hash1(1)).unwrap();
        tc.siblings_path = other_proof.siblings_path.try_into().unwrap();
        tc.siblings_side = other_proof.siblings_side.try_into().unwrap();
        assert!(run_test_case(&tc).is_err());
    }

    // --- C. edge cases ---

    // Zero-amount withdrawal verifies; rejecting it (if desired) is the on-chain program's job.
    #[test]
    fn test_full_circuit_zero_chunk_ok() {
        let tc = TestCase::new([Fr::from(0), Fr::from(3), Fr::from(4)], Fr::from(7), 0);
        assert!(run_test_case(&tc).is_ok());
    }

    // --- D. production tree depth ---

    // Depth-20 case built by hand instead of via OffChainImt: materializing a
    // 2^20-leaf tree means ~1M poseidon hashes, far too slow for a test. With the
    // commitment as the leftmost (only) leaf, every path sibling is exactly the
    // zero-subtree value of its level and the sibling is always on the right.
    fn valid_prod_depth() -> TestCase<PROD_TREE_DEPTH> {
        let base = TestCase::new_with_step(0);
        let leaf = calculate_user_and_deposit_commitment_hash(
            base.s,
            &base.chunks,
            &base.addresses,
            base.total_amount,
        );

        let zero_values = generate_zero_values_for_levels(PROD_TREE_DEPTH);
        // calculate root hash going from left most leaf upwards to the root node
        // we want to skip build_tree() as with tree depth with would be about 2M poseidon hashes to calculate
        let mut current_node = leaf;
        for zero_value in &zero_values {
            current_node = poseidon_hash(current_node, *zero_value);
        }
        let root = current_node;

        TestCase {
            s: base.s,
            total_amount: base.total_amount,
            chunks: base.chunks,
            addresses: base.addresses,
            siblings_path: zero_values.try_into().unwrap(),
            siblings_side: [1; PROD_TREE_DEPTH], // leftmost leaf -> sibling always on the right
            step: base.step,
            chunk_amount: base.chunk_amount,
            dest_address: base.dest_address,
            nullifier: base.nullifier,
            root,
        }
    }

    #[test]
    fn test_full_circuit_prod_depth_ok() {
        let tc = valid_prod_depth();
        assert!(run_test_case(&tc).is_ok());
    }

    #[test]
    fn test_full_circuit_prod_depth_wrong_root_fails() {
        let mut tc = valid_prod_depth();
        tc.root += Fr::ONE;
        assert!(run_test_case(&tc).is_err());
    }

    #[test]
    #[ignore]
    // Here it will be ~2M poseidon hashes to calculate
    // RESULTS: Test run on Mac M4 Pro was 16s
    fn test_prod_tree_depth_generation_time() {
        let start_time = Instant::now();
        // OffChainImt::new() calls build_tree() internally with "zero" values for all nodes
        // (which is the same if we had any other values as leafs, number of poseidon hashes to calculate is the same)
        let _imt = OffChainImt::new(PROD_TREE_DEPTH as u32);
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        println!("Duration for 20 depth tree generation: {duration:?}");
    }
}
