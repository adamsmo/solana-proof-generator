use crate::imt::imt_utils::{
    generate_zero_values_for_levels, poseidon_hash, EMPTY_VALUE, TREE_DEPTH_MAX, Z_0,
};
use crate::Fr;
use anyhow::{Error, Result};

// ********************
// This is a memory-heavy full IMT tree implementation used off-chain on the client side
// to reconstruct the tree and build the Merkle proof of inclusion for give leaf node (commitment hash)
//
// It stores hash, Fr::zero and Fr::one are not possible values
// ********************

// Note that we start node indexing from 1 (nodes[0] is unused)
pub struct OffChainImt {
    pub nodes: Vec<Fr>,
    pub zero_values: Vec<Fr>,
    pub first_leaf_idx: usize,
    pub next_free_leaf_idx: usize,
    pub tree_depth: u32,
}

/**
 * Note: We are starting at index 1 (leaving index 0 unused makes the math clean):
 * Example tree indexes for depth = 3 :
 *            1                - level 3 (root)
 *      2             3        - level 2
 *   4     5      6      7     - level 1
 *  8 9  10 11  12 13  14 15   - level 0 (leafs)
 *
 * Example proof for leaf ad node_8:
 * proof.siblings_path = [node_9, node_5, node_3]
 * proof.siblings_side = [1, 1, 1]
 * proof.leaf = node_8
 */
pub struct MerkleProof {
    pub leaf: Fr, // we prove that this leaf node is part of the tree
    pub siblings_path: Vec<Fr>,
    pub siblings_side: Vec<u8>, // side on which node on the path is (0 for left, 1 for right)
}

impl OffChainImt {
    pub fn new(tree_depth: u32) -> Self {
        assert!(tree_depth > 0, "Tree depth must be greater than 0");
        assert!(
            tree_depth <= TREE_DEPTH_MAX as u32,
            "Tree depth is too large"
        );

        // For tree_depth = 20 node_code ~= 2M
        let node_count = 2usize.pow(tree_depth + 1);
        let nodes = vec![EMPTY_VALUE; node_count];

        let zero_values = generate_zero_values_for_levels(tree_depth as usize);
        // We need to skip all the nodes on levels above the zero level where leafs are stored
        // Note: We start node indexing from 1 this makes the math cleaner
        let first_leaf_idx = 2usize.pow(tree_depth as u32);

        let mut off_chain_imt = Self {
            nodes,
            zero_values,
            first_leaf_idx,
            next_free_leaf_idx: first_leaf_idx,
            tree_depth,
        };
        // build the empty tree with zero values
        off_chain_imt.build_tree();
        off_chain_imt
    }

    pub fn root(&self) -> Fr {
        self.nodes[1]
    }

    // Insert leaf on next unused leaf position, do not recalculate the full tree
    pub fn insert_leaf_lazy(&mut self, leaf: Fr) -> Result<()> {
        if leaf == EMPTY_VALUE || leaf == Z_0 {
            return Err(Error::msg("Leaf value is not valid"));
        }
        if self.next_free_leaf_idx >= self.nodes.len() {
            return Err(Error::msg("Tree is full"));
        }
        self.nodes[self.next_free_leaf_idx] = leaf;
        self.next_free_leaf_idx += 1;
        Ok(())
    }

    pub fn build_tree(&mut self) {
        // first fill the leaf level
        for i in self.first_leaf_idx..self.nodes.len() {
            self.nodes[i] = self.node(i);
        }

        let mut last_level_start_idx = self.first_leaf_idx;
        // fill other levels
        for level in 1..=self.tree_depth {
            let level_start_idx = 2usize.pow(self.tree_depth - level);
            for i in level_start_idx..last_level_start_idx {
                let left_child = self.node(i * 2);
                let right_child = self.node(i * 2 + 1);
                self.nodes[i] = poseidon_hash(left_child, right_child)
            }
            last_level_start_idx = level_start_idx;
        }
    }

    pub fn merkle_proof(&self, leaf: Fr) -> Result<MerkleProof> {
        let mut proof = MerkleProof {
            leaf,
            siblings_path: Vec::new(),
            siblings_side: Vec::new(),
        };
        let leaf_idx = self
            .find_leaf_index(leaf)
            .ok_or_else(|| Error::msg("Leaf is not in the tree"))?;

        let mut current_idx = leaf_idx;
        while current_idx > 1 {
            let is_left_leaf = current_idx % 2 == 0;
            let sibling = if is_left_leaf {
                self.nodes[current_idx + 1]
            } else {
                self.nodes[current_idx - 1]
            };
            proof.siblings_path.push(sibling);
            // side of the sibling (opposite to current node), 0 - left, 1 - right
            proof.siblings_side.push(if is_left_leaf { 1 } else { 0 });
            current_idx /= 2; // go level up to parent idx
        }
        Ok(proof)
    }

    pub fn verify_merkle_proof(&self, proof: &MerkleProof) -> bool {
        let mut parent = EMPTY_VALUE;
        let mut other_sibling = proof.leaf;
        for i in 0..proof.siblings_path.len() {
            let sibling = proof.siblings_path[i];
            let is_left = proof.siblings_side[i] == 0; // 0 - left, 1 - right
            if is_left {
                parent = poseidon_hash(sibling, other_sibling);
            } else {
                parent = poseidon_hash(other_sibling, sibling);
            }
            // level up
            other_sibling = parent;
        }

        // check if calculated hash equals root
        self.root() == parent
    }

    fn node(&self, idx: usize) -> Fr {
        if self.nodes[idx] == EMPTY_VALUE {
            // unset node, fetch zero value based on level
            let node_level = self.calculate_level(idx);
            self.zero_values[node_level]
        } else {
            self.nodes[idx]
        }
    }

    fn find_leaf_index(&self, leaf: Fr) -> Option<usize> {
        for i in self.first_leaf_idx..self.nodes.len() {
            if self.nodes[i] == leaf {
                return Some(i);
            }
        }
        None
    }

    /**
     * Note: We are starting at index 1 (leaving index 0 unused makes the math clean):
     * Example tree indexes for depth = 3 :
     *            1                - level 3 (root)
     *      2             3        - level 2
     *   4     5      6      7     - level 1
     *  8 9  10 11  12 13  14 15   - level 0 (leafs)
     */
    fn calculate_level(&self, node_idx: usize) -> usize {
        // ilog2 - does integer bit logic, not floating-point logarithms. It asks: “what is the position of the highest set bit?”
        let depth_from_root = node_idx.ilog2();
        (self.tree_depth - depth_from_root) as usize
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native::hash1;
    use crate::imt::imt_utils::poseidon_hash;

    // ---------------------------------------------------------------------
    // Snapshot of the depth-3 reference tree (leafs = commitment(1..=8)).
    // These are the single source of truth for IMT expected values: the
    // on-chain tests cross-check against this off-chain IMT at runtime instead of
    // duplicating constants. Regenerate only if the hash impl legitimately
    // changes (a change here that you didn't intend means something broke).
    // ---------------------------------------------------------------------
    pub(crate) const Z0_HEX: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
    pub(crate) const Z1_HEX: &str =
        "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";
    pub(crate) const Z2_HEX: &str =
        "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1";
    pub(crate) const EMPTY_ROOT_HEX: &str =
        "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238";
    pub(crate) const SINGLE_ROOT_HEX: &str =
        "0x2f07f534fd5f83e212b83e064032f089786072d95aed5c34eda673c7e4c19532";
    pub(crate) const PARTIAL3_ROOT_HEX: &str =
        "0x3015bf8153f5d30e705e0d22f11ee927bd0a9b642bfabb00917a2c4b3ebe684d";
    // Full depth-3 tree, all 15 used nodes in array order
    // Includes root, internal nodes, and leaves.
    // Note:
    // It has length 15 because it stores only the used tree nodes, without unused nodes[0], so FULL_DEPTH3_TREE_NODES[0] -> off_chain_imt.nodes[1]
    pub(crate) const FULL_DEPTH3_TREE_NODES: [&str; 15] = [
        "0x020126f16d65c43533b2065e8939761b7f9993c94749902994754f7301a01d41",
        "0x0b6d2198cbb5072f5a2b185ea758205a719242a76379ddcf9f59976b30ec1877",
        "0x0f7c214c6741ce8f15a9dab749d59f58fe17b5a85c19063a18db81c5efc8a747",
        "0x12668119982ac0da64d7a9ca4d1864852d9811796709bbe2b62423237efff48c",
        "0x163aa87c31666d17b4aa3232f7b851eb6db722c8332c0a2a39100d32b4258e21",
        "0x0120c0eb6220226347f4a4b424c6901ec33816c53b83a14a2b2fceae125eabc8",
        "0x1031bbcff7fce23df60ead2f17f8171c1cf0a90fa576d65b60cf38295f70e491",
        "0x007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81",
        "0x0a63c241bc6454987d6c55dcf23e42ee3076a76b960e1270188ee2f91ee85399",
        "0x16fe483062aa7b228c90e5e390c630293e2c40ad1d69abb07acb287f2770d3cd",
        "0x2ba34021e166fcf2fd51bc278e603d180d1f9735f1742519db6b6fdbe8d43c14",
        "0x20d3fef1dcf4a5754f7465b5db793630917b7c9d14cdbebd36fe0fcbaf958f14",
        "0x0462e0ccca25abbfd7e44b50bc383df65c31d272ef28a22550cb9ddfb902f3fd",
        "0x0c9315a2570d1c8ec884fd8dc1adb4662310c435c392f3a0701e8fe94b3b537b",
        "0x0c0e9c16ef7a50e2ecbfeca5a77bd70b4950b7694bc0e694e3ced87d438fd1cf",
    ];

    fn hex(f: Fr) -> String {
        format!("{:?}", f)
    }

    // test_layout_depth3 - first_leaf_idx==8, nodes.len()==16, next_free_leaf_idx==8 after new(3) | structural
    #[test]
    fn test_layout_depth3() {
        let off_chain_imt = OffChainImt::new(3);
        assert_eq!(off_chain_imt.first_leaf_idx, 8);
        assert_eq!(off_chain_imt.nodes.len(), 16);
        assert_eq!(off_chain_imt.next_free_leaf_idx, 8);
    }

    // test_calculate_level - idx 1→3, 2–3→2, 4–7→1, 8–15→0 (pins the ilog2 math) | structural
    #[test]
    fn test_calculate_level() {
        let off_chain_imt = OffChainImt::new(3);
        assert_eq!(off_chain_imt.calculate_level(1), 3);
        for i in 2..=3 {
            assert_eq!(off_chain_imt.calculate_level(i), 2);
        }
        for i in 4..=7 {
            assert_eq!(off_chain_imt.calculate_level(i), 1);
        }
        for i in 8..=15 {
            assert_eq!(off_chain_imt.calculate_level(i), 0);
        }
    }

    // test_zero_values_snapshot - zero_values == [z0, z1, z2] | snapshot
    #[test]
    fn test_zero_values_snapshot() {
        let zv = generate_zero_values_for_levels(3);
        assert_eq!(hex(zv[0]), Z0_HEX);
        assert_eq!(hex(zv[1]), Z1_HEX);
        assert_eq!(hex(zv[2]), Z2_HEX);
    }

    // test_empty_root_snapshot - empty depth-3 root() matches snapshot, and == poseidon_hash(z2,z2) | snapshot
    #[test]
    fn test_empty_root_snapshot() {
        let off_chain_imt = OffChainImt::new(3);
        assert_eq!(hex(off_chain_imt.root()), EMPTY_ROOT_HEX);
        let zv = generate_zero_values_for_levels(3);
        assert_eq!(off_chain_imt.root(), poseidon_hash(zv[2], zv[2]));
    }

    // test_single_leaf_snapshot - insert one commitment, build_tree, root matches snapshot; path siblings resolve to zero_values | snapshot
    #[test]
    fn test_single_leaf_snapshot() {
        let zv = generate_zero_values_for_levels(3);
        let mut off_chain_imt = OffChainImt::new(3);
        off_chain_imt.insert_leaf_lazy(hash1(1)).unwrap();
        off_chain_imt.build_tree();
        assert_eq!(hex(off_chain_imt.root()), SINGLE_ROOT_HEX);
        // only leaf 0 (node 8) is set; the rest resolve to the leaf-level zero value Z_0
        assert_eq!(off_chain_imt.nodes[8], hash1(1));
        for i in 9..=15 {
            assert_eq!(off_chain_imt.nodes[i], zv[0]);
        }
    }

    // test_full_tree_snapshot - insert 8 commitment leafs, build_tree, assert entire 15-node nodes vector matches snapshot array | snapshot (strong)
    #[test]
    fn test_full_tree_snapshot() {
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=8 {
            off_chain_imt.insert_leaf_lazy(hash1(i)).unwrap();
        }
        off_chain_imt.build_tree();
        for (i, expected) in FULL_DEPTH3_TREE_NODES.iter().enumerate() {
            let node_idx = i + 1;
            assert_eq!(
                hex(off_chain_imt.nodes[node_idx]),
                *expected,
                "node {}",
                node_idx
            );
        }
    }

    // test_partial_tree_zero_substitution - insert 3 leafs, build, root matches snapshot (exercises node() zero-fill) | snapshot
    #[test]
    fn test_partial_tree_zero_substitution() {
        let zv = generate_zero_values_for_levels(3);
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=3 {
            off_chain_imt.insert_leaf_lazy(hash1(i)).unwrap();
        }
        off_chain_imt.build_tree();
        assert_eq!(hex(off_chain_imt.root()), PARTIAL3_ROOT_HEX);
        // leafs 3..7 (nodes 11..15) were never inserted -> zero-filled with Z_0
        for i in 11..=15 {
            assert_eq!(off_chain_imt.nodes[i], zv[0]);
        }
    }

    // test_insert_rejects_zero_and_one - insert_leaf_lazy(Z_0) and (EMPTY_VALUE) return Err | error
    #[test]
    fn test_insert_rejects_zero_and_one() {
        let mut off_chain_imt = OffChainImt::new(3);
        assert!(off_chain_imt.insert_leaf_lazy(Z_0).is_err());
        assert!(off_chain_imt.insert_leaf_lazy(EMPTY_VALUE).is_err());
    }

    // test_tree_full - 9th insert on depth 3 → Err("Tree is full") | error
    #[test]
    fn test_tree_full() {
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=8 {
            off_chain_imt.insert_leaf_lazy(hash1(i)).unwrap();
        }
        assert!(off_chain_imt.insert_leaf_lazy(hash1(9)).is_err());
    }

    // test_build_tree_idempotent - build_tree() twice → same root | invariant
    #[test]
    fn test_build_tree_idempotent() {
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=5 {
            off_chain_imt.insert_leaf_lazy(hash1(i)).unwrap();
        }
        off_chain_imt.build_tree();
        let r1 = off_chain_imt.root();
        off_chain_imt.build_tree();
        assert_eq!(off_chain_imt.root(), r1);
    }

    #[test]
    fn test_merkle_proof_check() {
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=8 {
            off_chain_imt.insert_leaf_lazy(hash1(i)).unwrap();
        }
        off_chain_imt.build_tree();

        // build and check proof for each leaf
        for i in 1..=8 {
            let proof = off_chain_imt.merkle_proof(hash1(i)).unwrap();
            assert_eq!(proof.siblings_path.len(), 3);
            assert_eq!(proof.siblings_side.len(), 3);

            assert!(
                off_chain_imt.verify_merkle_proof(&proof),
                "proof mismatch for leaf {}",
                i
            );
        }
    }
}

// Throwaway helper to (re)generate the depth-3 snapshot constants used in the
// tests above. Run with: `cargo test print_snapshots -- --nocapture` and paste
// the printed values into the snapshot consts. Not an assertion test.
#[cfg(test)]
mod capture {
    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native::hash1;

    #[test]
    fn print_snapshots() {
        let zv = generate_zero_values_for_levels(3);
        println!("Z0 = {:?}", zv[0]);
        println!("Z1 = {:?}", zv[1]);
        println!("Z2 = {:?}", zv[2]);

        let empty = OffChainImt::new(3);
        println!("EMPTY_ROOT = {:?}", empty.root());

        let mut single = OffChainImt::new(3);
        single.insert_leaf_lazy(hash1(1)).unwrap();
        single.build_tree();
        println!("SINGLE_ROOT = {:?}", single.root());

        let mut partial = OffChainImt::new(3);
        for i in 1..=3 {
            partial.insert_leaf_lazy(hash1(i)).unwrap();
        }
        partial.build_tree();
        println!("PARTIAL3_ROOT = {:?}", partial.root());

        let mut full = OffChainImt::new(3);
        for i in 1..=8 {
            full.insert_leaf_lazy(hash1(i)).unwrap();
        }
        full.build_tree();
        for (i, n) in full.nodes.iter().enumerate() {
            println!("FULL_NODE[{}] = {:?}", i, n);
        }
    }
}
