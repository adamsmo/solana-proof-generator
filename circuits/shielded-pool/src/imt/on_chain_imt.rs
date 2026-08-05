#![allow(dead_code)] // Only exercised by unit tests today; keep in non-test builds for typechecking.

use crate::imt::imt_utils::{
    generate_zero_values_for_levels, poseidon_hash, EMPTY_VALUE, TREE_DEPTH_MAX,
};
use crate::Fr;
use anyhow::{Error, Result};

// This limits only how many deposit can happen in between you generate a proof for withdrawal
// and actually sending the withdrawal transaction as each new deposit changes the root.
// The on-chain program keeps a ring buffer of the last ROOT_HISTORY_LENGTH roots.
//
// The circuit proves membership against ONE root, supplied as a public input by the prover (root observed during proof generation).
// After verifying the proof, the program checks that this public root is present in the
// ring buffer. If it has already rolled off (more than ROOT_HISTORY_LENGTH deposits landed
// since the proof was made), the program rejects it - regenerate the proof against a more
// recent root and resubmit.
const ROOT_HISTORY_LENGTH: usize = 10;

/// # Fields
///
/// - `root` - current root of the tree (root level == TREE_DEPTH, leaf level == 0)
///
/// - `frontiers` - also called filledSubtrees. It stores exactly one hash per level - the hash of the
///   most recently updated left subtree at that level.
///   One value per level (no need to store it for root level)
///
/// - `zero_values` - Z_k for each level k (precomputed). Contains TREE_DEPTH values (we do not need it on root level)
///
/// - `roots_history` - old roots history. Represented as ring buffer.
///
/// - `last_root_idx` - index of the last root in the roots_history
///
/// - `next_leaf_idx` - Index of the next leaf to be inserted (0.. 2^TREE_DEPTH)
///   First (leaf) level depth == 0 and amount of leafs at this level is 2^TREE_DEPTH
struct OnChainImt<const TREE_DEPTH: usize> {
    pub root: Fr,
    pub frontiers: [Fr; TREE_DEPTH],
    pub zero_values: [Fr; TREE_DEPTH],
    pub roots_history: [Fr; ROOT_HISTORY_LENGTH],
    pub last_root_idx: usize,
    pub next_leaf_idx: usize,
}

impl<const TREE_DEPTH: usize> OnChainImt<TREE_DEPTH> {
    pub fn new() -> Self {
        assert!(TREE_DEPTH <= TREE_DEPTH_MAX, "Tree depth is too large");

        // init tree values when tree is empty (no leafs inserted yet) -  but still need to be correct Merkle tree (hashing tree)
        let zero_values: [Fr; TREE_DEPTH] = generate_zero_values_for_levels(TREE_DEPTH)
            .try_into()
            .unwrap();
        let root = poseidon_hash(zero_values[TREE_DEPTH - 1], zero_values[TREE_DEPTH - 1]);
        let mut roots_history = [EMPTY_VALUE; ROOT_HISTORY_LENGTH];
        roots_history[0] = root;

        Self {
            root,
            frontiers: [EMPTY_VALUE; TREE_DEPTH], // initial values do not matter (will be first filled during first insert)
            zero_values,
            roots_history,
            last_root_idx: 0,
            next_leaf_idx: 0,
        }
    }

    /**
     * Example tree indexes for depth = 3 (note: we use level-local indexing - each level index starts from 0) :
     *                     R_0                   - level 3 (root)
     *           A_0                A_1          - level 2
     *     B_0      B_1        B_2         B_3   - level 1
     *  C_0  C_1  C_2  C_3  C_4  C_5  C_6  C_7   - level 0 (leafs)
     */
    pub fn insert(&mut self, leaf: Fr) -> Result<()> {
        if self.next_leaf_idx >= 1 << TREE_DEPTH {
            return Err(Error::msg("Tree is full"));
        }

        // traverse tree from leaf to root (current leaf index on leaf level == next_leaf_index)
        // each level node indexing starts from 0
        let mut current_idx = self.next_leaf_idx;
        let mut current_node_value = leaf;
        for current_level in 0..TREE_DEPTH {
            let is_left_leaf = current_idx % 2 == 0;

            // go level up add calculate upper node value
            if is_left_leaf {
                self.frontiers[current_level] = current_node_value;
                current_node_value =
                    poseidon_hash(current_node_value, self.zero_values[current_level])
            } else {
                current_node_value =
                    poseidon_hash(self.frontiers[current_level], current_node_value)
            };
            current_idx /= 2;
        }
        self.root = current_node_value;
        self.next_leaf_idx += 1;
        self.inc_last_root_idx();
        self.roots_history[self.last_root_idx] = self.root;

        Ok(())
    }

    // root_history is a ring buffer (cyclic array)
    fn inc_last_root_idx(&mut self) {
        if self.last_root_idx == ROOT_HISTORY_LENGTH - 1 {
            self.last_root_idx = 0;
        } else {
            self.last_root_idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native::hash1;
    // Leaf generator + snapshots are owned by the builder tests; we cross-check
    // against the builder at runtime instead of duplicating constants.
    use crate::imt::off_chain_imt::OffChainImt;

    // test_empty_root_matches_builder - OnChainImt::<3>::new().root == OffChainImtBuilder::new(3).root() | differential
    #[test]
    fn test_empty_root_matches_builder() {
        let on_chain_imt = OnChainImt::<3>::new();
        let off_chain_imt = OffChainImt::new(3);
        assert_eq!(on_chain_imt.root, off_chain_imt.root());
    }

    // test_initial_state - next_leaf_idx==0, last_root_idx==0, roots_history[0]==root, rest EMPTY_VALUE | structural
    #[test]
    fn test_initial_state() {
        let on_chain_imt = OnChainImt::<3>::new();
        assert_eq!(on_chain_imt.next_leaf_idx, 0);
        assert_eq!(on_chain_imt.last_root_idx, 0);
        assert_eq!(on_chain_imt.roots_history[0], on_chain_imt.root);
        for i in 1..ROOT_HISTORY_LENGTH {
            assert_eq!(on_chain_imt.roots_history[i], EMPTY_VALUE);
        }
    }

    // test_full_tree_matches_builder_stepwise - for each of 8 commitment(_) : on_chain.insert(L) and builder.insert_leaf_lazy(L)+build_tree();
    // assert roots equal after every insert | differential (covers all left/right branches, proves frontiers populated before read)
    #[test]
    fn test_full_tree_matches_builder_stepwise() {
        let mut on_chain_imt = OnChainImt::<3>::new();
        let mut off_chain_imt = OffChainImt::new(3);
        for i in 1..=8u64 {
            let leaf = hash1(i);
            on_chain_imt.insert(leaf).unwrap();
            off_chain_imt.insert_leaf_lazy(leaf).unwrap();
            off_chain_imt.build_tree();
            assert_eq!(
                on_chain_imt.root,
                off_chain_imt.root(),
                "root mismatch after {} inserts",
                i
            );
        }
    }

    // test_tree_full - 9th insert → Err, state unchanged | error
    #[test]
    fn test_tree_full() {
        let mut on_chain_imt = OnChainImt::<3>::new();
        for i in 1..=8u64 {
            on_chain_imt.insert(hash1(i)).unwrap();
        }
        let root_before = on_chain_imt.root;
        let idx_before = on_chain_imt.next_leaf_idx;
        assert!(on_chain_imt.insert(hash1(9)).is_err());
        assert_eq!(on_chain_imt.root, root_before);
        assert_eq!(on_chain_imt.next_leaf_idx, idx_before);
    }

    // test_next_leaf_idx_increments - 0→8 | structural
    #[test]
    fn test_next_leaf_idx_increments() {
        let mut on_chain_imt = OnChainImt::<3>::new();
        assert_eq!(on_chain_imt.next_leaf_idx, 0);
        for i in 1..=8u64 {
            on_chain_imt.insert(hash1(i)).unwrap();
            assert_eq!(on_chain_imt.next_leaf_idx, i as usize);
        }
    }

    // test_roots_history_records_each_root - roots_history[last_root_idx]==root after each insert (no wrap, by design at depth 3) | invariant
    #[test]
    fn test_roots_history_records_each_root() {
        let mut on_chain_imt = OnChainImt::<3>::new();
        for i in 1..=8u64 {
            on_chain_imt.insert(hash1(i)).unwrap();
            assert_eq!(
                on_chain_imt.roots_history[on_chain_imt.last_root_idx],
                on_chain_imt.root
            );
        }
    }

    // test_insert_deterministic - two trees, same leafs ==> same root | invariant
    #[test]
    fn test_insert_deterministic() {
        let mut on_chain_imt_a = OnChainImt::<3>::new();
        let mut on_chain_imt_b = OnChainImt::<3>::new();
        for i in 1..=6u64 {
            on_chain_imt_a.insert(hash1(i)).unwrap();
            on_chain_imt_b.insert(hash1(i)).unwrap();
        }
        assert_eq!(on_chain_imt_a.root, on_chain_imt_b.root);
    }
}
