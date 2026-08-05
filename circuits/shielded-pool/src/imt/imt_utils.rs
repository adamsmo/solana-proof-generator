use crate::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::Field;
use solana_poseidon::{Endianness, Parameters};

use crate::circuit::utils::{fr_from_le_bytes, fr_to_le_bytes};

// We use Fr::zero and Fr::one as no each element in our tree is a 32 byte hash,
// so we know for sure that zero and one will never be used (as hashes much bigger)
pub const Z_0: Fr = Fr::ZERO;
// tree node value that was not updated yet
pub const EMPTY_VALUE: Fr = Fr::ONE;

// 1M leafs and total size of full tree 64MB (32 bytes per leaf)
pub const TREE_DEPTH_MAX: usize = 20;
// max leaf count 2^20 = 1_048_576
pub const MAX_LEAF_COUNT: usize = 1 << TREE_DEPTH_MAX;
// 2^21 - 1 = 2_097_151
pub const MAX_TREE_SIZE: usize = (1 << (TREE_DEPTH_MAX + 1)) - 1;

pub fn generate_zero_values_for_levels(tree_depth: usize) -> Vec<Fr> {
    let mut zero_values = Vec::with_capacity(tree_depth);
    zero_values.push(Z_0);

    for i in 1..tree_depth {
        let z_prev = zero_values[i - 1];
        let z_prev_bytes = fr_to_le_bytes(z_prev);
        let hash = solana_poseidon::hashv(
            Parameters::Bn254X5,
            Endianness::LittleEndian,
            &[&z_prev_bytes, &z_prev_bytes],
        )
        .unwrap();

        zero_values.push(fr_from_le_bytes(hash.to_bytes()));
    }

    zero_values
}

pub fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let hash = solana_poseidon::hashv(
        Parameters::Bn254X5,
        Endianness::LittleEndian,
        &[&fr_to_le_bytes(left), &fr_to_le_bytes(right)],
    )
    .unwrap();

    fr_from_le_bytes(hash.to_bytes())
}
