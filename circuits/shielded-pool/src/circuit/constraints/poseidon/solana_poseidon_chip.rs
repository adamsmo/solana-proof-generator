use crate::circuit::consts::MAX_CHUNKS;
use crate::Fr;
use halo2_base::{
    gates::{GateChip, GateInstructions},
    halo2_proofs::halo2curves::ff::Field,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use pse_poseidon::Spec;

// Solana `Parameters::Bn254X5`:
//   width/state T = inputs + 1
//   full rounds R_F = 8 (same for every width)
//   partial rounds R_P depends on width (N_ROUNDS_P[T - 2]): 64 for T=8, 57 for T=3
//   S-box alpha = 5
//   domain tag = 0
//   output = state[0]
const SOLANA_POSEIDON_R_F: usize = 8;

// 7-input commitment: T = 8, R_P = 64
pub const SOLANA_POSEIDON_INPUTS_7: usize = 7;
const SOLANA_POSEIDON_WIDTH_7: usize = SOLANA_POSEIDON_INPUTS_7 + 1;
const SOLANA_POSEIDON_R_P_7: usize = 64;

// 2-input hash (left, right): T = 3, R_P = 57
pub const SOLANA_POSEIDON_INPUTS_2: usize = 2;
const SOLANA_POSEIDON_WIDTH_2: usize = SOLANA_POSEIDON_INPUTS_2 + 1;
const SOLANA_POSEIDON_R_P_2: usize = 57;

pub fn user_deposit_commitment_inputs(
    s: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) -> [Fr; SOLANA_POSEIDON_INPUTS_7] {
    [
        s,
        chunks[0],
        chunks[1],
        chunks[2],
        addresses[0],
        addresses[1],
        addresses[2],
    ]
}

pub struct SolanaPoseidonChip<const MAX_CHUNKS: usize> {
    gate: GateChip<Fr>,
}

impl<const MAX_CHUNKS: usize> SolanaPoseidonChip<MAX_CHUNKS> {
    pub fn new() -> Self {
        Self {
            gate: GateChip::default(),
        }
    }

    pub fn hash_7_inputs(
        &self,
        ctx: &mut Context<Fr>,
        s: AssignedValue<Fr>,
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        addresses: &[AssignedValue<Fr>; MAX_CHUNKS],
    ) -> AssignedValue<Fr> {
        let inputs = [
            s,
            chunks[0],
            chunks[1],
            chunks[2],
            addresses[0],
            addresses[1],
            addresses[2],
        ];

        solana_poseidon::<SOLANA_POSEIDON_WIDTH_7, SOLANA_POSEIDON_INPUTS_7>(
            ctx,
            &self.gate,
            inputs,
            SOLANA_POSEIDON_R_P_7,
        )
    }

    /// Plain 2-input hash `H(left, right)` (no extra constraints).
    /// Width T = 3, partial rounds R_P = 57.
    pub fn hash_2_inputs(
        &self,
        ctx: &mut Context<Fr>,
        left: AssignedValue<Fr>,
        right: AssignedValue<Fr>,
    ) -> AssignedValue<Fr> {
        solana_poseidon::<SOLANA_POSEIDON_WIDTH_2, SOLANA_POSEIDON_INPUTS_2>(
            ctx,
            &self.gate,
            [left, right],
            SOLANA_POSEIDON_R_P_2,
        )
    }
}

// Implementation of Solana Poseidon hash for halo2 circuits.
// This code will generate hashes (prove them) same as Poseidon function that is available on Solana blockchain
//
// `WIDTH` is the state size T; `RATE` is the number of inputs (T - 1). `R_F` is
// always 8 for `Bn254X5`, so only the width-dependent `r_p` is passed in.
fn solana_poseidon<const WIDTH: usize, const RATE: usize>(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    inputs: [AssignedValue<Fr>; RATE],
    r_p: usize,
) -> AssignedValue<Fr> {
    let spec = Spec::<Fr, WIDTH, RATE>::new(SOLANA_POSEIDON_R_F, r_p);

    let domain_tag = ctx.load_zero();
    let mut state: [AssignedValue<Fr>; WIDTH] =
        std::array::from_fn(|i| if i == 0 { domain_tag } else { inputs[i - 1] });

    let constants = spec.constants();
    let mds_matrices = spec.mds_matrices();
    let r_f_half = SOLANA_POSEIDON_R_F / 2;

    add_constants(ctx, gate, &mut state, &constants.start()[0]);
    for round_constants in constants.start().iter().skip(1).take(r_f_half - 1) {
        sbox_full(ctx, gate, &mut state);
        add_constants(ctx, gate, &mut state, round_constants);
        apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());
    }
    sbox_full(ctx, gate, &mut state);
    add_constants(ctx, gate, &mut state, constants.start().last().unwrap());
    apply_mds(ctx, gate, &mut state, &mds_matrices.pre_sparse_mds().rows());

    for (round_constant, sparse_mds) in constants
        .partial()
        .iter()
        .zip(mds_matrices.sparse_matrices())
    {
        state[0] = sbox_5(ctx, gate, state[0]);
        state[0] = add_constant(ctx, gate, state[0], *round_constant);

        let old = state;
        state[0] = gate.inner_product(
            ctx,
            old.iter().copied(),
            sparse_mds.row().iter().map(|c| Constant(*c)),
        );
        for i in 1..WIDTH {
            state[i] = gate.mul_add(ctx, old[0], Constant(sparse_mds.col_hat()[i - 1]), old[i]);
        }
    }

    for round_constants in constants.end() {
        sbox_full(ctx, gate, &mut state);
        add_constants(ctx, gate, &mut state, round_constants);
        apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());
    }
    sbox_full(ctx, gate, &mut state);
    apply_mds(ctx, gate, &mut state, &mds_matrices.mds().rows());

    state[0]
}

fn sbox_full<const WIDTH: usize>(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; WIDTH],
) {
    for value in state.iter_mut() {
        *value = sbox_5(ctx, gate, *value);
    }
}

fn sbox_5(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    value: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let value_squared = gate.mul(ctx, value, value);
    let value_fourth = gate.mul(ctx, value_squared, value_squared);
    gate.mul(ctx, value, value_fourth)
}

fn add_constants<const WIDTH: usize>(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; WIDTH],
    constants: &[Fr; WIDTH],
) {
    for (value, constant) in state.iter_mut().zip(constants.iter()) {
        *value = add_constant(ctx, gate, *value, *constant);
    }
}

fn add_constant(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    value: AssignedValue<Fr>,
    constant: Fr,
) -> AssignedValue<Fr> {
    if constant == Fr::ZERO {
        value
    } else {
        gate.add(ctx, value, Constant(constant))
    }
}

fn apply_mds<const WIDTH: usize>(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    state: &mut [AssignedValue<Fr>; WIDTH],
    rows: &[[Fr; WIDTH]; WIDTH],
) {
    let old = *state;
    for (value, row) in state.iter_mut().zip(rows.iter()) {
        *value = gate.inner_product(
            ctx,
            old.iter().map(|x| Existing(*x)),
            row.iter().map(|c| Constant(*c)),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::constraints::poseidon::solana_poseidon_native;
    use crate::circuit::consts::MAX_CHUNKS;
    use crate::circuit::utils::convert_pubkey_32bytes_to_fr;

    use super::*;
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs::dev::MockProver;
    use hex_literal::hex;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_solana_poseidon_matches_reference_vectors() {
        let k = 18;
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let mut vectors = vec![
            (Fr::ZERO, [Fr::ZERO; MAX_CHUNKS], [Fr::ZERO; MAX_CHUNKS]),
            (
                -Fr::ONE,
                [Fr::ONE, Fr::from(2), Fr::from(3)],
                [-Fr::ONE, Fr::ZERO, Fr::ONE],
            ),
        ];

        for _ in 0..10 {
            vectors.push((
                Fr::random(&mut rng),
                std::array::from_fn(|_| Fr::random(&mut rng)),
                std::array::from_fn(|_| Fr::random(&mut rng)),
            ));
        }

        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);
        let mut expected_hashes = Vec::with_capacity(vectors.len());

        for (s, chunks, addresses) in vectors {
            expected_hashes.push(solana_poseidon_native::hash7(
                &user_deposit_commitment_inputs(s, &chunks, &addresses),
            ));

            let ctx = builder.main(0);
            let s = ctx.load_witness(s);
            let chunks = chunks.map(|chunk| ctx.load_witness(chunk));
            let addresses = addresses.map(|address| ctx.load_witness(address));
            let hash = SolanaPoseidonChip::new().hash_7_inputs(ctx, s, &chunks, &addresses);
            builder.assigned_instances[0].push(hash);
        }

        builder.calculate_params(Some(9));
        MockProver::run(k as u32, &builder, vec![expected_hashes])
            .unwrap()
            .assert_satisfied();
    }

    #[test]
    fn test_solana_poseidon_2_matches_reference_vectors() {
        let k = 14;
        let mut rng = StdRng::seed_from_u64(0x5eed);

        // edge cases
        let mut hash_pairs: Vec<(Fr, Fr)> = vec![
            (Fr::ZERO, Fr::ZERO),
            (-Fr::ONE, Fr::ONE),
            (Fr::ONE, Fr::ZERO),
            (Fr::ZERO, Fr::ONE),
        ];

        // random field pairs
        for _ in 0..10 {
            hash_pairs.push((Fr::random(&mut rng), Fr::random(&mut rng)));
        }

        // inputs originating as raw 32-byte values that do NOT fit in Fr,
        // mapped into the field via `convert_pubkey_32bytes_to_fr` (as pubkeys are).
        let byte_inputs: [[u8; 32]; 6] = [
            [0xff; 32],
            std::array::from_fn(|_| rng.r#gen()),
            hex!("ef3f5c0aa200f955d8585acf2c37899aba125227f9eb923cbba774e1006ca967"),
            hex!("e35a64aa641f5288574df3bfee4acf6523f498fe9adb94254bcf44978a132890"),
            hex!("4c9e0a027ca5ab1ba271525eb234c3fe233a9e6b5c1a5751eb7a7ce0b6edac6f"),
            hex!("0979b6f8a7d59ce2de209df4ef3e543467cf2187b5bebafa1f2414ecc8cc8fa7"),
        ];
        let byte_fr_array = byte_inputs.map(convert_pubkey_32bytes_to_fr);
        hash_pairs.push((byte_fr_array[0], byte_fr_array[1]));
        hash_pairs.push((byte_fr_array[2], byte_fr_array[3]));

        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);
        let mut expected_hashes = Vec::with_capacity(hash_pairs.len());

        for (left, right) in hash_pairs {
            expected_hashes.push(solana_poseidon_native::hash2(&[left, right]));

            let ctx = builder.main(0);
            let left = ctx.load_witness(left);
            let right = ctx.load_witness(right);
            let hash = SolanaPoseidonChip::<MAX_CHUNKS>::new().hash_2_inputs(ctx, left, right);
            builder.assigned_instances[0].push(hash);
        }

        builder.calculate_params(Some(9));
        MockProver::run(k as u32, &builder, vec![expected_hashes])
            .unwrap()
            .assert_satisfied();
    }
}
