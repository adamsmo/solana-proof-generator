use crate::{
    circuit::{
        constraints::poseidon::solana_poseidon_native,
        consts::{MAX_CHUNKS, PROD_TREE_DEPTH},
        full_circuit::{self, build_full_circuit},
        utils::convert_pubkey_32bytes_to_fr,
    },
    transcript::{fr_to_be, g1_to_be, SolanaKeccak},
    Fr,
};
use halo2_base::{
    gates::circuit::builder::BaseCircuitBuilder,
    gates::{
        circuit::{BaseCircuitParams, CircuitBuilderStage},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk_with_k, prepare, VerifyingKey},
        poly::{commitment::Guard, gwc_kzg::GwcKZGCommitmentScheme, kzg::params::ParamsKZG},
        transcript::{CircuitTranscript, Transcript},
    },
};
use halo2_solana_verifier::{
    curve::{G1 as SolanaG1, G2 as SolanaG2},
    kzg::KzgVk,
};
use halo2_solana_vk_host::compile_vk;
use halo2curves::{
    bn256::{Bn256, G1, G2},
    ff::PrimeField,
    group::{prime::PrimeCurveAffine, Curve},
};
use hex_literal::hex;
use rand::{rngs::StdRng, SeedableRng};

pub const BLINDING_FACTOR: usize = 9;
pub const CIRCUIT_K: u32 = 16;

type GwcKzg = GwcKZGCommitmentScheme<Bn256>;
type ProofTranscript = CircuitTranscript<SolanaKeccak>;

#[derive(Clone)]
pub struct ProverInput<const TREE_DEPTH: usize> {
    pub s: Fr,
    pub total_amount: Fr,
    pub chunks: [Fr; MAX_CHUNKS],
    pub addresses: [Fr; MAX_CHUNKS],
    pub siblings_path: [Fr; TREE_DEPTH],
    pub siblings_side: [u8; TREE_DEPTH],
    pub step: Fr,
    pub chunk_amount: Fr,
    pub dest_address: Fr,
    pub nullifier: Fr,
    pub root: Fr,
}

pub struct TestVector {
    pub vk_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: [[u8; 32]; 5],
    pub kzg_vk: KzgVk,
    pub halo2_vk: VerifyingKey<Fr, GwcKzg>,
}

fn build_circuit<const TREE_DEPTH: usize>(
    stage: CircuitBuilderStage,
    k: u32,
    proof_input: &ProverInput<TREE_DEPTH>,
    pinned: Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)>,
) -> BaseCircuitBuilder<Fr> {
    let mut circuit_builder = match pinned {
        None => BaseCircuitBuilder::<Fr>::from_stage(stage)
            .use_k(k as usize)
            .use_instance_columns(1)
            .use_lookup_bits(k as usize - 1),
        Some((params, break_points)) => BaseCircuitBuilder::<Fr>::prover(params, break_points),
    };

    build_full_circuit::<TREE_DEPTH>(
        &mut circuit_builder,
        proof_input.s,
        proof_input.total_amount,
        &proof_input.chunks,
        &proof_input.addresses,
        &proof_input.siblings_path,
        &proof_input.siblings_side,
        proof_input.step,
        proof_input.chunk_amount,
        proof_input.dest_address,
        proof_input.nullifier,
    );
    circuit_builder
}

pub fn generate_test_vector<const TREE_DEPTH: usize>(
    proof_input: ProverInput<TREE_DEPTH>,
    seed: [u8; 32],
) -> anyhow::Result<TestVector> {
    let mut rng = StdRng::from_seed(seed); // used in blinding
    let params = ParamsKZG::<Bn256>::unsafe_setup(CIRCUIT_K, &mut rng);
    let public_values = vec![
        proof_input.step,
        proof_input.chunk_amount,
        proof_input.dest_address,
        proof_input.nullifier,
        proof_input.root,
    ];
    let public_instances = vec![public_values.clone()];
    let public_instance_refs: Vec<&[Fr]> = public_instances.iter().map(Vec::as_slice).collect();

    let mut keygen_circuit =
        build_circuit(CircuitBuilderStage::Keygen, CIRCUIT_K, &proof_input, None);
    let circuit_params = keygen_circuit.calculate_params(Some(BLINDING_FACTOR));
    let vk = keygen_vk_with_k(&params, &keygen_circuit, CIRCUIT_K)
        .map_err(|error| anyhow::anyhow!("keygen_vk_with_k: {error:?}"))?;
    let pk =
        keygen_pk(vk, &keygen_circuit).map_err(|error| anyhow::anyhow!("keygen_pk: {error:?}"))?;
    let break_points = keygen_circuit.break_points();

    let prover_circuit = build_circuit(
        CircuitBuilderStage::Prover,
        CIRCUIT_K,
        &proof_input,
        Some((circuit_params, break_points)),
    );
    let mut transcript = ProofTranscript::init();
    create_proof::<Fr, GwcKzg, _, _>(
        &params,
        &pk,
        &[prover_circuit],
        &[public_instance_refs.as_slice()],
        &mut rng,
        &mut transcript,
    )
    .map_err(|error| anyhow::anyhow!("create_proof: {error:?}"))?;
    let proof_bytes = transcript.finalize();

    let mut verifier_transcript = ProofTranscript::init_from_bytes(&proof_bytes);
    let guard = prepare::<Fr, GwcKzg, _>(
        pk.get_vk(),
        &[public_instance_refs.as_slice()],
        &mut verifier_transcript,
    )
    .map_err(|error| anyhow::anyhow!("prepare: {error:?}"))?;
    guard
        .verify(&params.verifier_params())
        .map_err(|error| anyhow::anyhow!("native GWC verify: {error:?}"))?;

    let vk_bytes = compile_vk(&params, pk.get_vk())
        .map_err(|error| anyhow::anyhow!("compile_vk: {error:?}"))?;
    let public_inputs: [[u8; 32]; 5] = public_values
        .iter()
        .map(fr_to_be)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let kzg_vk = KzgVk {
        g1_one: SolanaG1(g1_to_be(&G1::generator())),
        g2_one: SolanaG2(g2_to_be(&params.g2())),
        g2_tau: SolanaG2(g2_to_be(&params.s_g2())),
    };

    Ok(TestVector {
        vk_bytes,
        proof_bytes,
        public_inputs,
        kzg_vk,
        halo2_vk: pk.get_vk().clone(),
    })
}

/// Recipient of every chunk in the checked-in fixture.
/// Base58: `dstH17g8RBGdUo3YeYhSFHDdFzHrWkAzNCKSveAchyD`. These are its 32 raw bytes.
pub const FIXTURE_DEST_PUBKEY: [u8; 32] =
    hex!("097271a50fa501a5658a19ee58e6fa6d2bdc786a62d39bb5e4bf243f4561d144");
/// Fixture amounts, in lamports.
pub const FIXTURE_TOTAL_AMOUNT: u64 = 9_000_000_000;
pub const FIXTURE_CHUNKS: [u64; MAX_CHUNKS] = [2_000_000_000, 3_000_000_000, 4_000_000_000];
pub const FIXTURE_STEP: usize = 0;
/// Seed for the deterministic test KZG setup and the prover RNG.
pub const FIXTURE_SEED: [u8; 32] = [0x53; 32];

/// The witness the checked-in `fixtures/*.bin` files are generated from.
/// All three destinations are the same real public key, mapped to a field value with
/// `convert_pubkey_32bytes_to_fr`.
pub fn build_fixture_input() -> ProverInput<PROD_TREE_DEPTH> {
    build_fixture_input_for_step(FIXTURE_STEP)
}

/// Same deposit as `build_fixture_input`, but proving the withdrawal of chunk `step_idx`.
/// The checked-in `fixtures/step{1,2}/*.bin` files are generated from this.
pub fn build_fixture_input_for_step(step_idx: usize) -> ProverInput<PROD_TREE_DEPTH> {
    let dest_address = convert_pubkey_32bytes_to_fr(FIXTURE_DEST_PUBKEY);
    build_test_input(
        FIXTURE_CHUNKS.map(Fr::from),
        Fr::from(FIXTURE_TOTAL_AMOUNT),
        [dest_address; MAX_CHUNKS],
        step_idx,
    )
}

/// Witness for a deposit that is the only leaf of an otherwise empty tree.
pub fn build_test_input<const TREE_DEPTH: usize>(
    chunks: [Fr; MAX_CHUNKS],
    total_amount: Fr,
    addresses: [Fr; MAX_CHUNKS],
    step_idx: usize,
) -> ProverInput<TREE_DEPTH> {
    let s = Fr::from(1_234_567_890);
    let step = Fr::from(step_idx as u64);
    let user_hash = full_circuit::user_commitment_hash(s, &chunks, &addresses);
    let deposit_commitment = full_circuit::deposit_commitment_hash(user_hash, total_amount);
    let mut zero_value = Fr::from(0);
    let siblings_path = std::array::from_fn(|_| {
        let sibling = zero_value;
        zero_value = solana_poseidon_native::hash2(&[zero_value, zero_value]);
        sibling
    });
    let siblings_side = [1; TREE_DEPTH];
    let mut root = deposit_commitment;
    for sibling in siblings_path {
        root = solana_poseidon_native::hash2(&[root, sibling]);
    }

    ProverInput {
        s,
        total_amount,
        chunks,
        addresses,
        siblings_path,
        siblings_side,
        step,
        chunk_amount: chunks[step_idx],
        dest_address: addresses[step_idx],
        nullifier: solana_poseidon_native::hash2(&[s, step]),
        root,
    }
}

fn g2_to_be(value: &G2) -> [u8; 128] {
    let affine = value.to_affine();
    if bool::from(affine.is_identity()) {
        return [0u8; 128];
    }
    let mut out = [0u8; 128];
    let x_repr = affine.x.to_repr();
    let y_repr = affine.y.to_repr();
    for (destination, source) in out[..32]
        .iter_mut()
        .zip(x_repr.as_ref()[32..64].iter().rev())
    {
        *destination = *source;
    }
    for (destination, source) in out[32..64]
        .iter_mut()
        .zip(x_repr.as_ref()[..32].iter().rev())
    {
        *destination = *source;
    }
    for (destination, source) in out[64..96]
        .iter_mut()
        .zip(y_repr.as_ref()[32..64].iter().rev())
    {
        *destination = *source;
    }
    for (destination, source) in out[96..].iter_mut().zip(y_repr.as_ref()[..32].iter().rev()) {
        *destination = *source;
    }
    out
}
