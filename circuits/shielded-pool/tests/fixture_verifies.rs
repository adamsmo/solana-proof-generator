use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};
use shielded_pool_circuit::{
    circuit::{
        constraints::poseidon::solana_poseidon_native,
        prover::{
            build_fixture_input, build_fixture_input_for_step, FIXTURE_CHUNKS,
            FIXTURE_DEST_PUBKEY, FIXTURE_STEP,
        },
        utils::convert_pubkey_32bytes_to_fr,
    },
    transcript::fr_to_be,
    Fr,
};

const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/public_inputs.bin");

/// `(step, proof, public inputs)` for the other steps of the same deposit.
const STEP_FIXTURES: [(usize, &[u8], &[u8]); 2] = [
    (
        1,
        include_bytes!("../../../fixtures/step1/proof.bin"),
        include_bytes!("../../../fixtures/step1/public_inputs.bin"),
    ),
    (
        2,
        include_bytes!("../../../fixtures/step2/proof.bin"),
        include_bytes!("../../../fixtures/step2/public_inputs.bin"),
    ),
];

fn checked_in_public_inputs() -> Vec<[u8; 32]> {
    split_public_inputs(PUBLIC_INPUTS)
}

fn split_public_inputs(bytes: &[u8]) -> Vec<[u8; 32]> {
    bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().unwrap())
        .collect()
}

fn checked_in_kzg_vk() -> KzgVk {
    let kzg_bytes = include_bytes!("../../../fixtures/kzg_vk.bin");
    KzgVk {
        g1_one: G1(kzg_bytes[..64].try_into().unwrap()),
        g2_one: G2(kzg_bytes[64..192].try_into().unwrap()),
        g2_tau: G2(kzg_bytes[192..320].try_into().unwrap()),
    }
}

#[test]
fn checked_in_bn254_gwc_fixture_verifies() {
    let vk = include_bytes!("../../../fixtures/vk.bin");
    let proof = include_bytes!("../../../fixtures/proof.bin");

    let public_inputs = checked_in_public_inputs();
    assert!(
        halo2_solana_verifier::verify_gwc(vk, proof, &public_inputs, &checked_in_kzg_vk()).unwrap()
    );
}

/// Step 1 and step 2 proofs verify with the step 0 keys, and their public inputs are the
/// ones `build_fixture_input_for_step` describes.
#[test]
fn checked_in_step_fixtures_verify_and_match_their_inputs() {
    let vk = include_bytes!("../../../fixtures/vk.bin");
    let kzg_vk = checked_in_kzg_vk();

    for (step, proof, public_inputs_bytes) in STEP_FIXTURES {
        let public_inputs = split_public_inputs(public_inputs_bytes);
        assert!(
            halo2_solana_verifier::verify_gwc(vk, proof, &public_inputs, &kzg_vk).unwrap(),
            "step {step} proof does not verify"
        );

        let input = build_fixture_input_for_step(step);
        let expected = [
            input.step,
            input.chunk_amount,
            input.dest_address,
            input.nullifier,
            input.root,
        ]
        .map(|value| fr_to_be(&value));
        assert_eq!(public_inputs, expected, "step {step} public inputs");
        assert_eq!(public_inputs[1][24..], FIXTURE_CHUNKS[step].to_be_bytes());
        // Same deposit, so the same root as step 0.
        assert_eq!(public_inputs[4], checked_in_public_inputs()[4]);
    }
}

/// The checked-in public inputs must be the ones `build_fixture_input` describes.
/// Fails if the fixture files were not regenerated after the fixture values changed.
#[test]
fn checked_in_public_inputs_match_the_fixture_input() {
    let input = build_fixture_input();
    let public_inputs = checked_in_public_inputs();

    let expected = [
        input.step,
        input.chunk_amount,
        input.dest_address,
        input.nullifier,
        input.root,
    ]
    .map(|value| fr_to_be(&value));
    assert_eq!(public_inputs, expected);

    // [step, chunk_amount, dest_address, nullifier, root], each 32 bytes big-endian.
    assert_eq!(public_inputs[0], fr_to_be(&Fr::from(FIXTURE_STEP as u64)));
    // A u64 amount sits in the last 8 bytes. Bytes 0..24 are zero.
    assert_eq!(public_inputs[1][..24], [0u8; 24]);
    assert_eq!(
        public_inputs[1][24..],
        FIXTURE_CHUNKS[FIXTURE_STEP].to_be_bytes()
    );
    assert_eq!(
        public_inputs[2],
        fr_to_be(&convert_pubkey_32bytes_to_fr(FIXTURE_DEST_PUBKEY))
    );
    assert_eq!(
        public_inputs[3],
        fr_to_be(&solana_poseidon_native::hash2(&[
            Fr::from(1_234_567_890),
            Fr::from(FIXTURE_STEP as u64)
        ]))
    );
}
