use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};
use shielded_pool_circuit::{
    circuit::{
        constraints::poseidon::solana_poseidon_native,
        prover::{build_fixture_input, FIXTURE_CHUNKS, FIXTURE_DEST_PUBKEY, FIXTURE_STEP},
        utils::convert_pubkey_32bytes_to_fr,
    },
    transcript::fr_to_be,
    Fr,
};

const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/public_inputs.bin");

fn checked_in_public_inputs() -> Vec<[u8; 32]> {
    PUBLIC_INPUTS
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().unwrap())
        .collect()
}

#[test]
fn checked_in_bn254_gwc_fixture_verifies() {
    let vk = include_bytes!("../../../fixtures/vk.bin");
    let proof = include_bytes!("../../../fixtures/proof.bin");
    let kzg_bytes = include_bytes!("../../../fixtures/kzg_vk.bin");

    let public_inputs = checked_in_public_inputs();
    let kzg_vk = KzgVk {
        g1_one: G1(kzg_bytes[..64].try_into().unwrap()),
        g2_one: G2(kzg_bytes[64..192].try_into().unwrap()),
        g2_tau: G2(kzg_bytes[192..320].try_into().unwrap()),
    };

    assert!(halo2_solana_verifier::verify_gwc(vk, proof, &public_inputs, &kzg_vk).unwrap());
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
