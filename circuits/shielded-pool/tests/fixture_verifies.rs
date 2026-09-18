use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};
use shielded_pool_circuit::{
    circuit::{
        constraints::poseidon::solana_poseidon_native,
        consts::MAX_CHUNKS,
        prover::{build_fixture_input_for_step, FIXTURE_CHUNKS, FIXTURE_DEST_PUBKEY},
        utils::convert_pubkey_32bytes_to_fr,
    },
    transcript::fr_to_be,
    Fr,
};

const VK: &[u8] = include_bytes!("../../../fixtures/vk.bin");
const KZG_VK: &[u8] = include_bytes!("../../../fixtures/kzg_vk.bin");

struct StepFixture {
    step: usize,
    proof: &'static [u8],
    public_inputs: &'static [u8],
    fixture: &'static [u8],
}

macro_rules! step_fixture {
    ($step:literal) => {
        StepFixture {
            step: $step,
            proof: include_bytes!(concat!("../../../fixtures/step", $step, "/proof.bin")),
            public_inputs: include_bytes!(concat!(
                "../../../fixtures/step",
                $step,
                "/public_inputs.bin"
            )),
            fixture: include_bytes!(concat!("../../../fixtures/step", $step, "/fixture.bin")),
        }
    };
}

/// One entry per withdrawal step of the fixture deposit, in step order.
const STEP_FIXTURES: [StepFixture; MAX_CHUNKS] =
    [step_fixture!(0), step_fixture!(1), step_fixture!(2)];

fn split_public_inputs(bytes: &[u8]) -> Vec<[u8; 32]> {
    assert_eq!(bytes.len() % 32, 0);
    bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().unwrap())
        .collect()
}

fn checked_in_kzg_vk() -> KzgVk {
    KzgVk {
        g1_one: G1(KZG_VK[..64].try_into().unwrap()),
        g2_one: G2(KZG_VK[64..192].try_into().unwrap()),
        g2_tau: G2(KZG_VK[192..320].try_into().unwrap()),
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

#[test]
fn step_fixtures_are_listed_in_step_order() {
    for (index, fixture) in STEP_FIXTURES.iter().enumerate() {
        assert_eq!(fixture.step, index);
    }
}

/// Every step proof verifies against the shared `vk.bin` and `kzg_vk.bin`.
#[test]
fn checked_in_step_proofs_verify_with_shared_keys() {
    let kzg_vk = checked_in_kzg_vk();
    for StepFixture {
        step,
        proof,
        public_inputs,
        ..
    } in STEP_FIXTURES
    {
        let public_inputs = split_public_inputs(public_inputs);
        assert!(
            halo2_solana_verifier::verify_gwc(VK, proof, &public_inputs, &kzg_vk).unwrap(),
            "step {step} proof does not verify"
        );
    }
}

/// The checked-in public inputs of every step must be the ones `build_fixture_input_for_step`
/// describes. Fails if the fixture files were not regenerated after the fixture values changed.
#[test]
fn checked_in_public_inputs_match_the_fixture_input() {
    let root = split_public_inputs(STEP_FIXTURES[0].public_inputs)[4];

    for StepFixture {
        step,
        public_inputs,
        ..
    } in STEP_FIXTURES
    {
        let public_inputs = split_public_inputs(public_inputs);
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

        // [step, chunk_amount, dest_address, nullifier, root], each 32 bytes big-endian.
        assert_eq!(
            public_inputs[0],
            fr_to_be(&Fr::from(step as u64)),
            "step {step}"
        );
        // A u64 amount sits in the last 8 bytes. Bytes 0..24 are zero.
        assert_eq!(public_inputs[1][..24], [0u8; 24], "step {step}");
        assert_eq!(
            public_inputs[1][24..],
            FIXTURE_CHUNKS[step].to_be_bytes(),
            "step {step}"
        );
        assert_eq!(
            public_inputs[2],
            fr_to_be(&convert_pubkey_32bytes_to_fr(FIXTURE_DEST_PUBKEY)),
            "step {step}"
        );
        assert_eq!(
            public_inputs[3],
            fr_to_be(&solana_poseidon_native::hash2(&[
                Fr::from(1_234_567_890),
                Fr::from(step as u64)
            ])),
            "step {step}"
        );
        // Same deposit, so every step has the same root.
        assert_eq!(public_inputs[4], root, "step {step} root");
    }
}

/// Every packed `fixture.bin` is the H2PF0001 payload of that step's proof and public inputs.
#[test]
fn checked_in_packed_fixtures_contain_their_step_proof_and_public_inputs() {
    for StepFixture {
        step,
        proof,
        public_inputs,
        fixture,
    } in STEP_FIXTURES
    {
        assert_eq!(&fixture[..8], b"H2PF0001", "step {step} magic");
        let proof_len = read_u32_le(fixture, 8);
        assert_eq!(proof_len, proof.len(), "step {step} proof length");
        let proof_end = 12 + proof_len;
        assert_eq!(&fixture[12..proof_end], proof, "step {step} proof");
        let public_input_count = read_u32_le(fixture, proof_end);
        assert_eq!(public_input_count, 5, "step {step} public input count");
        assert_eq!(
            &fixture[proof_end + 4..],
            public_inputs,
            "step {step} public inputs"
        );
    }
}
