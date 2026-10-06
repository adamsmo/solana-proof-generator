use shielded_pool_circuit::{
    circuit::{
        consts::{MAX_CHUNKS, PROD_TREE_DEPTH},
        prover::{build_test_input, generate_test_vector, FIXTURE_SEED},
    },
    Fr,
};

#[test]
fn shielded_pool_bn254_gwc_verifies_and_rejects_tampering() {
    let chunks: [Fr; MAX_CHUNKS] = [Fr::from(2), Fr::from(3), Fr::from(4)];
    // Three different destinations, unlike the checked-in fixture where all three are the
    // same key. The proof then has to pick addresses[step], not just any of them.
    let addresses: [Fr; MAX_CHUNKS] = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];
    let input = build_test_input::<PROD_TREE_DEPTH>(chunks, Fr::from(9), addresses, 0);
    let vector = generate_test_vector(input, FIXTURE_SEED).unwrap();

    assert!(halo2_solana_verifier::verify_gwc(
        &vector.vk_bytes,
        &vector.proof_bytes,
        &vector.public_inputs,
        &vector.kzg_vk,
    )
    .unwrap());

    let mut wrong_inputs = vector.public_inputs;
    wrong_inputs[1][31] ^= 1;
    assert!(!halo2_solana_verifier::verify_gwc(
        &vector.vk_bytes,
        &vector.proof_bytes,
        &wrong_inputs,
        &vector.kzg_vk,
    )
    .unwrap_or(false));

    let mut wrong_proof = vector.proof_bytes.clone();
    let last = wrong_proof.len() - 1;
    wrong_proof[last] ^= 1;
    assert!(!halo2_solana_verifier::verify_gwc(
        &vector.vk_bytes,
        &wrong_proof,
        &vector.public_inputs,
        &vector.kzg_vk,
    )
    .unwrap_or(false));
}
