use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
};

#[test]
fn checked_in_bn254_gwc_fixture_verifies() {
    let vk = include_bytes!("../../../fixtures/vk.bin");
    let proof = include_bytes!("../../../fixtures/proof.bin");
    let public_input_bytes = include_bytes!("../../../fixtures/public_inputs.bin");
    let kzg_bytes = include_bytes!("../../../fixtures/kzg_vk.bin");

    let public_inputs: Vec<[u8; 32]> = public_input_bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();
    let kzg_vk = KzgVk {
        g1_one: G1(kzg_bytes[..64].try_into().unwrap()),
        g2_one: G2(kzg_bytes[64..192].try_into().unwrap()),
        g2_tau: G2(kzg_bytes[192..320].try_into().unwrap()),
    };

    assert!(halo2_solana_verifier::verify_gwc(vk, proof, &public_inputs, &kzg_vk).unwrap());
}
