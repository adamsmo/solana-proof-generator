use std::{env, fs, path::PathBuf};

use shielded_pool_circuit::{
    circuit::{
        consts::{MAX_CHUNKS, PROD_TREE_DEPTH},
        prover::{build_test_input, generate_test_vector},
    },
    Fr,
};

fn main() -> anyhow::Result<()> {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures"));
    fs::create_dir_all(&output_dir)?;

    let chunks: [Fr; MAX_CHUNKS] = [Fr::from(2), Fr::from(3), Fr::from(4)];
    let input = build_test_input::<PROD_TREE_DEPTH>(chunks, Fr::from(9), 0);
    let vector = generate_test_vector(input, [0x53; 32])?;

    let mut public_inputs = Vec::with_capacity(5 * 32);
    for value in &vector.public_inputs {
        public_inputs.extend_from_slice(value);
    }
    let mut kzg_vk = Vec::with_capacity(320);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g1_one.0);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g2_one.0);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g2_tau.0);

    fs::write(output_dir.join("vk.bin"), &vector.vk_bytes)?;
    fs::write(output_dir.join("proof.bin"), &vector.proof_bytes)?;
    fs::write(output_dir.join("public_inputs.bin"), &public_inputs)?;
    fs::write(output_dir.join("kzg_vk.bin"), &kzg_vk)?;
    let mut fixture =
        Vec::with_capacity(8 + 4 + vector.proof_bytes.len() + 4 + public_inputs.len());
    fixture.extend_from_slice(b"H2PF0001");
    fixture.extend_from_slice(&(vector.proof_bytes.len() as u32).to_le_bytes());
    fixture.extend_from_slice(&vector.proof_bytes);
    fixture.extend_from_slice(&(vector.public_inputs.len() as u32).to_le_bytes());
    fixture.extend_from_slice(&public_inputs);
    fs::write(output_dir.join("fixture.bin"), &fixture)?;

    println!("vk={} bytes", vector.vk_bytes.len());
    println!("proof={} bytes", vector.proof_bytes.len());
    println!("public_inputs={} bytes", public_inputs.len());
    println!("kzg_vk={} bytes", kzg_vk.len());
    println!("fixture={} bytes", fixture.len());

    let verified = halo2_solana_verifier::verify_gwc(
        &vector.vk_bytes,
        &vector.proof_bytes,
        &vector.public_inputs,
        &vector.kzg_vk,
    )
    .map_err(|error| anyhow::anyhow!("Solana GWC verifier: {error:?}"))?;
    anyhow::ensure!(verified, "Solana verifier rejected generated GWC proof");

    println!("BN254/GWC host verification=passed");
    Ok(())
}
