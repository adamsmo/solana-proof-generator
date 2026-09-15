use std::{env, fs, path::PathBuf};

use shielded_pool_circuit::circuit::{
    consts::MAX_CHUNKS,
    prover::{build_fixture_input_for_step, generate_test_vector, TestVector, FIXTURE_SEED},
};

fn main() -> anyhow::Result<()> {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures"));
    fs::create_dir_all(&output_dir)?;

    // Every step proves a withdrawal from the same deposit with the same circuit and setup seed,
    // so all steps share vk.bin and kzg_vk.bin. They are taken from the first step and
    // every step must reproduce them.
    let mut shared_keys: Option<(Vec<u8>, Vec<u8>)> = None;

    for step in 0..MAX_CHUNKS {
        let vector = generate_test_vector(build_fixture_input_for_step(step), FIXTURE_SEED)?;
        host_verify(&vector)?;

        let vk = &vector.vk_bytes;
        let kzg_vk = flatten_kzg_vk(&vector);
        match &shared_keys {
            None => {
                fs::write(output_dir.join("vk.bin"), vk)?;
                fs::write(output_dir.join("kzg_vk.bin"), &kzg_vk)?;
                println!("vk={} bytes", vk.len());
                println!("kzg_vk={} bytes", kzg_vk.len());
                shared_keys = Some((vk.clone(), kzg_vk));
            }
            Some((shared_vk, shared_kzg_vk)) => {
                anyhow::ensure!(
                    vk == shared_vk,
                    "step {step}: circuit vk differs from step 0"
                );
                anyhow::ensure!(
                    &kzg_vk == shared_kzg_vk,
                    "step {step}: KZG vk differs from step 0"
                );
            }
        }

        let public_inputs = flatten_public_inputs(&vector);
        let fixture = pack_fixture(&vector.proof_bytes, &public_inputs);

        let step_dir = output_dir.join(format!("step{step}"));
        fs::create_dir_all(&step_dir)?;
        fs::write(step_dir.join("proof.bin"), &vector.proof_bytes)?;
        fs::write(step_dir.join("public_inputs.bin"), &public_inputs)?;
        fs::write(step_dir.join("fixture.bin"), &fixture)?;

        println!(
            "step {step}: proof={} bytes, public_inputs={} bytes, fixture={} bytes, \
             BN254/GWC host verification=passed",
            vector.proof_bytes.len(),
            public_inputs.len(),
            fixture.len()
        );
    }

    Ok(())
}

/// `[1]_1 || [1]_2 || [tau]_2`, 320 bytes.
fn flatten_kzg_vk(vector: &TestVector) -> Vec<u8> {
    let mut kzg_vk = Vec::with_capacity(320);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g1_one.0);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g2_one.0);
    kzg_vk.extend_from_slice(&vector.kzg_vk.g2_tau.0);
    kzg_vk
}

fn flatten_public_inputs(vector: &TestVector) -> Vec<u8> {
    let mut public_inputs = Vec::with_capacity(5 * 32);
    for value in &vector.public_inputs {
        public_inputs.extend_from_slice(value);
    }
    public_inputs
}

/// H2PF0001 proof-account payload: magic, proof length, proof, public input count, public inputs.
fn pack_fixture(proof: &[u8], public_inputs: &[u8]) -> Vec<u8> {
    let mut fixture = Vec::with_capacity(8 + 4 + proof.len() + 4 + public_inputs.len());
    fixture.extend_from_slice(b"H2PF0001");
    fixture.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    fixture.extend_from_slice(proof);
    fixture.extend_from_slice(&((public_inputs.len() / 32) as u32).to_le_bytes());
    fixture.extend_from_slice(public_inputs);
    fixture
}

fn host_verify(vector: &TestVector) -> anyhow::Result<()> {
    let verified = halo2_solana_verifier::verify_gwc(
        &vector.vk_bytes,
        &vector.proof_bytes,
        &vector.public_inputs,
        &vector.kzg_vk,
    )
    .map_err(|error| anyhow::anyhow!("Solana GWC verifier: {error:?}"))?;
    anyhow::ensure!(verified, "Solana verifier rejected generated GWC proof");
    Ok(())
}
