use std::{env, fs, path::PathBuf};

use shielded_pool_circuit::circuit::{
    consts::MAX_CHUNKS,
    prover::{
        build_fixture_input, build_fixture_input_for_step, generate_test_vector, TestVector,
        FIXTURE_SEED, FIXTURE_STEP,
    },
};

fn main() -> anyhow::Result<()> {
    let output_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures"));
    fs::create_dir_all(&output_dir)?;

    let vector = generate_test_vector(build_fixture_input(), FIXTURE_SEED)?;
    let public_inputs = flatten_public_inputs(&vector);

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

    host_verify(&vector)?;
    println!("step {FIXTURE_STEP}: BN254/GWC host verification=passed");

    // The other steps of the same deposit (step 1 and 2). Only the proof and the public inputs change,
    // so they share vk.bin and kzg_vk.bin with the step above.
    for step in (0..MAX_CHUNKS).filter(|step| *step != FIXTURE_STEP) {
        let step_vector = generate_test_vector(build_fixture_input_for_step(step), FIXTURE_SEED)?;
        anyhow::ensure!(
            step_vector.vk_bytes == vector.vk_bytes,
            "step {step}: circuit vk differs from step {FIXTURE_STEP}"
        );
        anyhow::ensure!(
            step_vector.kzg_vk.g1_one.0 == vector.kzg_vk.g1_one.0
                && step_vector.kzg_vk.g2_one.0 == vector.kzg_vk.g2_one.0
                && step_vector.kzg_vk.g2_tau.0 == vector.kzg_vk.g2_tau.0,
            "step {step}: KZG vk differs from step {FIXTURE_STEP}"
        );

        let step_dir = output_dir.join(format!("step{step}"));
        fs::create_dir_all(&step_dir)?;
        fs::write(step_dir.join("proof.bin"), &step_vector.proof_bytes)?;
        fs::write(
            step_dir.join("public_inputs.bin"),
            flatten_public_inputs(&step_vector),
        )?;

        host_verify(&step_vector)?;
        println!("step {step}: BN254/GWC host verification=passed");
    }

    Ok(())
}

fn flatten_public_inputs(vector: &TestVector) -> Vec<u8> {
    let mut public_inputs = Vec::with_capacity(5 * 32);
    for value in &vector.public_inputs {
        public_inputs.extend_from_slice(value);
    }
    public_inputs
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
