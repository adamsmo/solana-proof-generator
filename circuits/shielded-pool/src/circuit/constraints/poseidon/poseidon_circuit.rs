use crate::circuit::constraints::poseidon::solana_poseidon_chip::{
    user_deposit_commitment_inputs, SolanaPoseidonChip,
};
use crate::circuit::constraints::poseidon::solana_poseidon_native;
use crate::circuit::consts::MAX_CHUNKS;
use crate::circuit::utils::convert_pubkey_32bytes_to_fr;
use crate::Fr;
use halo2_base::{
    gates::circuit::builder::BaseCircuitBuilder,
    halo2_proofs::{dev::MockProver, dev::VerifyFailure},
    AssignedValue,
};
use hex_literal::hex;

pub fn build_solana_poseidon_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    s: Fr,
    total_amount: Fr,
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
) {
    let chip = SolanaPoseidonChip::<MAX_CHUNKS>::new();
    let ctx = builder.main(0);

    let s_witness = ctx.load_witness(s);
    let chunks_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));
    let total_amount_witness = ctx.load_witness(total_amount);

    let poseidon_user_hash =
        chip.hash_7_inputs(ctx, s_witness, &chunks_witness, &addresses_witness);
    let poseidon_final_hash = chip.hash_2_inputs(ctx, poseidon_user_hash, total_amount_witness);

    builder.assigned_instances[0].push(poseidon_final_hash);
}

pub fn run_constraint_1_solana_poseidon_test_ok() -> Result<(), Vec<VerifyFailure>> {
    let k: usize = 16;

    // --- private proof values
    let s = Fr::from(1234567890);
    let total_amount = Fr::from(7);
    let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
    // Demo addresses are already field elements. Raw Solana pubkeys need a
    // separate, identical field-mapping step in both the circuit and program.
    let addr_hex: [u8; 32] =
        hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
    let addresses = [addr_hex, addr_hex, addr_hex];

    let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_pubkey_32bytes_to_fr);
    // ---

    let commitment_inputs = &user_deposit_commitment_inputs(s, &chunks, &addresses_fr);
    let poseidon_user_hash = solana_poseidon_native::hash7(commitment_inputs);
    println!(
        "Solana-compatible Poseidon user hash: {:?}",
        poseidon_user_hash
    );
    let poseidon_final_hash = solana_poseidon_native::hash2(&[poseidon_user_hash, total_amount]);
    println!(
        "Solana-compatible Poseidon final hash: {:?}",
        poseidon_final_hash
    );

    let mut builder = BaseCircuitBuilder::<Fr>::new(false)
        .use_k(k)
        .use_instance_columns(1);

    build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses_fr);
    builder.calculate_params(Some(9)); // blinding factor

    let public_instances = vec![vec![poseidon_final_hash]];
    let verification_result = MockProver::run(k as u32, &builder, public_instances)
        .unwrap()
        .verify();
    match &verification_result {
        Ok(()) => println!("Solana-compatible Poseidon verification successful"),
        Err(e) => println!("Solana-compatible Poseidon verification failed: {e:?}"),
    }
    verification_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::ff::Field;

    #[test]
    fn test_solana_poseidon_v2_circuit() {
        let verification_result = run_constraint_1_solana_poseidon_test_ok();
        assert!(verification_result.is_ok());
    }

    // test rejecting wrong public hash
    #[test]
    fn test_solana_poseidon_rejects_wrong_public_hash() {
        // --- private proof values
        let k = 16;
        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];
        // ---

        let user_hash =
            solana_poseidon_native::hash7(&user_deposit_commitment_inputs(s, &chunks, &addresses));
        let expected_final_hash = solana_poseidon_native::hash2(&[user_hash, total_amount]);
        let wrong_hash = expected_final_hash + Fr::ONE;

        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);
        build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses);
        builder.calculate_params(Some(9));

        assert!(MockProver::run(k as u32, &builder, vec![vec![wrong_hash]])
            .unwrap()
            .verify()
            .is_err());
    }

    // the circuit proves H = Poseidon(H_user, total_amount), so a public instance
    // computed with a different total than the one the prover used must not verify
    #[test]
    fn test_solana_poseidon_rejects_forged_total_amount() {
        // --- private proof values
        let k = 16;
        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let forged_total_amount = Fr::from(8);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addresses = [Fr::from(1001), Fr::from(1002), Fr::from(1003)];
        // ---

        let user_hash =
            solana_poseidon_native::hash7(&user_deposit_commitment_inputs(s, &chunks, &addresses));
        let forged_final_hash = solana_poseidon_native::hash2(&[user_hash, forged_total_amount]);

        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);
        build_solana_poseidon_circuit(&mut builder, s, total_amount, &chunks, &addresses);
        builder.calculate_params(Some(9));

        assert!(
            MockProver::run(k as u32, &builder, vec![vec![forged_final_hash]])
                .unwrap()
                .verify()
                .is_err()
        );
    }
}
