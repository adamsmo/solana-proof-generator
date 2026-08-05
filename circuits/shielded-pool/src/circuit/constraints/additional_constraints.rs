use crate::circuit::constraints::poseidon::solana_poseidon_chip::SolanaPoseidonChip;
use crate::circuit::consts::{MAX_CHUNKS, MAX_CHUNK_AMOUNT};
use crate::Fr;
use halo2_base::gates::{GateChip, GateInstructions, RangeChip, RangeInstructions};
use halo2_base::Context;
use halo2_base::{gates::circuit::builder::BaseCircuitBuilder, AssignedValue};

/*
 Private inputs:
 - s - the user's secret
 - [2, 3, 2] -  chunks
 - [A0, A1, A2] -  addresses
 - total_amount = 7.0 - the deposited total

 Public inputs (verifier and chain see):
 - root - the root user path climbs to (the program will check it's recent root)
 - nullifier_0 = Poseidon(s, 0) - derived from her secret and step 0
 - step = 0 - the step the user wants to withdraw
 - chunk_amount = 2.0 - what to transfer
 - destination = A0 - where to send it
*/

pub struct AdditionalConstraintsChip<'a> {
    gate: GateChip<Fr>,
    range: RangeChip<Fr>,
    poseidon: &'a SolanaPoseidonChip<MAX_CHUNKS>,
}

impl<'a> AdditionalConstraintsChip<'a> {
    pub fn new(range: RangeChip<Fr>, poseidon: &'a SolanaPoseidonChip<MAX_CHUNKS>) -> Self {
        Self {
            gate: GateChip::default(),
            range,
            poseidon,
        }
    }

    pub fn step_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness and instance
        step_w: AssignedValue<Fr>,
    ) {
        // check if step is in the array bounds
        self.range
            .check_less_than_safe(ctx, step_w, MAX_CHUNKS as u64); // < MAX_CHUNKS
    }

    // check if chunk_amount == chunks[step]
    pub fn chunk_selection_and_amount_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        // instances and also witnesses
        chunk_amount_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        self.range
            .check_less_than_safe(ctx, chunk_amount_w, MAX_CHUNK_AMOUNT); // < MAX_CHUNK_AMOUNT

        // check if chunk_amount == chunks[step]
        let selected_chunk = self
            .gate
            .select_from_idx(ctx, chunks.iter().copied(), step_w);
        ctx.constrain_equal(&chunk_amount_w, &selected_chunk);
    }

    pub fn destination_selection(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        addresses: &[AssignedValue<Fr>; MAX_CHUNKS],
        // instances and also witnesses
        dest_address_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        // check if dest_address == addresses[step]
        let selected_address = self
            .gate
            .select_from_idx(ctx, addresses.iter().copied(), step_w);
        ctx.constrain_equal(&dest_address_w, &selected_address);
    }

    pub fn chunks_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
    ) {
        for chunk in chunks {
            self.range
                .check_less_than_safe(ctx, *chunk, MAX_CHUNK_AMOUNT); // < MAX_CHUNK_AMOUNT
        }
    }

    pub fn total_amount_in_range(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        total_amount_w: AssignedValue<Fr>,
    ) {
        self.range
            .check_less_than_safe(ctx, total_amount_w, MAX_CHUNK_AMOUNT); // < MAX_CHUNK_AMOUNT
    }

    pub fn chunks_sum_to_total(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        chunks: &[AssignedValue<Fr>; MAX_CHUNKS],
        total_amount_w: AssignedValue<Fr>,
    ) {
        let sum_of_chunks = self.gate.sum(ctx, chunks.iter().copied());
        ctx.constrain_equal(&total_amount_w, &sum_of_chunks);
    }

    pub fn nullifier_derivation(
        &self,
        ctx: &mut Context<Fr>,
        // witness
        s_w: AssignedValue<Fr>,
        // instances and also witnesses
        nullifier_w: AssignedValue<Fr>,
        step_w: AssignedValue<Fr>,
    ) {
        let nullifier_hash = self.poseidon.hash_2_inputs(ctx, s_w, step_w);

        ctx.constrain_equal(&nullifier_hash, &nullifier_w);
    }
}

pub fn build_additional_constraints_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    // private witness(advice) values
    chunks: &[Fr; MAX_CHUNKS],
    addresses: &[Fr; MAX_CHUNKS],
    s: Fr,
    total_amount: Fr,
    // instances (public) and witnesses (advice columns)
    step: Fr,
    chunk_amount: Fr,
    dest_address: Fr,
    nullifier: Fr,
) {
    let solana_poseidon = SolanaPoseidonChip::<MAX_CHUNKS>::new();
    let range: RangeChip<Fr> = builder.range_chip();
    let additional_constraints = AdditionalConstraintsChip::new(range, &solana_poseidon);
    let ctx = builder.main(0); // TODO: again, what is does, is this should always be at the start of the circuit ?

    let s_w = ctx.load_witness(s);
    let total_amount_w = ctx.load_witness(total_amount);
    let step_w = ctx.load_witness(step);
    let chunk_amount_w = ctx.load_witness(chunk_amount);
    let dest_address_w = ctx.load_witness(dest_address);
    let nullifier_w = ctx.load_witness(nullifier);

    let chunks_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(chunks[i]));
    let addresses_witness: [AssignedValue<Fr>; MAX_CHUNKS] =
        std::array::from_fn(|i| ctx.load_witness(addresses[i]));

    additional_constraints.step_in_range(ctx, step_w);
    additional_constraints.chunk_selection_and_amount_in_range(
        ctx,
        &chunks_witness,
        chunk_amount_w,
        step_w,
    );
    additional_constraints.destination_selection(ctx, &addresses_witness, dest_address_w, step_w);
    additional_constraints.chunks_sum_to_total(ctx, &chunks_witness, total_amount_w);
    additional_constraints.nullifier_derivation(ctx, s_w, nullifier_w, step_w);
    additional_constraints.total_amount_in_range(ctx, total_amount_w);
    additional_constraints.chunks_in_range(ctx, &chunks_witness);

    builder.assigned_instances[0].push(step_w);
    builder.assigned_instances[0].push(chunk_amount_w);
    builder.assigned_instances[0].push(dest_address_w);
    builder.assigned_instances[0].push(nullifier_w);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::constraints::poseidon::solana_poseidon_native;
    use crate::circuit::utils::convert_pubkey_32bytes_to_fr;
    use halo2_base::halo2_proofs::dev::MockProver;
    use hex_literal::hex;

    #[test]
    fn test_additional_constraints_ok() {
        let k: usize = 16;

        let s = Fr::from(1234567890);
        let total_amount = Fr::from(7);
        let chunks = [Fr::from(2), Fr::from(2), Fr::from(3)];
        let addr_hex: [u8; 32] =
            hex!("fc91f35435da1610a33bc390ba7f94227e0ac863b3c4ddf49349f0a8406114d3");
        let addresses = [addr_hex, addr_hex, addr_hex];
        let addresses_fr: [Fr; MAX_CHUNKS] = addresses.map(convert_pubkey_32bytes_to_fr);

        let step = Fr::from(0);
        let chunk_amount = chunks[0];
        let dest_address = addresses_fr[0];
        let nullifier = solana_poseidon_native::hash2(&[s, step]);

        let mut builder = BaseCircuitBuilder::<Fr>::new(false)
            .use_k(k)
            .use_instance_columns(1);

        // In constraints we check against the max value u64
        // But lookup_bits = 15 does not conflict with checking a 64-bit u64 range
        // lookup_bits is the size of each lookup limb, not the max value being checked.
        // For a 64-bit check, halo2-base decomposes the value into multiple 15-bit limbs:
        //   64 bits / 15 bits = 5 limbs, rounded up
        //   range_bits = 75
        // So with lookup_bits = 15, the range chip can still check 64-bit values by splitting them up.
        builder.set_lookup_bits(k - 1);

        build_additional_constraints_circuit(
            &mut builder,
            &chunks,
            &addresses_fr,
            s,
            total_amount,
            step,
            chunk_amount,
            dest_address,
            nullifier,
        );
        builder.calculate_params(Some(9));

        let public_instances = vec![vec![step, chunk_amount, dest_address, nullifier]];
        assert!(MockProver::run(k as u32, &builder, public_instances)
            .unwrap()
            .verify()
            .is_ok());
    }
}
