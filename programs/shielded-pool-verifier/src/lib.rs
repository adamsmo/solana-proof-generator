#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use halo2_solana_verifier::{
    curve::{G1, G2},
    kzg::KzgVk,
    verify_gwc,
};

const MAGIC: &[u8; 8] = b"H2PF0001";
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;
const EXPECTED_VK: &[u8] = include_bytes!("../../../fixtures/vk.bin");
const EXPECTED_KZG_VK: &[u8] = include_bytes!("../../../fixtures/kzg_vk.bin");

pub const VERIFY_TAG: u8 = 0;
#[cfg(feature = "cu-bench")]
pub const BENCH_CUSTOM_MUL_TAG: u8 = 0x42;
#[cfg(feature = "cu-bench")]
pub const BENCH_ARK_MUL_TAG: u8 = 0x43;

pub mod errors {
    pub const MALFORMED_INPUT: u32 = 0x100;
    pub const PROOF_OUT_OF_BOUNDS: u32 = 0x102;
    pub const PUBLIC_INPUTS_OUT_OF_BOUNDS: u32 = 0x104;
    pub const VERIFIER_REJECTED: u32 = 0x200;
    pub const VERIFIER_ERROR: u32 = 0x201;
    pub const NO_ACCOUNT: u32 = 0x301;
}

struct ParsedInput<'a> {
    proof: &'a [u8],
    public_inputs: Vec<[u8; 32]>,
}

fn parse_fixture(data: &[u8]) -> Result<ParsedInput<'_>, u32> {
    if data.len() < MAGIC.len() + 4 || &data[..MAGIC.len()] != MAGIC {
        return Err(errors::MALFORMED_INPUT);
    }
    let mut cursor = MAGIC.len();

    let proof_len = read_u32_le(data, &mut cursor)? as usize;
    let proof_end = cursor
        .checked_add(proof_len)
        .ok_or(errors::PROOF_OUT_OF_BOUNDS)?;
    if proof_end > data.len() {
        return Err(errors::PROOF_OUT_OF_BOUNDS);
    }
    let proof = &data[cursor..proof_end];
    cursor = proof_end;

    let public_input_count = read_u32_le(data, &mut cursor)? as usize;
    let public_input_len = public_input_count
        .checked_mul(32)
        .ok_or(errors::PUBLIC_INPUTS_OUT_OF_BOUNDS)?;
    let public_input_end = cursor
        .checked_add(public_input_len)
        .ok_or(errors::PUBLIC_INPUTS_OUT_OF_BOUNDS)?;
    if public_input_end != data.len() {
        return Err(errors::PUBLIC_INPUTS_OUT_OF_BOUNDS);
    }
    // This is making a heap allocation (Vec allocates on heap)
    let mut public_inputs = Vec::with_capacity(public_input_count);
    while cursor < public_input_end {
        let mut value = [0u8; 32];
        value.copy_from_slice(&data[cursor..cursor + 32]);
        public_inputs.push(value);
        cursor += 32;
    }

    Ok(ParsedInput {
        proof,
        public_inputs,
    })
}

fn pinned_kzg_vk() -> KzgVk {
    let mut g1_one = [0u8; G1_LEN];
    g1_one.copy_from_slice(&EXPECTED_KZG_VK[..G1_LEN]);
    let mut g2_one = [0u8; G2_LEN];
    g2_one.copy_from_slice(&EXPECTED_KZG_VK[G1_LEN..G1_LEN + G2_LEN]);
    let mut g2_tau = [0u8; G2_LEN];
    g2_tau.copy_from_slice(&EXPECTED_KZG_VK[G1_LEN + G2_LEN..]);

    KzgVk {
        g1_one: G1(g1_one),
        g2_one: G2(g2_one),
        g2_tau: G2(g2_tau),
    }
}

fn read_u32_le(data: &[u8], cursor: &mut usize) -> Result<u32, u32> {
    let end = cursor.checked_add(4).ok_or(errors::MALFORMED_INPUT)?;
    let raw: [u8; 4] = data
        .get(*cursor..end)
        .ok_or(errors::MALFORMED_INPUT)?
        .try_into()
        .map_err(|_| errors::MALFORMED_INPUT)?;
    *cursor = end;
    Ok(u32::from_le_bytes(raw))
}

pub fn run(fixture: &[u8]) -> Result<(), u32> {
    let parsed = parse_fixture(fixture)?;
    let kzg_vk = pinned_kzg_vk();
    match verify_gwc(EXPECTED_VK, parsed.proof, &parsed.public_inputs, &kzg_vk) {
        Ok(true) => Ok(()),
        Ok(false) => Err(errors::VERIFIER_REJECTED),
        Err(_) => Err(errors::VERIFIER_ERROR),
    }
}

#[cfg(feature = "cu-bench")]
#[allow(dead_code)]
#[inline(never)]
fn bench_scalar_mul(instruction_data: &[u8], custom: bool) -> Result<(), u32> {
    use halo2_solana_verifier::field::{fr_from_bytes_be_mod_order, fr_mul, fr_to_bytes_be};

    if instruction_data.len() != 1 + 4 + 32 {
        return Err(errors::MALFORMED_INPUT);
    }
    let n = u32::from_le_bytes(
        instruction_data[1..5]
            .try_into()
            .map_err(|_| errors::MALFORMED_INPUT)?,
    );
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&instruction_data[5..37]);

    let mut one = [0u8; 32];
    one[31] = 1;
    let mut acc = fr_from_bytes_be_mod_order(&seed);
    let base = acc + fr_from_bytes_be_mod_order(&one);
    for _ in 0..n {
        acc = if custom {
            fr_mul(&acc, &base)
        } else {
            acc * base
        };
    }

    if fr_to_bytes_be(&acc) == [0u8; 32] {
        Err(errors::MALFORMED_INPUT)
    } else {
        Ok(())
    }
}

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, default_allocator, error::ProgramError,
        program_entrypoint, ProgramResult,
    };

    // set memory allocator to bump allocator (used by pinocchio and quasar)
    default_allocator!();
    program_entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let tag = instruction_data
            .first()
            .copied()
            .ok_or(ProgramError::Custom(super::errors::MALFORMED_INPUT))?;
        let account = accounts
            .first()
            .ok_or(ProgramError::Custom(super::errors::NO_ACCOUNT))?;

        match tag {
            super::VERIFY_TAG => {
                // here we are borrowing the account data not copying it on stack (zero-copy style)
                // account data contains: H2PF0001 (custom 8 byte tag) + proof + public inputs
                let data: &[u8] = unsafe { account.borrow_unchecked() };
                super::run(data).map_err(ProgramError::Custom)
            }
            #[cfg(feature = "cu-bench")]
            super::BENCH_CUSTOM_MUL_TAG => {
                super::bench_scalar_mul(instruction_data, true).map_err(ProgramError::Custom)
            }
            #[cfg(feature = "cu-bench")]
            super::BENCH_ARK_MUL_TAG => {
                super::bench_scalar_mul(instruction_data, false).map_err(ProgramError::Custom)
            }
            _ => Err(ProgramError::Custom(super::errors::MALFORMED_INPUT)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/step0/fixture.bin");

    #[test]
    fn host_run_accepts_fixture() {
        assert_eq!(run(FIXTURE), Ok(()));
    }

    #[test]
    fn host_run_rejects_changed_public_input() {
        let mut fixture = FIXTURE.to_vec();
        let last = fixture.len() - 1;
        fixture[last] ^= 1;
        assert_ne!(run(&fixture), Ok(()));
    }

    #[test]
    fn parser_rejects_trailing_bytes() {
        let mut fixture = FIXTURE.to_vec();
        fixture.push(0);
        assert_eq!(run(&fixture), Err(errors::PUBLIC_INPUTS_OUT_OF_BOUNDS));
    }
}
