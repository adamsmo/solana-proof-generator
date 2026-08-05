#![cfg(feature = "svm-test")]

use halo2_solana_verifier::{
    curve::{G1, G2},
    field::fr_from_bytes_be,
    pairing::pairing_check,
    vk::parse_vk,
};
use mollusk_svm::{
    result::{InstructionResult, ProgramResult},
    Mollusk,
};
use solana_account::Account;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::{env, fs, ops::Range, path::PathBuf};

const PROGRAM_NAME: &str = "shielded_pool_solana_verifier";
const VERIFY_TAG: u8 = 0;
const SOLANA_TRANSACTION_CU_LIMIT: u64 = 1_400_000;
const MALFORMED_INPUT: u32 = 0x100;
const PROOF_OUT_OF_BOUNDS: u32 = 0x102;
const PUBLIC_INPUTS_OUT_OF_BOUNDS: u32 = 0x104;
const VERIFIER_REJECTED: u32 = 0x200;
const VERIFIER_ERROR: u32 = 0x201;
const FIXTURE_MAGIC_LEN: usize = 8;
const KZG_G1_LEN: usize = 64;
const KZG_G2_LEN: usize = 128;
#[cfg(feature = "cu-bench")]
const BENCH_CUSTOM_MUL_TAG: u8 = 0x42;
#[cfg(feature = "cu-bench")]
const BENCH_ARK_MUL_TAG: u8 = 0x43;

#[derive(Debug)]
struct FixtureSections {
    proof_len: Range<usize>,
    proof: Range<usize>,
    public_inputs: Range<usize>,
}

fn checked_in_fixture() -> Vec<u8> {
    include_bytes!("../../../fixtures/fixture.bin").to_vec()
}

fn read_u32_le(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn fixture_sections(fixture: &[u8]) -> FixtureSections {
    assert!(fixture.len() >= FIXTURE_MAGIC_LEN + 4);

    let proof_len = FIXTURE_MAGIC_LEN..FIXTURE_MAGIC_LEN + 4;
    let proof_size = read_u32_le(fixture, proof_len.start);
    let proof_start = proof_len.end;
    let proof_end = proof_start + proof_size;

    let public_input_count_offset = proof_end;
    let public_input_count = read_u32_le(fixture, public_input_count_offset);
    let public_inputs =
        public_input_count_offset + 4..public_input_count_offset + 4 + public_input_count * 32;

    assert_eq!(public_inputs.end, fixture.len());

    FixtureSections {
        proof_len,
        proof: proof_start..proof_end,
        public_inputs,
    }
}

fn program_elf() -> Vec<u8> {
    let output_dir = env::var_os("SBF_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy"));
    let path = output_dir.join(format!("{PROGRAM_NAME}.so"));
    fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read SBF program at {}: {error}; build it with cargo build-sbf first",
            path.display()
        )
    })
}

fn run_instruction_with_fixture_and_limit(
    instruction_data: Vec<u8>,
    fixture: &[u8],
    compute_unit_limit: u64,
) -> mollusk_svm::result::InstructionResult {
    let program_id = Pubkey::new_unique();
    let data_pubkey = Pubkey::new_unique();
    let mut data_account = Account::new(100_000_000, fixture.len(), &program_id);
    data_account.data.copy_from_slice(fixture);

    let elf = program_elf();
    let mut mollusk = Mollusk::default();
    mollusk.add_program_with_loader_and_elf(
        &program_id,
        &mollusk_svm::program::loader_keys::LOADER_V3,
        &elf,
    );
    mollusk.compute_budget.compute_unit_limit = compute_unit_limit;
    mollusk.compute_budget.heap_size = 256 * 1024;

    let instruction = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(data_pubkey, false)],
        data: instruction_data,
    };
    mollusk.process_instruction(&instruction, &[(data_pubkey, data_account)])
}

fn run_instruction_with_limit(
    instruction_data: Vec<u8>,
    compute_unit_limit: u64,
) -> mollusk_svm::result::InstructionResult {
    run_instruction_with_fixture_and_limit(
        instruction_data,
        &checked_in_fixture(),
        compute_unit_limit,
    )
}

fn run_with_limit(compute_unit_limit: u64) -> mollusk_svm::result::InstructionResult {
    run_instruction_with_limit(vec![VERIFY_TAG], compute_unit_limit)
}

fn verify_fixture(fixture: &[u8]) -> InstructionResult {
    run_instruction_with_fixture_and_limit(vec![VERIFY_TAG], fixture, SOLANA_TRANSACTION_CU_LIMIT)
}

fn assert_custom_error(result: &InstructionResult, expected: u32) {
    assert_eq!(
        result.raw_result,
        Err(InstructionError::Custom(expected)),
        "unexpected program result: {:?}",
        result.program_result,
    );
}

#[cfg(feature = "cu-bench")]
fn scalar_mul_bench_cu(tag: u8, n: u32) -> u64 {
    let mut data = vec![tag];
    data.extend_from_slice(&n.to_le_bytes());
    data.extend_from_slice(&[0xabu8; 32]);
    let result = run_instruction_with_limit(data, 1_000_000_000);
    assert!(matches!(result.program_result, ProgramResult::Success));
    result.compute_units_consumed
}

#[cfg(feature = "cu-bench")]
#[test]
fn compare_custom_and_ark_scalar_mul_cu() {
    let low_n = 100;
    let high_n = 1_100;

    let custom_low = scalar_mul_bench_cu(BENCH_CUSTOM_MUL_TAG, low_n);
    let custom_high = scalar_mul_bench_cu(BENCH_CUSTOM_MUL_TAG, high_n);
    let ark_low = scalar_mul_bench_cu(BENCH_ARK_MUL_TAG, low_n);
    let ark_high = scalar_mul_bench_cu(BENCH_ARK_MUL_TAG, high_n);

    eprintln!(
        "custom_fr_mul_cu_per_call={:.3}",
        (custom_high - custom_low) as f64 / (high_n - low_n) as f64
    );
    eprintln!(
        "ark_fr_mul_cu_per_call={:.3}",
        (ark_high - ark_low) as f64 / (high_n - low_n) as f64
    );
    eprintln!(
        "custom_low={custom_low} custom_high={custom_high} ark_low={ark_low} ark_high={ark_high}"
    );
}

#[test]
fn shielded_pool_gwc_verifies_inside_svm_and_reports_cu() {
    let result = run_with_limit(1_000_000_000);
    eprintln!("program_result={:?}", result.program_result);
    eprintln!("compute_units_consumed={}", result.compute_units_consumed);
    eprintln!(
        "account_payload_bytes={}",
        include_bytes!("../../../fixtures/fixture.bin").len()
    );
    assert!(matches!(result.program_result, ProgramResult::Success));
}

#[test]
fn shielded_pool_gwc_fits_current_transaction_cu_limit() {
    let result = run_with_limit(SOLANA_TRANSACTION_CU_LIMIT);
    eprintln!("program_result={:?}", result.program_result);
    eprintln!("compute_units_consumed={}", result.compute_units_consumed);
    assert!(
        matches!(result.program_result, ProgramResult::Success),
        "verification exceeded the {SOLANA_TRANSACTION_CU_LIMIT} CU transaction limit"
    );
    assert!(result.compute_units_consumed <= SOLANA_TRANSACTION_CU_LIMIT);
}

#[test]
fn shielded_pool_gwc_rejects_changed_public_input_inside_svm_at_pairing() {
    let mut fixture = checked_in_fixture();
    let sections = fixture_sections(&fixture);

    // Public input #1 is chunk_amount. Flip its low bit while keeping a
    // canonical Fr encoding so parsing succeeds and verification reaches the
    // final pairing equation.
    let chunk_amount_last_byte = sections.public_inputs.start + 32 + 31;
    fixture[chunk_amount_last_byte] ^= 1;
    let changed: [u8; 32] = fixture
        [sections.public_inputs.start + 32..sections.public_inputs.start + 64]
        .try_into()
        .unwrap();
    assert!(fr_from_bytes_be(&changed).is_ok());

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, VERIFIER_REJECTED);
}

#[test]
fn shielded_pool_gwc_rejects_changed_proof_scalar_inside_svm_at_pairing() {
    let mut fixture = checked_in_fixture();
    let sections = fixture_sections(&fixture);
    let protocol = parse_vk(include_bytes!("../../../fixtures/vk.bin")).unwrap();

    // read_gwc_proof reads all of these compressed G1 points before the first
    // advice evaluation. Deriving the offset from VK metadata keeps the test
    // stable if the circuit shape changes.
    let g1_count_before_evals = protocol.num_advice
        + 2 * protocol.num_lookups()
        + protocol.num_perm_chunks
        + protocol.num_lookups()
        + protocol.num_shuffles()
        + 1
        + protocol.cs_degree.saturating_sub(1);
    let first_eval = sections.proof.start + g1_count_before_evals * 32;
    assert!(first_eval + 32 <= sections.proof.end);

    fixture[first_eval + 31] ^= 1;
    let changed: [u8; 32] = fixture[first_eval..first_eval + 32].try_into().unwrap();
    assert!(fr_from_bytes_be(&changed).is_ok());

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, VERIFIER_REJECTED);
}

#[test]
fn shielded_pool_gwc_rejects_invalid_compressed_g1_inside_svm() {
    let mut fixture = checked_in_fixture();
    let sections = fixture_sections(&fixture);

    fixture[sections.proof.start..sections.proof.start + 32].fill(0xff);

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, VERIFIER_ERROR);
}

#[test]
fn shielded_pool_gwc_rejects_wrong_fixture_magic_inside_svm() {
    let mut fixture = checked_in_fixture();
    fixture[0] ^= 1;

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, MALFORMED_INPUT);
}

#[test]
fn shielded_pool_gwc_rejects_proof_length_out_of_bounds_inside_svm() {
    let mut fixture = checked_in_fixture();
    let sections = fixture_sections(&fixture);
    fixture[sections.proof_len].copy_from_slice(&u32::MAX.to_le_bytes());

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, PROOF_OUT_OF_BOUNDS);
}

#[test]
fn shielded_pool_gwc_rejects_trailing_fixture_bytes_inside_svm() {
    let mut fixture = checked_in_fixture();
    fixture.push(0);

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, PUBLIC_INPUTS_OUT_OF_BOUNDS);
}

#[test]
fn shielded_pool_gwc_rejects_noncanonical_public_input_inside_svm() {
    let mut fixture = checked_in_fixture();
    let sections = fixture_sections(&fixture);
    fixture[sections.public_inputs.start..sections.public_inputs.start + 32].fill(0xff);

    let result = verify_fixture(&fixture);
    assert_custom_error(&result, VERIFIER_ERROR);
}

#[test]
fn pairing_rejects_non_identity_product() {
    let kzg_vk = include_bytes!("../../../fixtures/kzg_vk.bin");
    let g1_one = G1(kzg_vk[..KZG_G1_LEN].try_into().unwrap());
    let g2_one = G2(kzg_vk[KZG_G1_LEN..KZG_G1_LEN + KZG_G2_LEN]
        .try_into()
        .unwrap());

    assert!(!pairing_check(&[(g1_one, g2_one)]).unwrap());
}
