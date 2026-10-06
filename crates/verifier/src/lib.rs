#![cfg_attr(not(feature = "std"), no_std)]
// Raw Solana syscall FFI (keccak / big_mod_exp) needs `unsafe`. Cryptographic
// logic stays safe; forbid unsafe when the syscall feature is off.
#![cfg_attr(not(feature = "solana-syscalls"), forbid(unsafe_code))]

//! halo2-solana-verifier
//!
//! BN254/KZG verifier for Halo2 proofs, designed for the Solana SBF VM.
//! The GWC verification path is covered by generated-proof, checked-fixture,
//! tamper-rejection and Mollusk tests.
//!
//! Architecture:
//!   - On-chain: arkworks-bn254 for Fr (scalar field) arithmetic.
//!     Syscalls for G1/pairing (the Solana runtime also does the base-field
//!     Fq math inside those syscalls). Keccak and Fr inverse use direct
//!     Solana syscalls (`sol_keccak256`, `sol_big_mod_exp`), not
//!     `solana-program` wrappers.
//!   - Off-chain: same code paths with feature `solana-syscalls` off; the
//!     syscalls module falls back to host arkworks / sha3 ops (used for unit
//!     tests and the prover-side reference verifier).

extern crate alloc;

pub mod error;
pub mod syscalls;

pub mod curve;
pub mod field;
pub mod pairing;
pub mod transcript;

pub mod kzg;
pub mod plonk;
pub use plonk::proof_reader;

pub mod proof;
pub mod stage_state;
pub mod vk;

pub use error::Error;

use crate::kzg::KzgVk;

/// Verify a Halo2-PSE (BN254/KZG/SHPLONK) proof against the flat on-chain VK
/// bytes and a list of public inputs.
///
/// `kzg_vk` is the trimmed KZG verifying SRS (`[1]_1`, `[1]_2`, `[τ]_2`),
/// supplied by the calling program.
pub fn verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk: &KzgVk,
) -> Result<bool, Error> {
    plonk::verifier::verify(vk_bytes, proof_bytes, public_inputs, kzg_vk)
}

/// Verify an IOG Halo2 proof using BN254/KZG and the GWC19 multi-opening
/// backend.
pub fn verify_gwc(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
    kzg_vk: &KzgVk,
) -> Result<bool, Error> {
    plonk::verifier::verify_gwc(vk_bytes, proof_bytes, public_inputs, kzg_vk)
}
