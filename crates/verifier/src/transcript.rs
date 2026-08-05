//! Keccak Fiat–Shamir transcript.
//!
//! Mirrors the algorithm of `snark_verifier::system::halo2::transcript::evm`
//! `EvmTranscript` (NativeLoader path) so that proofs produced with PSE
//! halo2's `Keccak256Write` (or `EvmTranscript::write_*`) verify on-chain
//! byte-for-byte.
//!
//! Algorithm (paraphrased):
//!
//! ```text
//! state := empty Vec<u8>
//! absorb_scalar(s)  : state ‖= be32(s)
//! absorb_g1(p)      : state ‖= be32(p.x) ‖ be32(p.y)
//! squeeze_challenge():
//!     padded = state ‖ (if |state| == 32 then [0x01] else [])
//!     hash   = keccak256(padded)         // 32 bytes
//!     state := hash
//!     return Fr::from_be_bytes_mod_order(hash)
//! ```
//!
//! Initial state on the verifier:
//!     `state := vk.transcript_repr (32 BE bytes)`,
//! where `transcript_repr` is the Blake2b("Halo2-Verify-Key" ‖ …) digest
//! pre-computed off-chain by the VK compiler (task #7) - this lets the
//! on-chain verifier skip Blake2b entirely.
//!
//! Why "if |state| == 32 append 0x01" matters: when squeeze_challenge runs
//! immediately after a previous squeeze (no absorbs in between), the buf
//! is exactly 32 bytes and a `0x01` is appended for domain separation.
//! Skipping this byte produces a different challenge and would silently
//! desync the prover and verifier.

use ark_bn254::Fr;

use crate::{curve::G1, syscalls, Error};

/// Minimal transcript surface used by the protocol-order proof reader.
///
/// The existing SHPLONK path and the IOG GWC path use different transcript
/// state machines, but read the same PLONK messages before the multi-opening
/// proof starts.
pub trait ProofTranscript {
    fn absorb_scalar(&mut self, be_bytes: &[u8; 32]);
    fn read_scalar(&mut self, proof: &[u8], cursor: &mut usize) -> Result<Fr, Error>;
    fn read_g1(&mut self, proof: &[u8], cursor: &mut usize) -> Result<G1, Error>;
    fn squeeze_challenge(&mut self) -> Fr;
}

pub struct Keccak256Transcript {
    state: alloc::vec::Vec<u8>,
}

impl Keccak256Transcript {
    /// Initialize the transcript with `vk.transcript_repr` (32 BE bytes)
    /// already absorbed. This matches `vk.hash_into(&mut transcript)` in
    /// PSE halo2's `verify_proof`.
    pub fn new(transcript_repr_be: &[u8; 32]) -> Self {
        let mut state = alloc::vec::Vec::with_capacity(64);
        state.extend_from_slice(transcript_repr_be);
        Self { state }
    }

    pub fn absorb_scalar(&mut self, be_bytes: &[u8; 32]) {
        self.state.extend_from_slice(be_bytes);
    }

    pub fn absorb_g1(&mut self, point: &G1) {
        self.state.extend_from_slice(&point.0); // 64 bytes BE (x ‖ y)
    }

    /// Read 32 BE bytes from `proof[cursor..]`, absorb them, advance cursor.
    /// Returns the parsed `Fr` (with strict modulus check - proof scalars
    /// must be in canonical form, just like `groth16-solana` enforces).
    pub fn read_scalar(&mut self, proof: &[u8], cursor: &mut usize) -> Result<Fr, Error> {
        if cursor.checked_add(32).map_or(true, |end| end > proof.len()) {
            return Err(Error::InvalidProofEncoding);
        }
        let bytes: &[u8; 32] = proof[*cursor..*cursor + 32].try_into().unwrap();
        let scalar = crate::field::fr_from_bytes_be(bytes)?;
        self.absorb_scalar(bytes);
        *cursor += 32;
        Ok(scalar)
    }

    /// Read 64 BE bytes (G1 affine, x ‖ y) from `proof`, absorb, advance.
    /// We do *not* perform an on-curve check here - the syscall path
    /// (`alt_bn128_*_be`) will reject malformed points downstream.
    pub fn read_g1(&mut self, proof: &[u8], cursor: &mut usize) -> Result<G1, Error> {
        if cursor.checked_add(64).map_or(true, |end| end > proof.len()) {
            return Err(Error::InvalidProofEncoding);
        }
        let bytes: [u8; 64] = proof[*cursor..*cursor + 64].try_into().unwrap();
        let p = G1(bytes);
        self.absorb_g1(&p);
        *cursor += 64;
        Ok(p)
    }

    /// Squeeze a Fr challenge from the current state. Mutates `self.state`.
    ///
    /// After this call, `state` is exactly 32 bytes (the keccak digest), so
    /// the next squeeze will append `0x01` for domain separation.
    pub fn squeeze_challenge(&mut self) -> Fr {
        // Domain separation: when state is exactly 32 bytes (i.e. previous
        // squeeze with no intervening absorbs), append 0x01 before hashing.
        let needs_domain_sep = self.state.len() == 32;
        let hash = if needs_domain_sep {
            let mut padded = alloc::vec::Vec::with_capacity(33);
            padded.extend_from_slice(&self.state);
            padded.push(0x01);
            syscalls::keccak256(&padded)
        } else {
            syscalls::keccak256(&self.state)
        };
        self.state.clear();
        self.state.extend_from_slice(&hash);
        // Challenge = hash mod Fr modulus (no strict bound check - challenges
        // are produced by hashing and may exceed the modulus before reduction).
        crate::field::fr_from_bytes_be_mod_order(&hash)
    }
}

impl ProofTranscript for Keccak256Transcript {
    fn absorb_scalar(&mut self, be_bytes: &[u8; 32]) {
        Keccak256Transcript::absorb_scalar(self, be_bytes);
    }

    fn read_scalar(&mut self, proof: &[u8], cursor: &mut usize) -> Result<Fr, Error> {
        Keccak256Transcript::read_scalar(self, proof, cursor)
    }

    fn read_g1(&mut self, proof: &[u8], cursor: &mut usize) -> Result<G1, Error> {
        Keccak256Transcript::read_g1(self, proof, cursor)
    }

    fn squeeze_challenge(&mut self) -> Fr {
        Keccak256Transcript::squeeze_challenge(self)
    }
}

/// IOG Halo2 transcript semantics with Keccak-256 and Solana's canonical
/// compressed big-endian G1 encoding.
///
/// Every common scalar or point is prefixed with `0x01`. Squeezing appends
/// `0x00`, hashes the complete accumulated stream and leaves that prefix in
/// the stream for the next challenge. This mirrors
/// `halo2_proofs::transcript::CircuitTranscript`, with Keccak replacing the
/// hash implementation.
pub struct IogKeccak256Transcript {
    accumulated: alloc::vec::Vec<u8>,
}

impl IogKeccak256Transcript {
    const PREFIX_CHALLENGE: u8 = 0x00;
    const PREFIX_COMMON: u8 = 0x01;

    pub fn new(transcript_repr_be: &[u8; 32]) -> Self {
        let mut out = Self {
            accumulated: alloc::vec::Vec::with_capacity(256),
        };
        out.absorb_scalar(transcript_repr_be);
        out
    }

    fn absorb_common(&mut self, bytes: &[u8]) {
        self.accumulated.push(Self::PREFIX_COMMON);
        self.accumulated.extend_from_slice(bytes);
    }

    pub fn absorb_scalar(&mut self, be_bytes: &[u8; 32]) {
        self.absorb_common(be_bytes);
    }

    pub fn read_scalar(&mut self, proof: &[u8], cursor: &mut usize) -> Result<Fr, Error> {
        if cursor.checked_add(32).map_or(true, |end| end > proof.len()) {
            return Err(Error::InvalidProofEncoding);
        }
        let bytes: &[u8; 32] = proof[*cursor..*cursor + 32].try_into().unwrap();
        let scalar = crate::field::fr_from_bytes_be(bytes)?;
        self.absorb_scalar(bytes);
        *cursor += 32;
        Ok(scalar)
    }

    pub fn read_g1(&mut self, proof: &[u8], cursor: &mut usize) -> Result<G1, Error> {
        if cursor.checked_add(32).map_or(true, |end| end > proof.len()) {
            return Err(Error::InvalidProofEncoding);
        }
        let compressed: [u8; 32] = proof[*cursor..*cursor + 32].try_into().unwrap();
        let point = G1(syscalls::g1_decompress(&compressed)?);
        self.absorb_common(&compressed);
        *cursor += 32;
        Ok(point)
    }

    pub fn squeeze_challenge(&mut self) -> Fr {
        let mut input = self.accumulated.clone();
        input.push(Self::PREFIX_CHALLENGE);
        let hash = syscalls::keccak256(&input);
        self.accumulated.push(Self::PREFIX_CHALLENGE);
        crate::field::fr_from_bytes_be_mod_order(&hash)
    }
}

impl ProofTranscript for IogKeccak256Transcript {
    fn absorb_scalar(&mut self, be_bytes: &[u8; 32]) {
        IogKeccak256Transcript::absorb_scalar(self, be_bytes);
    }

    fn read_scalar(&mut self, proof: &[u8], cursor: &mut usize) -> Result<Fr, Error> {
        IogKeccak256Transcript::read_scalar(self, proof, cursor)
    }

    fn read_g1(&mut self, proof: &[u8], cursor: &mut usize) -> Result<G1, Error> {
        IogKeccak256Transcript::read_g1(self, proof, cursor)
    }

    fn squeeze_challenge(&mut self) -> Fr {
        IogKeccak256Transcript::squeeze_challenge(self)
    }
}

#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    /// First squeeze without any absorbs (after construction with zero VK)
    /// must domain-separate (state was 32 bytes after `new()`).
    #[test]
    fn empty_init_first_squeeze_domain_separates() {
        let mut t1 = Keccak256Transcript::new(&[0u8; 32]);
        let c1 = t1.squeeze_challenge();
        // Reference: keccak256(0x00…00 ‖ 0x01) - 33-byte input.
        let mut padded = [0u8; 33];
        padded[32] = 0x01;
        let expected_hash = syscalls::keccak256(&padded);
        let expected = Fr::from_be_bytes_mod_order(&expected_hash);
        assert_eq!(c1, expected, "first squeeze must include 0x01 domain byte");
    }

    /// Two consecutive squeezes - second must hash `[hash_1] ‖ 0x01`.
    #[test]
    fn second_squeeze_chains_with_domain_byte() {
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let _c1 = t.squeeze_challenge();
        let state_after_first = t.state.clone();
        assert_eq!(state_after_first.len(), 32);
        let c2 = t.squeeze_challenge();

        let mut padded = alloc::vec::Vec::with_capacity(33);
        padded.extend_from_slice(&state_after_first);
        padded.push(0x01);
        let expected_hash = syscalls::keccak256(&padded);
        let expected = Fr::from_be_bytes_mod_order(&expected_hash);
        assert_eq!(c2, expected);
    }

    /// Absorbing data between squeezes disables the domain-separation byte
    /// (state is no longer exactly 32 bytes when the next squeeze runs).
    #[test]
    fn absorb_between_squeezes_omits_domain_byte() {
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let _c1 = t.squeeze_challenge();
        // Any 32-byte pattern - absorb_scalar does not enforce mod-Fr bound.
        let scalar_be = [0xABu8; 32];
        t.absorb_scalar(&scalar_be);
        // State now 64 bytes - no 0x01.
        let c2 = t.squeeze_challenge();

        let mut input = alloc::vec::Vec::with_capacity(64);
        let prev = {
            let mut padded = [0u8; 33];
            padded[32] = 0x01;
            syscalls::keccak256(&padded)
        };
        input.extend_from_slice(&prev);
        input.extend_from_slice(&scalar_be);
        let expected_hash = syscalls::keccak256(&input);
        let expected = Fr::from_be_bytes_mod_order(&expected_hash);
        assert_eq!(c2, expected);
    }

    /// `read_scalar` advances the cursor and absorbs identically to manual
    /// absorb. Verifies prover-verifier byte parity for scalar reads.
    #[test]
    fn read_scalar_round_trip() {
        // 0x0101…01 - well below BN254 Fr modulus (which starts with 0x3064…).
        let scalar_be = [0x01u8; 32];
        let mut proof = [0u8; 64];
        proof[..32].copy_from_slice(&scalar_be);

        // Path A: read_scalar.
        let mut ta = Keccak256Transcript::new(&[0u8; 32]);
        let mut cursor = 0;
        let _read = ta.read_scalar(&proof, &mut cursor).unwrap();
        let ca = ta.squeeze_challenge();

        // Path B: manual absorb.
        let mut tb = Keccak256Transcript::new(&[0u8; 32]);
        tb.absorb_scalar(&scalar_be);
        let cb = tb.squeeze_challenge();

        assert_eq!(ca, cb);
        assert_eq!(cursor, 32);
    }

    #[test]
    fn read_scalar_rejects_out_of_modulus() {
        // Construct a stream containing the BN254 Fr modulus itself (invalid).
        let modulus_be: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let mut cursor = 0;
        assert!(matches!(
            t.read_scalar(&modulus_be, &mut cursor),
            Err(Error::PublicInputOutOfRange),
        ));
    }

    /// `read_g1` parses a 64-byte BE point and the resulting challenge
    /// matches a manual `absorb_g1` of the same bytes.
    #[test]
    fn read_g1_round_trip() {
        let mut g1_bytes = [0u8; 64];
        g1_bytes[31] = 1;
        g1_bytes[63] = 2;

        let mut ta = Keccak256Transcript::new(&[0u8; 32]);
        let mut cursor = 0;
        let p = ta.read_g1(&g1_bytes, &mut cursor).unwrap();
        let ca = ta.squeeze_challenge();

        let mut tb = Keccak256Transcript::new(&[0u8; 32]);
        tb.absorb_g1(&p);
        let cb = tb.squeeze_challenge();

        assert_eq!(ca, cb);
        assert_eq!(cursor, 64);
        assert_eq!(p.0, g1_bytes);
    }

    #[test]
    fn iog_read_g1_decompresses_and_absorbs_wire_bytes() {
        use solana_bn254::compression::prelude::alt_bn128_g1_compress_be;

        let mut generator = [0u8; 64];
        generator[31] = 1;
        generator[63] = 2;
        let compressed = alt_bn128_g1_compress_be(&generator).unwrap();

        let mut from_proof = IogKeccak256Transcript::new(&[0u8; 32]);
        let mut cursor = 0;
        let point = from_proof.read_g1(&compressed, &mut cursor).unwrap();
        let challenge_from_proof = from_proof.squeeze_challenge();

        let mut manual = IogKeccak256Transcript::new(&[0u8; 32]);
        manual.absorb_common(&compressed);
        let challenge_manual = manual.squeeze_challenge();

        assert_eq!(point.0, generator);
        assert_eq!(cursor, 32);
        assert_eq!(challenge_from_proof, challenge_manual);
    }

    #[test]
    fn read_scalar_short_buffer_errors() {
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let mut cursor = 0;
        let short = [0u8; 16];
        assert!(matches!(
            t.read_scalar(&short, &mut cursor),
            Err(Error::InvalidProofEncoding),
        ));
    }
}
