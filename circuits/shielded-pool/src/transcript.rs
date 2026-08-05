use std::io::{self, Read};

use halo2_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use halo2curves::{
    bn256::{Fq, Fr, G1Affine, G1},
    ff::{FromUniformBytes, PrimeField},
    group::{prime::PrimeCurveAffine, Curve, Group},
    CurveAffine,
};
use sha3::{Digest, Keccak256};
use solana_bn254::compression::prelude::{alt_bn128_g1_compress_be, alt_bn128_g1_decompress_be};

/// IOG Halo2 transcript state machine backed by Keccak-256.
///
/// Scalars and points use the same big-endian wire format as Solana's BN254
/// syscalls. The transcript prefixes common messages with `0x01` and
/// challenge requests with `0x00`.
#[derive(Clone, Debug, Default)]
pub struct SolanaKeccak {
    accumulated: Vec<u8>,
}

impl TranscriptHash for SolanaKeccak {
    type Input = Vec<u8>;
    type Output = [u8; 32];

    fn init() -> Self {
        Self::default()
    }

    fn absorb(&mut self, input: &Self::Input) {
        self.accumulated.push(0x01);
        self.accumulated.extend_from_slice(input);
    }

    fn squeeze(&mut self) -> Self::Output {
        let mut input = self.accumulated.clone();
        input.push(0x00);
        let digest: [u8; 32] = Keccak256::digest(input).into();
        self.accumulated.push(0x00);
        digest
    }
}

impl Hashable<SolanaKeccak> for Fr {
    fn to_input(&self) -> Vec<u8> {
        fr_to_be(self).to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        fr_to_be(self).to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut be = [0u8; 32];
        buffer.read_exact(&mut be)?;
        be.reverse();
        Option::from(Fr::from_repr(be.into()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid BN254 scalar"))
    }
}

impl Sampleable<SolanaKeccak> for Fr {
    fn sample(hash_output: [u8; 32]) -> Self {
        let mut little_endian_wide = [0u8; 64];
        for (index, byte) in hash_output.iter().rev().enumerate() {
            little_endian_wide[index] = *byte;
        }
        Fr::from_uniform_bytes(&little_endian_wide)
    }
}

impl Hashable<SolanaKeccak> for G1 {
    fn to_input(&self) -> Vec<u8> {
        g1_to_compressed_be(self).to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        g1_to_compressed_be(self).to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut compressed = [0u8; 32];
        buffer.read_exact(&mut compressed)?;
        let uncompressed = alt_bn128_g1_decompress_be(&compressed).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid compressed BN254 G1")
        })?;
        g1_from_be(uncompressed)
    }
}

pub fn fr_to_be(value: &Fr) -> [u8; 32] {
    let mut out: [u8; 32] = value.to_repr().into();
    out.reverse();
    out
}

pub fn fq_to_be(value: &Fq) -> [u8; 32] {
    let mut out: [u8; 32] = value.to_repr().into();
    out.reverse();
    out
}

pub fn g1_to_be(value: &G1) -> [u8; 64] {
    let affine = value.to_affine();
    if bool::from(affine.is_identity()) {
        return [0u8; 64];
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_be(&affine.x));
    out[32..].copy_from_slice(&fq_to_be(&affine.y));
    out
}

pub fn g1_to_compressed_be(value: &G1) -> [u8; 32] {
    alt_bn128_g1_compress_be(&g1_to_be(value)).expect("a valid BN254 G1 point must compress")
}

fn g1_from_be(bytes: [u8; 64]) -> io::Result<G1> {
    if bytes == [0u8; 64] {
        return Ok(G1::identity());
    }

    let mut x_le: [u8; 32] = bytes[..32].try_into().unwrap();
    let mut y_le: [u8; 32] = bytes[32..].try_into().unwrap();
    x_le.reverse();
    y_le.reverse();
    let x = Option::from(Fq::from_repr(x_le.into()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid BN254 G1 x"))?;
    let y = Option::from(Fq::from_repr(y_le.into()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid BN254 G1 y"))?;
    let affine = Option::<G1Affine>::from(G1Affine::from_xy(x, y))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "BN254 G1 not on curve"))?;
    Ok(affine.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField as ArkPrimeField;

    #[test]
    fn challenge_reduction_matches_onchain_arkworks() {
        let digest = [0xff; 32];
        let host = <Fr as Sampleable<SolanaKeccak>>::sample(digest);
        let host_be = fr_to_be(&host);
        let onchain = ark_bn254::Fr::from_be_bytes_mod_order(&digest);
        assert_eq!(
            host_be,
            halo2_solana_verifier::field::fr_to_bytes_be(&onchain),
        );
    }

    #[test]
    fn generator_uses_solana_big_endian_layout() {
        let bytes = g1_to_be(&G1::generator());
        let mut expected = [0u8; 64];
        expected[31] = 1;
        expected[63] = 2;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn compressed_generator_round_trips_through_solana_encoding() {
        let generator = G1::generator();
        let compressed = g1_to_compressed_be(&generator);
        assert_eq!(compressed.len(), 32);

        let uncompressed = alt_bn128_g1_decompress_be(&compressed).unwrap();
        assert_eq!(uncompressed, g1_to_be(&generator));
        assert_eq!(g1_from_be(uncompressed).unwrap(), generator);
    }
}
