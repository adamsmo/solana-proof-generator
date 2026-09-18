//! BN254 scalar (Fr) helpers.
//!
//! On-chain we only ever work with Fr arithmetic (challenges, evaluations,
//! linear combinations). Fq lives inside `alt_bn128_*` syscalls as opaque
//! 32-byte limbs. We never touch its arithmetic directly.
//!
//! Byte conventions: 32-byte big-endian at the verifier API boundary.
//! Optional SIMD-0284 conversion happens inside the syscall wrapper.

use ark_bn254::{Fr, FrConfig};
use ark_ff::{AdditiveGroup, BigInt, Field, MontConfig};

use crate::Error;

const U64_LIMB_COUNT: usize = 4;
const U32_LIMB_COUNT: usize = U64_LIMB_COUNT * 2;
const LOW_32_BITS_MASK: u64 = 0xffff_ffff;

const MODULUS_64: [u64; U64_LIMB_COUNT] = <FrConfig as MontConfig<U64_LIMB_COUNT>>::MODULUS.0;
const R2_64: [u64; U64_LIMB_COUNT] = <FrConfig as MontConfig<U64_LIMB_COUNT>>::R2.0;
const ONE_64: [u64; U64_LIMB_COUNT] = [1, 0, 0, 0];
const MONT_INV_LOW_32_BITS: u64 = <FrConfig as MontConfig<U64_LIMB_COUNT>>::INV & LOW_32_BITS_MASK;

/// BN254 scalar field modulus, canonical big-endian.
const MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[cfg(all(feature = "solana-syscalls", target_os = "solana"))]
const MODULUS_MINUS_TWO_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xef, 0xff, 0xff, 0xff,
];

/// Canonical big-endian encoding of the BN254 Fr DELTA constant used by
/// halo2's permutation argument as the coset shift multiplier.
pub const DELTA_BE: [u8; 32] = [
    0x09, 0x22, 0x6b, 0x6e, 0x22, 0xc6, 0xf0, 0xca, 0x64, 0xec, 0x26, 0xaa, 0xd4, 0xc8, 0x6e, 0x71,
    0x5b, 0x5f, 0x89, 0x8e, 0x5e, 0x96, 0x3f, 0x25, 0x87, 0x0e, 0x56, 0xbb, 0xe5, 0x33, 0xe9, 0xa2,
];

pub fn delta() -> Fr {
    fr_from_bytes_be_mod_order(&DELTA_BE)
}

const fn split_into_half_limbs(limbs: &[u64; U64_LIMB_COUNT]) -> [u64; U32_LIMB_COUNT] {
    let mut out = [0u64; U32_LIMB_COUNT];
    let mut i = 0;
    while i < U64_LIMB_COUNT {
        out[2 * i] = limbs[i] & LOW_32_BITS_MASK;
        out[2 * i + 1] = limbs[i] >> 32;
        i += 1;
    }
    out
}

const MODULUS_32: [u64; U32_LIMB_COUNT] = split_into_half_limbs(&MODULUS_64);

#[inline]
fn ge(left: &[u64; U64_LIMB_COUNT], right: &[u64; U64_LIMB_COUNT]) -> bool {
    let mut i = U64_LIMB_COUNT;
    while i > 0 {
        i -= 1;
        if left[i] > right[i] {
            return true;
        }
        if left[i] < right[i] {
            return false;
        }
    }
    true
}

#[inline]
fn sub_assign(left: &mut [u64; U64_LIMB_COUNT], right: &[u64; U64_LIMB_COUNT]) {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < U64_LIMB_COUNT {
        let (tmp, borrow_1) = left[i].overflowing_sub(right[i]);
        let (tmp, borrow_2) = tmp.overflowing_sub(borrow);
        left[i] = tmp;
        borrow = u64::from(borrow_1 || borrow_2);
        i += 1;
    }
}

/// CIOS Montgomery multiplication over eight 32-bit half-limbs.
///
/// Keeping every product at 32x32 -> 64 bits avoids the `u128`
/// multiplication emulation emitted for arkworks' generic Montgomery
/// multiplication on SBF. The wrapping operations below are intentional:
/// these sums are bounded by the half-limb construction, while explicit
/// wrapping prevents workspace-wide overflow checks from adding SBF guards
/// to every inner-loop operation.
fn mont_mul(left: &[u64; U64_LIMB_COUNT], right: &[u64; U64_LIMB_COUNT]) -> [u64; U64_LIMB_COUNT] {
    let a = split_into_half_limbs(left);
    let b = split_into_half_limbs(right);

    let mut t = [0u64; U32_LIMB_COUNT];
    let mut t_hi = 0u64;
    let mut t_top;

    for i in 0..U32_LIMB_COUNT {
        let ai = a[i];
        let mut carry = 0u64;
        for j in 0..U32_LIMB_COUNT {
            let tmp = t[j].wrapping_add(ai.wrapping_mul(b[j])).wrapping_add(carry);
            t[j] = tmp & LOW_32_BITS_MASK;
            carry = tmp >> 32;
        }
        let tmp = t_hi.wrapping_add(carry);
        t_hi = tmp & LOW_32_BITS_MASK;
        t_top = tmp >> 32;

        let m = t[0].wrapping_mul(MONT_INV_LOW_32_BITS) & LOW_32_BITS_MASK;
        let tmp = t[0].wrapping_add(m.wrapping_mul(MODULUS_32[0]));
        let mut carry = tmp >> 32;
        for j in 1..U32_LIMB_COUNT {
            let tmp = t[j]
                .wrapping_add(m.wrapping_mul(MODULUS_32[j]))
                .wrapping_add(carry);
            t[j - 1] = tmp & LOW_32_BITS_MASK;
            carry = tmp >> 32;
        }
        let tmp = t_hi.wrapping_add(carry);
        t[U32_LIMB_COUNT - 1] = tmp & LOW_32_BITS_MASK;
        t_hi = t_top.wrapping_add(tmp >> 32);
    }

    let mut out = [
        t[0] | (t[1] << 32),
        t[2] | (t[3] << 32),
        t[4] | (t[5] << 32),
        t[6] | (t[7] << 32),
    ];
    if t_hi != 0 || ge(&out, &MODULUS_64) {
        sub_assign(&mut out, &MODULUS_64);
    }
    out
}

#[inline]
fn limbs_from_be(bytes: &[u8; 32]) -> [u64; U64_LIMB_COUNT] {
    let mut out = [0u64; U64_LIMB_COUNT];
    let mut i = 0;
    while i < U64_LIMB_COUNT {
        let offset = (U64_LIMB_COUNT - 1 - i) * 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        out[i] = u64::from_be_bytes(limb_bytes);
        i += 1;
    }
    out
}

#[inline]
fn fr_from_reduced_limbs(limbs: &[u64; U64_LIMB_COUNT]) -> Fr {
    Fr::new_unchecked(BigInt::new(mont_mul(limbs, &R2_64)))
}

/// Decode a 32-byte big-endian scalar, rejecting representations at or above
/// the Fr modulus.
pub fn fr_from_bytes_be(bytes: &[u8; 32]) -> Result<Fr, Error> {
    if !is_strictly_less(bytes, &MODULUS_BE) {
        return Err(Error::PublicInputOutOfRange);
    }
    Ok(fr_from_reduced_limbs(&limbs_from_be(bytes)))
}

/// Reduce a 32-byte big-endian integer modulo Fr.
pub fn fr_from_bytes_be_mod_order(bytes: &[u8; 32]) -> Fr {
    let mut limbs = limbs_from_be(bytes);
    while ge(&limbs, &MODULUS_64) {
        sub_assign(&mut limbs, &MODULUS_64);
    }
    fr_from_reduced_limbs(&limbs)
}

/// Encode an Fr to its canonical 32-byte big-endian representation.
pub fn fr_to_bytes_be(value: &Fr) -> [u8; 32] {
    let limbs = mont_mul(&value.0 .0, &ONE_64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < U64_LIMB_COUNT {
        let offset = (U64_LIMB_COUNT - 1 - i) * 8;
        out[offset..offset + 8].copy_from_slice(&limbs[i].to_be_bytes());
        i += 1;
    }
    out
}

#[inline]
pub fn fr_mul(left: &Fr, right: &Fr) -> Fr {
    Fr::new_unchecked(BigInt::new(mont_mul(&left.0 .0, &right.0 .0)))
}

#[inline]
pub fn fr_square(value: &Fr) -> Fr {
    fr_mul(value, value)
}

pub fn fr_pow_u64(base: &Fr, mut exponent: u64) -> Fr {
    let mut acc = Fr::ONE;
    let mut power = *base;
    while exponent != 0 {
        if exponent & 1 == 1 {
            acc = fr_mul(&acc, &power);
        }
        exponent >>= 1;
        if exponent != 0 {
            power = fr_square(&power);
        }
    }
    acc
}

pub fn fr_inverse(value: &Fr) -> Option<Fr> {
    if *value == Fr::ZERO {
        return None;
    }

    #[cfg(all(feature = "solana-syscalls", target_os = "solana"))]
    {
        // Same ABI as solana-big-mod-exp 3.x (what solana-program re-exported):
        // pass BE limbs through BigModExpParams into sol_big_mod_exp.
        #[repr(C)]
        struct BigModExpParams {
            base: *const u8,
            base_len: u64,
            exponent: *const u8,
            exponent_len: u64,
            modulus: *const u8,
            modulus_len: u64,
        }

        use solana_define_syscall::definitions::sol_big_mod_exp;

        let base = fr_to_bytes_be(value);
        let mut result = [0u8; 32];
        let params = BigModExpParams {
            base: base.as_ptr(),
            base_len: base.len() as u64,
            exponent: MODULUS_MINUS_TWO_BE.as_ptr(),
            exponent_len: MODULUS_MINUS_TWO_BE.len() as u64,
            modulus: MODULUS_BE.as_ptr(),
            modulus_len: MODULUS_BE.len() as u64,
        };
        // SAFETY: params point at live 32-byte buffers; syscall writes
        // modulus_len bytes into `result`.
        unsafe {
            sol_big_mod_exp(
                &params as *const BigModExpParams as *const u8,
                result.as_mut_ptr(),
            );
        }
        return fr_from_bytes_be(&result).ok();
    }

    #[cfg(not(all(feature = "solana-syscalls", target_os = "solana")))]
    {
        value.inverse()
    }
}

#[inline]
fn is_strictly_less(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    false
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};

    fn ark_to_be(value: &Fr) -> [u8; 32] {
        let bytes = value.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn next_u64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn samples() -> alloc::vec::Vec<[u8; 32]> {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut modulus_plus_one = MODULUS_BE;
        modulus_plus_one[31] += 1;
        let mut out = alloc::vec![[0u8; 32], one, MODULUS_BE, modulus_plus_one, [0xffu8; 32],];
        let mut state = 0x1234_5678_9abc_def1u64;
        for _ in 0..8 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next_u64(&mut state).to_be_bytes());
            }
            out.push(bytes);
        }
        out
    }

    #[test]
    fn scalar_ops_match_arkworks() {
        let samples = samples();
        for a_bytes in &samples {
            let a = fr_from_bytes_be_mod_order(a_bytes);
            let ark_a = Fr::from_be_bytes_mod_order(a_bytes);
            assert_eq!(fr_to_bytes_be(&a), ark_to_be(&ark_a), "from/to bytes");
            assert_eq!(fr_square(&a), ark_a.square(), "square");
            assert_eq!(fr_inverse(&a), ark_a.inverse(), "inverse");

            for exponent in [0u64, 1, 2, 3, 7, 64, 1 << 63, u64::MAX] {
                assert_eq!(fr_pow_u64(&a, exponent), ark_a.pow([exponent]), "pow");
            }

            for b_bytes in &samples {
                let b = fr_from_bytes_be_mod_order(b_bytes);
                let ark_b = Fr::from_be_bytes_mod_order(b_bytes);
                assert_eq!(fr_mul(&a, &b), ark_a * ark_b, "mul");
            }
        }
    }

    #[test]
    fn strict_decode_boundaries() {
        assert!(fr_from_bytes_be(&[0u8; 32]).is_ok());

        let mut just_under = MODULUS_BE;
        just_under[31] -= 1;
        let value = fr_from_bytes_be(&just_under).unwrap();
        assert_eq!(fr_to_bytes_be(&value), just_under);

        assert!(matches!(
            fr_from_bytes_be(&MODULUS_BE),
            Err(Error::PublicInputOutOfRange)
        ));

        let mut over = MODULUS_BE;
        over[31] += 1;
        assert!(matches!(
            fr_from_bytes_be(&over),
            Err(Error::PublicInputOutOfRange)
        ));
    }

    #[test]
    fn delta_matches_arkworks_decode() {
        let decoded = delta();
        assert_eq!(decoded, Fr::from_be_bytes_mod_order(&DELTA_BE));
        assert_eq!(fr_to_bytes_be(&decoded), DELTA_BE);
    }
}
