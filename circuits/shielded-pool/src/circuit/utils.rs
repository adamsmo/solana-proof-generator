use crate::Fr;
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use solana_poseidon::{Endianness, Parameters};

pub fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    value.to_repr().into()
}

pub fn fr_from_le_bytes(bytes: [u8; 32]) -> Fr {
    Fr::from_repr(bytes.into()).unwrap()
}

/// Convert 32 bytes to 4 u64 limbs, each of the limbs is 8 bytes
/// (later those limbs will be converted to Fr and then used as input for Poseidon hash)
pub fn split_into_u64_limbs(bytes: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| {
        let start = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[start..start + 8]);
        u64::from_be_bytes(limb)
    })
}

/// Convert 32 bytes pubkey to Fr using Poseidon hash by splitting the 32 bytes into 4 64-bit limbs and than hash them.
/// We can not just put 32 bytes array cos those 32 bytes may not fit in Fr (254 bits).
/// Alternative:
///   Cheaper version of this conversion : Hash the whole 32bytes array and just take 254 bits that will fit in Fr (drop last two)
//     - For that we need to drop last two bits from the hash and than convert to Fr
//     -> Issue: collisions are possible, we lose part of and address
pub fn convert_pubkey_32bytes_to_fr(bytes: [u8; 32]) -> Fr {
    let limbs_as_fr: [Fr; 4] = split_into_u64_limbs(bytes).map(Fr::from);
    // poseidon hash expects 4x32 bytes arrays as input so we have to convert Fr back to bytes : u64 -> Fr -> [u8; 32]
    let limbs_as_arrays: [[u8; 32]; 4] = limbs_as_fr.each_ref().map(|limb| limb.to_repr().into());

    let hash = solana_poseidon::hashv(
        Parameters::Bn254X5,
        Endianness::LittleEndian,
        &limbs_as_arrays.each_ref().map(|l| l.as_slice()),
    )
    .unwrap();

    fr_from_le_bytes(hash.to_bytes())
}
