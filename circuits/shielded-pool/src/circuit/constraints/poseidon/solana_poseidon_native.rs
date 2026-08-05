use crate::circuit::constraints::poseidon::solana_poseidon_chip::{
    SOLANA_POSEIDON_INPUTS_2, SOLANA_POSEIDON_INPUTS_7,
};
use crate::circuit::utils::{fr_from_le_bytes, fr_to_le_bytes};
use crate::Fr;
use solana_poseidon::{hashv, Endianness, Parameters};

pub fn hash7(inputs: &[Fr; SOLANA_POSEIDON_INPUTS_7]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS_7] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

pub fn hash2(inputs: &[Fr; SOLANA_POSEIDON_INPUTS_2]) -> Fr {
    let input_bytes = inputs.map(fr_to_le_bytes);
    let input_refs: [&[u8]; SOLANA_POSEIDON_INPUTS_2] =
        input_bytes.each_ref().map(|bytes| &bytes[..]);
    let hash = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &input_refs).unwrap();
    fr_from_le_bytes(hash.to_bytes())
}

pub fn hash1(seed: u64) -> Fr {
    hash2(&[Fr::from(seed), Fr::from(seed)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash7() {
        let inputs = [Fr::from(1); SOLANA_POSEIDON_INPUTS_7];
        let hash = hash7(&inputs);
        assert_eq!(
            format!("{:?}", hash),
            "0x2276310aa7f3343a284214139d9da959be2a31b2c708a5f81954b265e53a30b8"
        );
    }

    #[test]
    fn test_hash2() {
        let inputs = [Fr::from(1); SOLANA_POSEIDON_INPUTS_2];
        let hash = hash2(&inputs);
        assert_eq!(
            format!("{:?}", hash),
            "0x007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81"
        );
    }

    #[test]
    fn test_hash1() {
        let hash = hash1(1);
        assert_eq!(
            format!("{:?}", hash),
            "0x007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81"
        );
    }
}
