//! GWC19 batched KZG multi-opening verifier for BN254.
//!
//! IOG Halo2 groups opening queries by evaluation point. For every distinct
//! point the proof contains one witness commitment. Challenges `v` and `u`
//! batch queries inside a point group and then batch the point groups.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

use crate::{
    curve::G1,
    field::fr_mul,
    kzg::{
        shplonk::{msm_g1, neg_g1, PairingInput, VerifierQuery},
        KzgVk,
    },
    Error,
};

struct PointQueries<'a> {
    point: Fr,
    queries: Vec<&'a VerifierQuery>,
}

fn group_by_point(queries: &[VerifierQuery]) -> Vec<PointQueries<'_>> {
    let mut groups: Vec<PointQueries<'_>> = Vec::new();
    for query in queries {
        if let Some(group) = groups.iter_mut().find(|group| group.point == query.point) {
            group.queries.push(query);
        } else {
            groups.push(PointQueries {
                point: query.point,
                queries: alloc::vec![query],
            });
        }
    }
    groups
}

/// Reduce a GWC proof to the two-pair KZG equation:
///
/// `e(witness, [tau]₂) * e(-right, [1]₂) = 1`
///
/// where `right = witness_with_aux + commitment_multi - eval_multi * [1]₁`.
#[inline(never)]
pub fn verify_opening(
    queries: &[VerifierQuery],
    witnesses: &[G1],
    v: Fr,
    u: Fr,
    kzg_vk: &KzgVk,
) -> Result<PairingInput, Error> {
    if queries.is_empty() {
        return Err(Error::Protocol("gwc: empty queries"));
    }

    let groups = group_by_point(queries);
    if groups.len() != witnesses.len() {
        return Err(Error::Protocol(
            "gwc: witness count does not match point groups",
        ));
    }

    let mut left_terms: Vec<(Fr, G1)> = Vec::with_capacity(witnesses.len());
    let mut right_terms: Vec<(Fr, G1)> = Vec::with_capacity(witnesses.len() + queries.len() + 1);
    let mut eval_multi = Fr::ZERO;
    let mut u_power = Fr::ONE;

    for (group, witness) in groups.iter().zip(witnesses.iter()) {
        left_terms.push((u_power, *witness));
        right_terms.push((fr_mul(&u_power, &group.point), *witness));

        let mut v_power = Fr::ONE;
        for query in &group.queries {
            let coefficient = fr_mul(&u_power, &v_power);
            right_terms.push((coefficient, query.commitment));
            eval_multi += fr_mul(&coefficient, &query.eval);
            v_power = fr_mul(&v_power, &v);
        }

        u_power = fr_mul(&u_power, &u);
    }

    right_terms.push((-eval_multi, kzg_vk.g1_one));

    let left = msm_g1(&left_terms)?;
    let right = msm_g1(&right_terms)?;
    let neg_right = neg_g1(&right)?;

    Ok(PairingInput(alloc::vec![
        (left, kzg_vk.g2_tau),
        (neg_right, kzg_vk.g2_one),
    ]))
}
