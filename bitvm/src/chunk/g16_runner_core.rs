
use ark_ec::CurveGroup;
use bitcoin_script::script;

use crate::chunk::{elements::CompressedStateObject, taps_point_ops::get_hint_for_add_with_frob, primitives::HashBytes, g16_runner_utils::*};


use super::{assigner::*, api_compiletime_utils::{ATE_LOOP_COUNT, NUM_PUBS}, elements::{DataType, ElementType}};

fn compare(hint_out: &DataType, claimed_assertions: &mut Option<Vec<HashBytes>>) -> Option<bool> {
    if claimed_assertions.is_none() {
        return None;
    }
    
    fn get_hash(claimed_assertions: &mut Option<Vec<HashBytes>>) -> HashBytes {
        if let Some(claimed_assertions) = claimed_assertions {
            claimed_assertions.pop().unwrap()
        } else {
            panic!()
        }
    }
    assert!(!hint_out.output_is_field_element());
    let hint_out_hash = hint_out.to_hash();
    let mut matches = false;
    if let CompressedStateObject::Hash(hash) = hint_out_hash {
        matches = get_hash(claimed_assertions) == hash;
    } else {
        panic!()
    }
    
    Some(matches) 
}

pub(crate) fn groth16_generate_segments(
    skip_evaluation: bool,
    all_output_hints: &mut Vec<Segment>,
    eval_ins: InputProofRaw,
    pubs: PublicParams,
    claimed_assertions: &mut Option<Vec<HashBytes>>,
) -> bool {
    macro_rules! push_compare_or_return {
        ($seg:ident) => {{
            all_output_hints.push($seg.clone());
            if $seg.scr_type.is_final_script() {
                if let DataType::U256Data(felem) = $seg.result.0 {
                    if felem != ark_ff::BigInt::<4>::one() {
                        return false;
                    }
                } else {
                    panic!();
                }
            } else if $seg.is_valid_input == false {
                return false;
            } else {
                let matches = compare(&$seg.result.0, claimed_assertions);
                if matches.is_some() && matches.unwrap() == false {
                    return false;
                }
            }
        }};
    }
    let vky = pubs.ks_vks;
    let vky0 = pubs.vky0;

    let (gp2, gp4, gq4, gc, gs, pub_scalars) = raw_input_proof_to_segments(eval_ins, all_output_hints);
    let (gp2x, gp2y) = (gp2[0].clone(), gp2[1].clone());
    let (gp4x, gp4y) = (gp4[0].clone(), gp4[1].clone());
    let (q4xc0, q4xc1, q4yc0, q4yc1) = (gq4[0].clone(), gq4[1].clone(), gq4[2].clone(), gq4[3].clone());
    let gc = gc.to_vec();
    let gs = gs.to_vec();
    let pub_scalars = pub_scalars.to_vec();

    let p4 = wrap_hints_precompute_p(skip_evaluation, all_output_hints.len(), &gp4y, &gp4x);
    push_compare_or_return!(p4);

    let p2 = wrap_hints_precompute_p(skip_evaluation, all_output_hints.len(), &gp2y, &gp2x);
    push_compare_or_return!(p2);

    let msms = wrap_hint_msm(skip_evaluation, all_output_hints.len(), pub_scalars.clone(), vky.clone());
    for msm in &msms {
        push_compare_or_return!(msm);
    }

    let p_vk0 = wrap_hint_hash_p(skip_evaluation, all_output_hints.len(), &msms[msms.len()-1], vky0);
    push_compare_or_return!(p_vk0);

    let p3 = wrap_hints_precompute_p_from_hash(skip_evaluation, all_output_hints.len(), &p_vk0);
    push_compare_or_return!(p3);

    let c = wrap_hint_hash_c(skip_evaluation, all_output_hints.len(), gc.clone());
    push_compare_or_return!(c);

    let s = wrap_hint_hash_c(skip_evaluation, all_output_hints.len(), gs);
    push_compare_or_return!(s);

    let gcinv = wrap_hint_hash_c_inv(skip_evaluation, all_output_hints.len(),gc);
    push_compare_or_return!(gcinv);

    let mut t4 = wrap_hint_init_t4(skip_evaluation, all_output_hints.len(), &q4yc1, &q4yc0, &q4xc1, &q4xc0);
    push_compare_or_return!(t4);

    let (mut t2, mut t3) = (pubs.q2, pubs.q3);
    let mut f_acc = gcinv.clone();

    for j in (1..ATE_LOOP_COUNT.len()).rev() {
        if !skip_evaluation {
            println!("Processing {:?}-th iteration of Miller Loop", j);
        }
        let ate = ATE_LOOP_COUNT[j - 1];
        let sq = wrap_hint_squaring(skip_evaluation, all_output_hints.len(), &f_acc);
        push_compare_or_return!(sq);
        f_acc = sq;

        t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
            skip_evaluation, all_output_hints.len(), true, None, None,
            &t4, &p4, None, &p3, t3, None, &p2, t2, None
        );
        push_compare_or_return!(t4);
        (t2, t3) = ((t2 + t2).into_affine(), (t3 + t3).into_affine());

        let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(skip_evaluation, all_output_hints.len(), &t4);
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);

        if ate == 0 {
            continue;
        }

        let c_or_cinv = if ate == -1 { c.clone() } else { gcinv.clone() };
        f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &c_or_cinv);
        push_compare_or_return!(f_acc);


        t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
            skip_evaluation, all_output_hints.len(), false, Some(false), Some(ate),
            &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
        );
        push_compare_or_return!(t4);
        if ate == 1 {
            (t2, t3) = ((t2 + pubs.q2).into_affine(), (t3 + pubs.q3).into_affine());
        } else {
            (t2, t3) = ((t2 - pubs.q2).into_affine(), (t3 - pubs.q3).into_affine());
        }

        let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(skip_evaluation, all_output_hints.len(), &t4);
        push_compare_or_return!(lev);

        f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
        push_compare_or_return!(f_acc);
    }

    let cp = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &gcinv, 1);
    push_compare_or_return!(cp);

    let cp2 = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &c, 2);
    push_compare_or_return!(cp2);

    let cp3 = wrap_hints_frob_fp12(skip_evaluation, all_output_hints.len(), &gcinv, 3);
    push_compare_or_return!(cp3);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp2);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &cp3);
    push_compare_or_return!(f_acc);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &s);
    push_compare_or_return!(f_acc);

    t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
        skip_evaluation, all_output_hints.len(), false, Some(true), Some(1),
        &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
    );
    push_compare_or_return!(t4);

    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, 1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, 1);
    let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(skip_evaluation, all_output_hints.len(), &t4);
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);

    t4 = wrap_chunk_point_ops_and_multiply_line_evals_step_1(
        skip_evaluation, all_output_hints.len(), false, Some(true), Some(-1),
        &t4, &p4, Some(gq4.to_vec()), &p3, t3, Some(pubs.q3), &p2, t2, Some(pubs.q2)
    );
    push_compare_or_return!(t4);

    // (t2, t3) = (le.t2, le.t3);
    t2 = get_hint_for_add_with_frob(pubs.q2, t2, -1);
    t3 = get_hint_for_add_with_frob(pubs.q3, t3, -1);
    let lev = wrap_chunk_point_ops_and_multiply_line_evals_step_2(skip_evaluation, all_output_hints.len(), &t4);
    push_compare_or_return!(lev);

    f_acc = wrap_hints_dense_dense_mul(skip_evaluation, all_output_hints.len(), &f_acc, &lev);
    push_compare_or_return!(f_acc);


    let valid_facc = wrap_chunk_final_verify(skip_evaluation, all_output_hints.len(), &f_acc, pubs.fixed_acc);
    push_compare_or_return!(valid_facc);

    let is_valid: ark_ff::BigInt::<4> = valid_facc.result.0.try_into().unwrap();

    
    is_valid == ark_ff::BigInt::<4>::one()
}

fn raw_input_proof_to_segments(eval_ins: InputProofRaw, all_output_hints: &mut Vec<Segment>) -> ([Segment;2], [Segment;2], [Segment;4], [Segment;6], [Segment;6], [Segment; NUM_PUBS]) {
    let pub_scalars: Vec<Segment> = eval_ins.ks.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::ScalarElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&pub_scalars);

    let p4vec: Vec<Segment> = [eval_ins.p4[1], eval_ins.p4[0], eval_ins.p2[1], eval_ins.p2[0]].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&p4vec);
    let (gp4y, gp4x, gp2y, gp2x) = (&p4vec[0], &p4vec[1], &p4vec[2], &p4vec[3]);

    let gc: Vec<Segment> = eval_ins.c.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&gc);

    let gs: Vec<Segment> = eval_ins.s.iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&gs);

    let temp_q4: Vec<Segment> = [eval_ins.q4[0], eval_ins.q4[1], eval_ins.q4[2], eval_ins.q4[3]].iter().enumerate().map(|(idx, f)| Segment {
        id: (all_output_hints.len() + idx) as u32,
        parameter_ids: vec![],
        is_valid_input: true,
        result: (DataType::U256Data(*f), ElementType::FieldElem),
        hints: vec![],
        scr_type: ScriptType::NonDeterministic,
        scr: script!(),
    }).collect();
    all_output_hints.extend_from_slice(&temp_q4);

    ([gp2x.clone(), gp2y.clone()], [gp4x.clone(), gp4y.clone()], temp_q4.try_into().unwrap(), gc.try_into().unwrap(), gs.try_into().unwrap(), pub_scalars.try_into().unwrap())
}


#[cfg(test)]
mod test {
    use std::{ops::Neg, str::FromStr};

    use ark_bn254::Bn254;
    use ark_ec::{bn::BnConfig, pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, Field};
    use ark_serialize::CanonicalDeserialize;
    use bitcoin_script::script;
    use num_bigint::BigUint;

    use crate::{chunk::{api_compiletime_utils::NUM_PUBS, taps_point_ops::chunk_point_ops_and_multiply_line_evals_step_1}, groth16::offchain_checker::compute_c_wi};

    use super::{groth16_generate_segments, InputProof, PublicParams, Segment};


    #[test]
    fn test_groth16() {
        let vk_bytes = [115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188, 59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161].to_vec();
        let proof_bytes: Vec<u8> = [162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90, 122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218, 218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122, 206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94, 59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226, 132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29, 120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183, 5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63, 133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157, 82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214, 220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255, 188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2, 133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131, 92, 103, 103, 176, 212, 223, 177, 242, 94, 14].to_vec();
        let scalar = [232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48].to_vec();

        let proof: ark_groth16::Proof<Bn254> = ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> = ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];


        let mut msm_scalar = scalars.to_vec();
        msm_scalar.reverse();
        let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
        msm_gs.reverse();
        let vky0 = msm_gs.pop().unwrap();
    
        let mut pp3 = vky0 * ark_bn254::Fr::ONE;
        for i in 0..NUM_PUBS {
            pp3 += msm_gs[i] * msm_scalar[i];
        }
        let p3 = pp3.into_affine();
    
        let (p2, p1, p4) = (proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let f_fixed = Bn254::multi_miller_loop_affine([p1], [q1]).0;
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, s) = compute_c_wi(f);
        let eval_ins: InputProof = InputProof {
            p2,
            p4,
            q4,
            c: c.c1/c.c0,
            s: s.c1,
            ks: msm_scalar.clone(),
        };

        let eval_ins_raw = eval_ins.to_raw();
    
        let pubs: PublicParams = PublicParams {
            q2, 
            q3, 
            fixed_acc: f_fixed.c1/f_fixed.c0, 
            ks_vks: msm_gs, 
            vky0
        };
        let mut segments: Vec<Segment> = vec![];
        let pass = groth16_generate_segments(false, &mut segments, eval_ins_raw, pubs, &mut None);
        assert!(pass);
        // hint_to_data(segments.clone());
    }

    // rust version of pairing verification check with normalized (1 + a. J) representation
    fn verify_pairing(ps: Vec<ark_bn254::G1Affine>, qs: Vec<ark_bn254::G2Affine>, gc: ark_bn254::Fq12, s: ark_bn254::Fq12, p1q1: ark_bn254::Fq6) {
        let beta_12x = BigUint::from_str(
            "21575463638280843010398324269430826099269044274347216827212613867836435027261",
        )
        .unwrap();
        let beta_12y = BigUint::from_str(
            "10307601595873709700152284273816112264069230130616436755625194854815875713954",
        )
        .unwrap();
        let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_12x.clone()),
            ark_bn254::Fq::from(beta_12y.clone()),
        ])
        .unwrap();
        let beta_13x = BigUint::from_str(
            "2821565182194536844548159561693502659359617185244120367078079554186484126554",
        )
        .unwrap();
        let beta_13y = BigUint::from_str(
            "3505843767911556378687030309984248845540243509899259641013678093033130930403",
        )
        .unwrap();
        let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_13x.clone()),
            ark_bn254::Fq::from(beta_13y.clone()),
        ])
        .unwrap();
        let beta_22x = BigUint::from_str(
            "21888242871839275220042445260109153167277707414472061641714758635765020556616",
        )
        .unwrap();
        let beta_22y = BigUint::from_str("0").unwrap();
        let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_22x.clone()),
            ark_bn254::Fq::from(beta_22y.clone()),
        ])
        .unwrap();

        let mut cinv = gc.inverse().unwrap();
        cinv = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cinv.c1/cinv.c0);
        let mut c =  gc;
        c = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, c.c1/c.c0);
        
        let mut f = cinv;
        
        let mut ts = qs.clone();
        let ps: Vec<ark_bn254::G1Affine> = ps.iter().map(|p1|ark_bn254::G1Affine::new_unchecked(-p1.x/p1.y, p1.y.inverse().unwrap())).collect();
        let num_pairings = ps.len();
        for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
            // square
            f = f * f;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);


            // double and eval
            for i in 0..num_pairings {
                let t = ts[i];
                let p = ps[i];
                let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
                let neg_bias = alpha * t.x - t.y;
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x);
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y);
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;

                f *= le;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        
                ts[i] = (t + t).into_affine();
            }



            if ate_bit == 1 || ate_bit == -1 {
                let c_or_cinv = if ate_bit == -1 { c } else { cinv };
                f *= c_or_cinv;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

                for i in 0..num_pairings {
                    let t = ts[i];
                    let mut q = qs[i];
                    let p = ps[i];

                    if ate_bit == -1 {
                        q = q.neg();
                    };
                    let alpha = (t.y - q.y) / (t.x - q.x);
                    let neg_bias = alpha * t.x - t.y;
        
                    let mut le0 = alpha;
                    le0.mul_assign_by_fp(&p.x);
                    let mut le1 = neg_bias;
                    le1.mul_assign_by_fp(&p.y);
                    let mut le = ark_bn254::Fq12::ZERO;
                    le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                    le.c1.c0 = le0;
                    le.c1.c1 = le1;
        
                    f *= le;
                    f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

                    ts[i] = (t + q).into_affine();
                }
            }
        }
        let cinv_q = cinv.frobenius_map(1);
        let c_q2 = c.frobenius_map(2);
        let cinv_q3 = cinv.frobenius_map(3);

        for mut cq in vec![cinv_q, c_q2, cinv_q3] {
            cq = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cq.c1/cq.c0); 
            f *= cq;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        }

        f *= s;
        f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];
            
            q.x.conjugate_in_place();
            q.x *= beta_12;
            q.y.conjugate_in_place();
            q.y *= beta_13;
            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;
        
            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        
            ts[i] = (t + q).into_affine();
        }


        // t + q^3
        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q.x *= beta_22;
        
            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;
        
            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
            ts[i] = (t + q).into_affine();
        }
        assert_eq!(f.c1+p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)
    }

    // Pairing verification check with normalized (1 + a. J) representation
    // Includes equivalent bitcoin script in for each functions
    pub fn verify_pairing_scripted(ps: Vec<ark_bn254::G1Affine>, qs: Vec<ark_bn254::G2Affine>, gc: ark_bn254::Fq12, s: ark_bn254::Fq12, p1q1: ark_bn254::Fq6) {
        use crate::chunk::{taps_mul::{chunk_dense_dense_mul, chunk_fq12_square}, taps_point_ops::{chunk_point_ops_and_multiply_line_evals_step_2, chunk_init_t4, get_hint_for_add_with_frob}, taps_ext_miller::chunk_frob_fp12};

        let beta_12x = BigUint::from_str(
            "21575463638280843010398324269430826099269044274347216827212613867836435027261",
        )
        .unwrap();
        let beta_12y = BigUint::from_str(
            "10307601595873709700152284273816112264069230130616436755625194854815875713954",
        )
        .unwrap();
        let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_12x.clone()),
            ark_bn254::Fq::from(beta_12y.clone()),
        ])
        .unwrap();
        let beta_13x = BigUint::from_str(
            "2821565182194536844548159561693502659359617185244120367078079554186484126554",
        )
        .unwrap();
        let beta_13y = BigUint::from_str(
            "3505843767911556378687030309984248845540243509899259641013678093033130930403",
        )
        .unwrap();
        let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_13x.clone()),
            ark_bn254::Fq::from(beta_13y.clone()),
        ])
        .unwrap();
        let beta_22x = BigUint::from_str(
            "21888242871839275220042445260109153167277707414472061641714758635765020556616",
        )
        .unwrap();
        let beta_22y = BigUint::from_str("0").unwrap();
        let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
            ark_bn254::Fq::from(beta_22x.clone()),
            ark_bn254::Fq::from(beta_22y.clone()),
        ])
        .unwrap();

        let mut cinv = gc.inverse().unwrap();
        cinv = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cinv.c1/cinv.c0);
        let mut c =  gc;
        c = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, c.c1/c.c0);
        
        let mut f = cinv;
        let mut g = cinv.c1;
        
        let mut ts = qs.clone();
        let ps: Vec<ark_bn254::G1Affine> = ps.iter().map(|p1|ark_bn254::G1Affine::new_unchecked(-p1.x/p1.y, p1.y.inverse().unwrap())).collect();
        let num_pairings = ps.len();

        let mut total_script_size = 0;
        let mut temp_scr = script!();

        let (mut t4, _, scr, _) = chunk_init_t4([qs[2].x.c0.into(), qs[2].x.c1.into(), qs[2].y.c0.into(), qs[2].y.c1.into()]);
        total_script_size += scr.len();
        let mut t3 = qs[1];
        let mut t2 = qs[0];


        for itr in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let ate_bit = ark_bn254::Config::ATE_LOOP_COUNT[itr - 1];
            println!("itr {} ate_bit {}", itr, ate_bit);
            // square
            f = f * f;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
            (g, _, temp_scr, _) = chunk_fq12_square(g);
            total_script_size += temp_scr.len();

            assert_eq!(g, f.c1);

            // double and eval
            for i in 0..num_pairings {
                let t = ts[i];
                let p = ps[i];
                let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
                let neg_bias = alpha * t.x - t.y;
                let mut le0 = alpha;
                le0.mul_assign_by_fp(&p.x);
                let mut le1 = neg_bias;
                le1.mul_assign_by_fp(&p.y);
                let mut le = ark_bn254::Fq12::ZERO;
                le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                le.c1.c0 = le0;
                le.c1.c1 = le1;

                f *= le;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        
                ts[i] = (t + t).into_affine();
            }
            (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(true, None, None, t4, ps[2], None, ps[1], t3, None, ps[0], t2, None);
            total_script_size += temp_scr.len();

            t3 = (t3 + t3).into_affine();
            t2 = (t2 + t2).into_affine();
            let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
            total_script_size += scr.len();
            (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
            total_script_size += temp_scr.len();

            assert_eq!(g, f.c1);
            

            if ate_bit == 1 || ate_bit == -1 {
                let c_or_cinv = if ate_bit == -1 { c } else { cinv };
                f *= c_or_cinv;
                f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
                (g, _, temp_scr, _) = chunk_dense_dense_mul(g, c_or_cinv.c1);
                total_script_size += temp_scr.len();

                assert_eq!(g, f.c1);

                for i in 0..num_pairings {
                    let t = ts[i];
                    let mut q = qs[i];
                    let p = ps[i];

                    if ate_bit == -1 {
                        q = q.neg();
                    };
                    let alpha = (t.y - q.y) / (t.x - q.x);
                    let neg_bias = alpha * t.x - t.y;
        
                    let mut le0 = alpha;
                    le0.mul_assign_by_fp(&p.x);
                    let mut le1 = neg_bias;
                    le1.mul_assign_by_fp(&p.y);
                    let mut le = ark_bn254::Fq12::ZERO;
                    le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
                    le.c1.c0 = le0;
                    le.c1.c1 = le1;
        
                    f *= le;
                    f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

                    ts[i] = (t + q).into_affine();
                    // println!("pair {:?} ts {:?}", i, ts[i]);
                }

                (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(
                    false, Some(false), Some(ate_bit), 
                    t4, ps[2], Some(qs[2]), 
                    ps[1], t3, Some(qs[1]), 
                    ps[0], t2, Some(qs[0]));
                total_script_size += temp_scr.len();
                
                if ate_bit == 1 {
                    t3 = (t3 + qs[1]).into_affine();
                    t2 = (t2 + qs[0]).into_affine();
                } else {
                    t3 = (t3 + qs[1].neg()).into_affine();
                    t2 = (t2 + qs[0].neg()).into_affine();
                }

                let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
                total_script_size += scr.len();

                (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
                total_script_size += temp_scr.len();
            }
            assert_eq!(g, f.c1);
        }

        let cinv_q = cinv.frobenius_map(1);
        let c_q2 = c.frobenius_map(2);
        let cinv_q3 = cinv.frobenius_map(3);

        let (sc_cinv_q, _, scr, _) = chunk_frob_fp12(cinv.c1, 1);
        total_script_size += scr.len();
        let (sc_c_q2, _, scr, _) = chunk_frob_fp12(c.c1, 2);
        total_script_size += scr.len();
        let (sc_cinv_q3, _, scr, _) = chunk_frob_fp12(cinv.c1, 3);
        total_script_size += scr.len();

        for mut cq in vec![cinv_q, c_q2, cinv_q3] {
            cq = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, cq.c1/cq.c0); 
            f *= cq;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        }
        for sc_cq in vec![sc_cinv_q, sc_c_q2, sc_cinv_q3] {
            (g, _, temp_scr, _) = chunk_dense_dense_mul(g, sc_cq);
            total_script_size += temp_scr.len();
        }
        assert_eq!(g, f.c1);

        f *= s;
        f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        (g, _, temp_scr, _) = chunk_dense_dense_mul(g, s.c1);
        total_script_size += temp_scr.len();
        assert_eq!(g, f.c1);

        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];
            
            q.x.conjugate_in_place();
            q.x *= beta_12;
            q.y.conjugate_in_place();
            q.y *= beta_13;
            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;
        
            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        
            ts[i] = (t + q).into_affine();
        }
        (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(false, Some(true), Some(1), t4, ps[2], Some(qs[2]), ps[1], t3, Some(qs[1]), ps[0], t2, Some(qs[0]));
        total_script_size += temp_scr.len();
        
        let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
        total_script_size += scr.len();

        (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
        total_script_size += temp_scr.len();
        t2 = get_hint_for_add_with_frob(qs[0], t2, 1);
        t3 = get_hint_for_add_with_frob(qs[1], t3, 1);
        assert_eq!(g, f.c1);

        // t + q^3
        for i in 0..num_pairings {
            let mut q = qs[i];
            let t = ts[i];
            let p = ps[i];

            q.x *= beta_22;
        
            let alpha = (t.y - q.y) / (t.x - q.x);
            let neg_bias = alpha * t.x - t.y;
            let mut le0 = alpha;
            le0.mul_assign_by_fp(&p.x);
            let mut le1 = neg_bias;
            le1.mul_assign_by_fp(&p.y);
            let mut le = ark_bn254::Fq12::ZERO;
            le.c0.c0 = ark_bn254::fq2::Fq2::ONE;
            le.c1.c0 = le0;
            le.c1.c1 = le1;
        
            f *= le;
            f = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

            ts[i] = (t + q).into_affine();
        }
        (t4, _, temp_scr, _) = chunk_point_ops_and_multiply_line_evals_step_1(false, Some(true), Some(-1), t4, ps[2], Some(qs[2]), ps[1], t3, Some(qs[1]), ps[0], t2, Some(qs[0]));
        total_script_size += temp_scr.len();

        let (lev, _, scr, _) = chunk_point_ops_and_multiply_line_evals_step_2(t4);
        total_script_size += scr.len();
        
        (g, _, temp_scr, _) = chunk_dense_dense_mul(g, lev);
        total_script_size += temp_scr.len();

        println!("total script size {:?}", total_script_size);
        
        t2 = get_hint_for_add_with_frob(qs[0], t2, -1);
        t3 = get_hint_for_add_with_frob(qs[1], t3, -1);
        assert_eq!(g, f.c1);

        assert_eq!(g+p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)    
        assert_eq!(f.c1+p1q1, ark_bn254::Fq6::ZERO); // final check, f: (a+b == 0 => (1 + a) * (1 + b) == Fq12::ONE)
    }

    #[test]
    fn test_verify_pairing() {
        let vk_bytes = [115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188, 59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161].to_vec();
        let proof_bytes: Vec<u8> = [162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90, 122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218, 218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122, 206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94, 59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226, 132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29, 120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183, 5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63, 133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157, 82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214, 220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255, 188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2, 133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131, 92, 103, 103, 176, 212, 223, 177, 242, 94, 14].to_vec();
        let scalar = [232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48].to_vec();

        let proof: ark_groth16::Proof<Bn254> = ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> = ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        // compute msm
        let mut msm_scalar = scalars.to_vec();
        msm_scalar.reverse();
        let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
        msm_gs.reverse();
        let vky0 = msm_gs.pop().unwrap();
        let mut p3 = vky0 * ark_bn254::Fr::ONE;
        for i in 0..NUM_PUBS {
            p3 += msm_gs[i] * msm_scalar[i];
        }
        let p3 = p3.into_affine();

        let (p2, p1, p4) = (proof.c, vk.alpha_g1, proof.a);
        let (q3, q2, q1, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );

        // precompute c, s
        let mut g = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let fixed_p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;
        let fixed_p1q1 = fixed_p1q1.c1/fixed_p1q1.c0;
        if g.c1 != ark_bn254::Fq6::ZERO {
            g = ark_bn254::Fq12::new( ark_bn254::Fq6::ONE, g.c1/g.c0);
        }
        let (c, wi) = compute_c_wi(g);

        // actual scripted verification
        verify_pairing(vec![p2, p3, p4], vec![q2, q3, q4], c, wi, fixed_p1q1);
        verify_pairing_scripted(vec![p2, p3, p4], vec![q2, q3, q4], c, wi, fixed_p1q1);

    }

    
}