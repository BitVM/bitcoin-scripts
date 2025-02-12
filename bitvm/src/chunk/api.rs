use std::ops::Neg;

use crate::chunk::assert::groth16_generate_segments;
use crate::chunk::assigner::{collect_assertions_from_wots_signature, collect_raw_assertion_data_from_segments, extract_proof_from_assertions, extract_public_params, get_intermediate_hashes, InputProof, PublicParams};
use crate::chunk::compile::{ append_bitcom_locking_script_to_partial_scripts, generate_partial_script, Vkey, NUM_PUBS};
use crate::chunk::segment::Segment;
use crate::groth16::g16::{
    Assertions, PublicKeys, Signatures, N_TAPLEAVES
};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;

use super::assert::script_exec;


// Step 1
// The function takes public parameters (here verifying key) and generates partial script
// partial script is essentially disprove script minus the bitcommitment locking script
pub fn api_generate_partial_script(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    assert!(vk.gamma_abc_g1.len() == NUM_PUBS + 1); // supports only 3 pubs

    let p1 = vk.alpha_g1;
    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );

    let p1q1 = Bn254::multi_miller_loop_affine([p1], [q1]).0;
    let mut p3vk = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    p3vk.reverse();
    let vky0 = p3vk.pop().unwrap();

    generate_partial_script(
        Vkey {
            q2,
            q3,
            p3vk,
            p1q1,
            vky0,
        },
    )
}

// Step 2
// given public keys and the partial scripts generated in api_generate_partial_script()
// it generates the complete disprove scripts
pub fn api_generate_full_tapscripts(
    inpubkeys: PublicKeys,
    ops_scripts_per_link: &[Script],
) -> Vec<Script> {

    let taps_per_link = append_bitcom_locking_script_to_partial_scripts(
        Vkey {
            q2: ark_bn254::G2Affine::identity(),
            q3: ark_bn254::G2Affine::identity(),
            p3vk: (0..NUM_PUBS).map(|_| ark_bn254::G1Affine::identity()).collect(),
            p1q1: ark_bn254::Fq12::ONE,
            vky0: ark_bn254::G1Affine::identity(),
        },
        inpubkeys,
        ops_scripts_per_link.to_vec(),
    );
    assert_eq!(ops_scripts_per_link.len(), taps_per_link.len());
    taps_per_link
}

// Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_assertions(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Assertions {
    assert_eq!(scalars.len(), NUM_PUBS);

    let mut msm_scalar = scalars.clone();
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

    let pubs: PublicParams = PublicParams {
        q2, 
        q3, 
        fixed_acc: f_fixed.c1/f_fixed.c0, 
        ks_vks: msm_gs, 
        vky0
    };

    let mut segments: Vec<Segment> = vec![];
    println!("generating assertions as prover");
    let success = groth16_generate_segments(false, &mut segments, eval_ins.to_raw(), pubs, &mut None);
    println!("segments len {}", segments.len());
    assert!(success);
    
    collect_raw_assertion_data_from_segments(segments)
}

// Step 4
// validate signed assertions
// returns index of disprove script generated in Step 2 
// and the witness required to execute this Disprove Script incase of failure
pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    _inpubkeys: PublicKeys,
    disprove_scripts: &[Script; N_TAPLEAVES],
) -> Option<(usize, Script)> {
    let asserts = collect_assertions_from_wots_signature(signed_asserts);
    let eval_ins = extract_proof_from_assertions(&asserts);
    let intermediates = get_intermediate_hashes(&asserts);

    let mut segments: Vec<Segment> = vec![];
    println!("generating assertions to validate");
    let passed = groth16_generate_segments(false, &mut segments, eval_ins, extract_public_params(vk), &mut Some(intermediates));
    if passed {
        println!("assertion passed, running full script execution now");
        let exec_result = script_exec(segments, signed_asserts, disprove_scripts);
        //assert!(exec_result.is_none());
        return exec_result;
    }
    println!("assertion failed, return faulty script segments acc {:?} at {:?}", segments.len(), segments[segments.len()-1].scr_type);
    let exec_result = script_exec(segments, signed_asserts, disprove_scripts);
    assert!(exec_result.is_some());
    exec_result
}

