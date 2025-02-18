
use std::collections::HashMap;
use std::str::FromStr;

use ark_bn254::Bn254;
use ark_ec::bn::BnConfig;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use bitcoin_script::script;
use num_bigint::BigUint;
use treepp::Script;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Neg;

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::chunk::elements::ElementType;
use crate::{treepp};

use super::api::PublicKeys;
use super::assigner::{InputProof, PublicParams};
use super::wrap_hasher::hash_messages;
use super::wrap_wots::checksig_verify_to_limbs;
use super::{g16_runner_core::{groth16_generate_segments}, g16_runner_utils::{ScriptType, Segment}, wrap_wots::WOTSPubKey};

pub const ATE_LOOP_COUNT: &[i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 20;
pub const NUM_U160: usize = 380;
const VALIDATING_TAPS: usize = 1;
const HASHING_TAPS: usize = NUM_U160;
pub const NUM_TAPS: usize = HASHING_TAPS + VALIDATING_TAPS; 

pub(crate) struct Vkey {
    pub(crate) q2: ark_bn254::G2Affine,
    pub(crate) q3: ark_bn254::G2Affine,
    pub(crate) p3vk: Vec<ark_bn254::G1Affine>,
    pub(crate) p1q1: ark_bn254::Fq12,
    pub(crate) vky0: ark_bn254::G1Affine,
}

pub(crate) fn generate_partial_script(
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Vec<bitcoin_script::Script>  {
    println!("generate_partial_script");
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
    
    let vk = Vkey {
        q2,
        q3,
        p3vk,
        p1q1,
        vky0,
    };


    println!("generate_partial_script; generate_segments_using_mock_proof");
    let segments = generate_segments_using_mock_proof(vk, false);
    println!("generate_partial_script; partial_scripts_from_segments");
    let op_scripts: Vec<Script> = partial_scripts_from_segments(&segments).into_iter().collect();
    assert_eq!(op_scripts.len(), NUM_TAPS);
    op_scripts
}


// we can use mock_vk and mock_proof here because generating bitcommitments only requires knowledge
// of how the chunks are connected and the public keys to generate locking_script
// we do not need values at the input or outputs of tapscript
pub(crate) fn append_bitcom_locking_script_to_partial_scripts(
    inpubkeys: PublicKeys,
    ops_scripts: Vec<bitcoin_script::Script>,
) ->  Vec<bitcoin_script::Script> {
    println!("append_bitcom_locking_script_to_partial_scripts; generage_segments_using_mock_vk_and_mock_proof");
    // mock_vk can be used because generating locking_script doesn't depend upon values or partial scripts; it's only a function of pubkey and ordering of input/outputs
    let mock_segments = generage_segments_using_mock_vk_and_mock_proof();

    println!("append_bitcom_locking_script_to_partial_scripts; bitcom_scripts_from_segments");
    let bitcom_scripts: Vec<treepp::Script> = bitcom_scripts_from_segments(&mock_segments, inpubkeys).into_iter().filter(|f| f.len() > 0).collect();
    assert_eq!(ops_scripts.len(), bitcom_scripts.len());
    let res: Vec<treepp::Script>  = ops_scripts.into_iter().zip(bitcom_scripts).map(|(op_scr, bit_scr)| 
        script!(
            {bit_scr}
            {op_scr}
        )   
    ).collect();

    res
}

fn generate_segments_using_mock_proof(vk: Vkey, skip_evaluation: bool) -> Vec<Segment> {
    // values known only at runtime, can be mocked
    let q4xc0: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("18327300221956260726652878806040774028373651771658608258634994907375058801387").unwrap());
    let q4xc1: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("2791853351403597124265928925229664715548948431563105825401192338793643440152").unwrap());
    let q4yc0: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("9203020065248672543175273161372438565462224153828027408202959864555260432617").unwrap());
    let q4yc1: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("21242559583226289516723159151189961292041850314492937202099045542257932723954").unwrap());
    let tx = ark_bn254::Fq2::new(q4xc0, q4xc1);
    let ty =  ark_bn254::Fq2::new(q4yc0, q4yc1);
    let t2 = ark_bn254::G2Affine::new(tx, ty);

    let g1x: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("5567084537907487155917146166615783238769284480674905823618779044732684151587").unwrap());
    let g1y: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("6500138522353517220105129525103627482682148482121078429366182801568786680416").unwrap());
    let t1 = ark_bn254::G1Affine::new(g1x, g1y);

    let mut segments: Vec<Segment> = vec![];
    let g1 = t1;
    let g2 = t2;
    let fr : ark_ff::BigInt<4> = ark_ff::BigInt::from(1u64);
    let s = ark_bn254::Fq6::ONE;
    let c = ark_bn254::Fq6::ONE;
    let mocked_eval_ins: InputProof = InputProof { p2: g1, p4: g1, q4: g2, c, s, ks: vec![fr.into()] };

    // public values known at compile time
    let pubs: PublicParams = PublicParams { q2: vk.q2, q3: vk.q3, fixed_acc: vk.p1q1.c1/vk.p1q1.c0, ks_vks: vk.p3vk, vky0: vk.vky0 };
    groth16_generate_segments(skip_evaluation, &mut segments, mocked_eval_ins.to_raw(), pubs, &mut None);
    segments
}

fn generage_segments_using_mock_vk_and_mock_proof() -> Vec<Segment> {
    let mock_vk = Vkey {
        q2: ark_bn254::G2Affine::identity(),
        q3: ark_bn254::G2Affine::identity(),
        p3vk: (0..NUM_PUBS).map(|_| ark_bn254::G1Affine::identity()).collect(),
        p1q1: ark_bn254::Fq12::ONE,
        vky0: ark_bn254::G1Affine::identity(),
    };
    generate_segments_using_mock_proof(mock_vk, true)
}

pub(crate) fn partial_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {
   fn serialize_element_types(elems: &[ElementType]) -> String {
        // 1. Convert each variant to its string representation.
        let joined = elems
            .iter()
            .map(|elem| format!("{:?}", elem)) // uses #[derive(Debug)]
            .collect::<Vec<String>>()
            .join("_");
    
        // 2. Compute a simple 64-bit hash of that string
        let mut hasher = DefaultHasher::new();
        joined.hash(&mut hasher);
        let unique_hash = hasher.finish();
    
        // 3. Concatenate final result as "ENUM1-ENUM2-ENUM3|hash"
        format!("{}|{}", joined, unique_hash)
    }

    let mut op_scripts: Vec<treepp::Script> = vec![];

    // cache hashing script as it is repititive
    let mut hashing_script_cache: HashMap<String, Script> = HashMap::new();
    for s in segments {
        if s.scr_type.is_final_script() || s.scr_type == ScriptType::NonDeterministic {
            continue;
        }
        let mut elem_types_to_hash: Vec<ElementType> = s.parameter_ids.iter().rev().map(|f| f.1).collect();
        elem_types_to_hash.push(s.result.1);
        let elem_types_str_as_key = serialize_element_types(&elem_types_to_hash);
        hashing_script_cache.entry(elem_types_str_as_key).or_insert_with(|| {
            let hash_scr = script!(
                {hash_messages(elem_types_to_hash)}
                OP_TRUE
            );
            hash_scr
        });
    };

    for i in 0..segments.len() {
        let seg= &segments[i];
        let scr_type = seg.scr_type.clone();
        if scr_type == ScriptType::NonDeterministic {
            continue;
        }

        let op_scr  = seg.scr.clone();

        if seg.scr_type.is_final_script() { // validating segments do not have output hash, so don't add hashing layer; they are self sufficient
            op_scripts.push(op_scr);
        } else {

            // fetch hashing script from cache for these element types
            let mut elem_types_to_hash: Vec<ElementType> = seg.parameter_ids.iter().rev().map(|(_, param_seg_type)| *param_seg_type).collect();
            elem_types_to_hash.push(seg.result.1);
            let elem_types_str = serialize_element_types(&elem_types_to_hash);
            let hash_scr = hashing_script_cache.get(&elem_types_str).unwrap();

            op_scripts.push(script!(
                {op_scr}
                {hash_scr.clone()}
            ));
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, wots_pubkeys: PublicKeys) -> Vec<treepp::Script> {
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];

    let mut pubkeys_arr = vec![];
    pubkeys_arr.extend_from_slice(&wots_pubkeys.0.iter().map(|f| WOTSPubKey::P256(*f)).collect::<Vec<WOTSPubKey>>());
    pubkeys_arr.extend_from_slice(&wots_pubkeys.1.iter().map(|f| WOTSPubKey::P256(*f)).collect::<Vec<WOTSPubKey>>());
    pubkeys_arr.extend_from_slice(&wots_pubkeys.2.iter().map(|f| WOTSPubKey::P160(*f)).collect::<Vec<WOTSPubKey>>());

    for seg in segments {
        if seg.scr_type == ScriptType::NonDeterministic {
            continue;
        }

        let mut index_of_bitcommitted_msg = vec![];
        if !seg.scr_type.is_final_script() {
            index_of_bitcommitted_msg.push(seg.id);
        };
        let sec_in: Vec<u32> = seg.parameter_ids.iter().map(|(f, _)| *f).collect();
        index_of_bitcommitted_msg.extend_from_slice(&sec_in);

        let mut locking_scr = script!();
        for index in index_of_bitcommitted_msg {
            locking_scr = script!(
                {locking_scr}
                {checksig_verify_to_limbs(&pubkeys_arr[index as usize])}
                {Fq::toaltstack()}
            );
        }
        bitcom_scripts.push(locking_scr);

    }
    bitcom_scripts
}
