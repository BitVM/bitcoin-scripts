
use std::collections::HashMap;
use std::str::FromStr;

use ark_ec::bn::BnConfig;
use ark_ff::Field;
use bitcoin_script::script;
use num_bigint::BigUint;
use treepp::Script;
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::chunk::elements::ElementType;
use crate::groth16::g16::{PublicKeys, N_TAPLEAVES};
use crate::{treepp};

use super::assigner::{InputProof, PublicParams};
use super::blake3compiled::hash_messages;
use super::{assert::{groth16_generate_segments}, primitives::gen_bitcom, segment::{ScriptType, Segment}, wots::WOTSPubKey};

pub const ATE_LOOP_COUNT: &[i8] = ark_bn254::Config::ATE_LOOP_COUNT;
pub const NUM_PUBS: usize = 1;
pub const NUM_U256: usize = 20;
pub const NUM_U160: usize = 380;
const VALIDATING_TAPS: usize = 7;
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
    vk: Vkey,
) -> Vec<bitcoin_script::Script>  {
    println!("generate_segments_using_mock_proof");
    let mock_segments = generate_segments_using_mock_proof(vk, false);
    println!("partial_scripts_from_segments");
    let op_scripts: Vec<Script> = partial_scripts_from_segments(&mock_segments).into_iter().collect();
    assert_eq!(op_scripts.len(), N_TAPLEAVES);
    op_scripts
}

// we can use mock_vk and mock_proof here because generating bitcommitments only requires knowledge
// of how the chunks are connected and the public keys to generate locking_script
// we do not need values at the input or outputs of tapscript
pub(crate) fn append_bitcom_locking_script_to_partial_scripts(
    mock_vk: Vkey,
    inpubkeys: PublicKeys,
    ops_scripts: Vec<bitcoin_script::Script>,
) ->  Vec<bitcoin_script::Script> {
    let mock_segments = generate_segments_using_mock_proof(mock_vk, true);

    let mut scalar_pubkeys = inpubkeys.0.to_vec();
    scalar_pubkeys.reverse();
    let mut felts_pubkeys = inpubkeys.1.to_vec();
    felts_pubkeys.reverse();
    let mut hash_pubkeys = inpubkeys.2.to_vec();
    hash_pubkeys.reverse();
    let mock_felt_pub = inpubkeys.0[0];

    let mut pubkeys: HashMap<u32, WOTSPubKey> = HashMap::new();
    for si  in 0..mock_segments.len() {
        let s = &mock_segments[si];
        if s.is_validation {
            let mock_fld_pub_key = WOTSPubKey::P256(mock_felt_pub);
            pubkeys.insert(si as u32, mock_fld_pub_key);
        } else if s.result.1 == ElementType::FieldElem {
            pubkeys.insert(si as u32, WOTSPubKey::P256(felts_pubkeys.pop().unwrap()));
        } else if s.result.1 == ElementType::ScalarElem {
            pubkeys.insert(si as u32, WOTSPubKey::P256(scalar_pubkeys.pop().unwrap()));
        } else {
            pubkeys.insert(si as u32, WOTSPubKey::P160(hash_pubkeys.pop().unwrap()));
        }
    }

    let bitcom_scripts: Vec<treepp::Script> = bitcom_scripts_from_segments(&mock_segments, pubkeys).into_iter().filter(|f| f.len() > 0).collect();
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

pub(crate) fn partial_scripts_from_segments(segments: &Vec<Segment>) -> Vec<treepp::Script> {
   fn serialize_element_types(elems: &[ElementType]) -> String {
        // 1. Convert each variant to its string representation.
        let joined = elems
            .iter()
            .map(|elem| format!("{:?}", elem)) // uses #[derive(Debug)]
            .collect::<Vec<String>>()
            .join("-");
    
        // 2. Compute a simple 64-bit hash of that string
        let mut hasher = DefaultHasher::new();
        joined.hash(&mut hasher);
        let unique_hash = hasher.finish();
    
        // 3. Concatenate final result as "ENUM1-ENUM2-ENUM3|hash"
        format!("{}|{}", joined, unique_hash)
    }


    let mut op_scripts: Vec<treepp::Script> = vec![];

    let mut hashing_script_cache: HashMap<String, Script> = HashMap::new();
    for s in segments {
        if s.is_validation || s.scr_type == ScriptType::NonDeterministic {
            continue;
        }
        let mut elem_types_to_hash: Vec<ElementType> = s.parameter_ids.iter().rev().map(|f| f.1).collect();
        elem_types_to_hash.push(s.result.1);
        let elem_types_str = serialize_element_types(&elem_types_to_hash);
        hashing_script_cache.entry(elem_types_str).or_insert_with(|| {
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

        if seg.is_validation { // validating segments do not have output hash, so don't add hashing layer; they are self sufficient
            op_scripts.push(op_scr);
        } else {
            let mut elem_types_to_hash: Vec<ElementType> = seg.parameter_ids.iter().rev().map(|(_, param_seg_type)| *param_seg_type).collect();
            elem_types_to_hash.push(seg.result.1);
            let elem_types_str = serialize_element_types(&elem_types_to_hash);
            let hash_scr = hashing_script_cache.get(&elem_types_str).unwrap();
            assert!(hash_scr.len() > 0);
            op_scripts.push(script!(
                {op_scr}
                {hash_scr.clone()}
            ));
        }
    }
    op_scripts
}

pub(crate) fn bitcom_scripts_from_segments(segments: &Vec<Segment>, pubkeys_map: HashMap<u32, WOTSPubKey>) -> Vec<treepp::Script> {
    let mut bitcom_scripts: Vec<treepp::Script> = vec![];
    for seg in segments {
        let mut sec = vec![];
        if !seg.is_validation {
            sec.push((seg.id, segments[seg.id as usize].result.0.output_is_field_element()));
        };
        let sec_in: Vec<(u32, bool)> = seg.parameter_ids.iter().map(|(f, _)| {
            let elem = &segments[*(f) as usize];
            let elem_type = elem.result.0.output_is_field_element();
            (*f, elem_type)
        }).collect();
        sec.extend_from_slice(&sec_in);
        match seg.scr_type {
            ScriptType::NonDeterministic => {
                bitcom_scripts.push(script!());
            },
            _ => {
                bitcom_scripts.push(gen_bitcom(&pubkeys_map, sec));
            }
        }
    }
    bitcom_scripts
}
