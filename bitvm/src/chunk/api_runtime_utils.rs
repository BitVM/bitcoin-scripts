use std::ops::Neg;

use ark_bn254::{Bn254};
use ark_ec::bn::Bn;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use bitcoin_script::script;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::chunk::g16_runner_core::groth16_generate_segments;
use crate::chunk::assigner::{InputProof, InputProofRaw, PublicParams};
use crate::chunk::api_compiletime_utils::partial_scripts_from_segments;
use crate::groth16::offchain_checker::compute_c_wi;
use crate::signatures::wots_api::{wots160, wots256, SignatureImpl};
use crate::treepp::Script;

use crate::{bn254::utils::Hint, chunk::{primitives::HashBytes, g16_runner_utils::*}, execute_script};


use super::api::{Assertions, PublicKeys, Signatures};
use super::api_compiletime_utils::NUM_TAPS;
use super::{api_compiletime_utils::{NUM_PUBS, NUM_U160, NUM_U256}, elements::CompressedStateObject, primitives::{ SigData}, wrap_wots::{wots160_sig_to_byte_array, wots256_sig_to_byte_array}};

// Segments are collected in the order [PublicInputSegment, ProofInputSegments, IntermediateHashSegments, FinalScriptSegment]
// mirror of the function get_segments_from_assertion()
pub(crate) fn get_assertion_from_segments(segments: &Vec<Segment>) -> Assertions {
    // extract output {hash or field elements} from all but final script (final script doesn't have output)
    let mut arr_of_output_state: Vec<CompressedStateObject> = vec![];
    for v in segments {
        if v.scr_type.is_final_script() {
            continue;
        }
        let x = v.result.0.to_hash();
        arr_of_output_state.push(x);
    }

    // Serialize and Collect:
    // Segments that were collected in order [PublicInputSegments, ProofInputSegments, IntermediateHashSegment, FinalScriptSegment]
    // are now serialized in the same order and collected as such => [PublicInputAssertion, ProofInputAssertion, IntermediateHashAssertion]
    let mut public_input_assertion_data = vec![];
    for i in 0..NUM_PUBS {
        let val = &arr_of_output_state[i];
        let val: [u8; 32] = val.serialize_to_byte_array().try_into().unwrap();
        public_input_assertion_data.push(val);
    }
    let public_input_assertion_data: [[u8; 32]; NUM_PUBS] = public_input_assertion_data.try_into().unwrap();

    let len = public_input_assertion_data.len();
    let mut proof_input_assertion_data = vec![];
    for i in 0..NUM_U256 {
        let val = &arr_of_output_state[i + len];
        let val: [u8; 32] = val.serialize_to_byte_array().try_into().unwrap();
        proof_input_assertion_data.push(val);
    }
    let proof_input_assertion_data: [[u8; 32]; NUM_U256] = proof_input_assertion_data.try_into().unwrap();

    let len = public_input_assertion_data.len() + proof_input_assertion_data.len();
    let mut intermediate_hash_assertion_data = vec![];
    for i in 0..NUM_U160 {
        let val = &arr_of_output_state[i+len];
        let val: [u8; 20] = val.serialize_to_byte_array().try_into().unwrap();
        intermediate_hash_assertion_data.push(val);
    }
    let batch3: [[u8; 20]; NUM_U160] = intermediate_hash_assertion_data.try_into().unwrap();

    (public_input_assertion_data, proof_input_assertion_data, batch3)
}

// deserialize assertions to CompressedState (i.e. concrete types of bigint and hasbytes) and get proof
fn utils_deserialize_assertions(asserts: Assertions) -> ([CompressedStateObject; NUM_PUBS], [CompressedStateObject; NUM_U256], [CompressedStateObject; NUM_U160]) {
    let mut cobj_pubs = vec![];
    for i in 0..NUM_PUBS {
        let nibs = asserts.0[i].to_vec();
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        cobj_pubs.push(cobj);
    }
    let cobj_pubs: [CompressedStateObject; NUM_PUBS] = cobj_pubs.try_into().unwrap();

    let mut cobj_fqs = vec![];
    for i in 0..NUM_U256 {
        let nibs = asserts.1[i].to_vec();
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        cobj_fqs.push(cobj);
    }
    let cobj_fqs: [CompressedStateObject; NUM_U256] = cobj_fqs.try_into().unwrap();

    let mut cobj_hashes = vec![];
    for i in 0..NUM_U160 {
        let nibs = asserts.2[i].to_vec();
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        cobj_hashes.push(cobj);
    }
    let cobj_hashes: [CompressedStateObject; NUM_U160] = cobj_hashes.try_into().unwrap();

    let cobjs: ([CompressedStateObject; NUM_PUBS], [CompressedStateObject; NUM_U256], [CompressedStateObject; NUM_U160]) = (cobj_pubs, cobj_fqs, cobj_hashes);

    cobjs
}

// mirror of the funtion get_assertion_from_segments
pub(crate) fn get_segments_from_assertion(assertions: Assertions, vk: ark_groth16::VerifyingKey<Bn254>) -> (bool, Vec<Segment>) {

    fn extract_proof_from_assertions(state_pubs: [CompressedStateObject; NUM_PUBS], state_fqs: [CompressedStateObject; NUM_U256]) -> Option<InputProofRaw> { 
        let mut ks: Vec<ark_ff::BigInt<4>> = vec![];
        for i in 0..NUM_PUBS {
            let cobj = &state_pubs[i];
            if let CompressedStateObject::U256(cobj) = cobj {
                ks.push(*cobj);
            } else {
                return None;
            }
        }
        let ks:[ark_ff::BigInt<4>; NUM_PUBS] = ks.try_into().unwrap();
    
        let mut numfqs: Vec<ark_ff::BigInt<4>> = vec![];
        for i in 0..NUM_U256 {
            let cobj = &state_fqs[i];
            if let CompressedStateObject::U256(cobj) = cobj {
                numfqs.push(*cobj);
            } else {
                return None;
            }
        }
        
        let p4 = [numfqs[1], numfqs[0]];
        let p2 = [numfqs[3], numfqs[2]];
        let step = 4;
        let c = [
                numfqs[step], numfqs[step+1],
                numfqs[step+2], numfqs[step+3],
                numfqs[step+4], numfqs[step+5],
        ];       
        let step = step + 6;
        let s = [
            numfqs[step], numfqs[step+1],
            numfqs[step+2], numfqs[step+3],
            numfqs[step+4], numfqs[step+5],
    ];
    
        let step = step + 6;
        let q4 = [
            numfqs[step], numfqs[step+1],
            numfqs[step+2], numfqs[step+3],
        ];
    
        let eval_ins: InputProofRaw = InputProofRaw { p2, p4, q4, c, s, ks };
        Some(eval_ins)
    }

    fn extract_hashes_from_assertions(state_hashes: [CompressedStateObject; NUM_U160]) -> Option<Vec<HashBytes>> { // Intermediates
        let mut hashes: Vec<HashBytes> = vec![];
        for i in 0..NUM_U160 {
            let cobj = &state_hashes[i];
            if let CompressedStateObject::Hash(cobj) = cobj {
                hashes.push(*cobj);
            } else {
                return None;
            }
        }
        hashes.reverse();
        Some(hashes)
    }

    fn extract_public_params(vk: &ark_groth16::VerifyingKey<Bn254>) -> PublicParams {
        let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
        msm_gs.reverse();
        let vky0 = msm_gs.pop().unwrap();
    
        let (q3, q2, q1) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
        );
        let fixed_acc = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;
        
        let pubs: PublicParams = PublicParams { q2, q3, fixed_acc: fixed_acc.c1/fixed_acc.c0, ks_vks: msm_gs.clone(), vky0 };
        pubs
    }
    
    let states = utils_deserialize_assertions(assertions);

    let proof_raw = extract_proof_from_assertions(states.0, states.1);
    let proof_raw = proof_raw.unwrap();
    let pubs = extract_public_params(&vk);
    let intermediates = extract_hashes_from_assertions(states.2);
    let intermediates = intermediates.unwrap();

    let mut segments: Vec<Segment> = vec![];
    let success = groth16_generate_segments(false, &mut segments, proof_raw, pubs, &mut Some(intermediates));
    (success, segments)
}


pub(crate) fn get_segments_from_groth16_proof(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> (bool, Vec<Segment>) {
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
    println!("get_segments_from_groth16_proof; groth16_generate_segments");
    let success = groth16_generate_segments(false, &mut segments, eval_ins.to_raw(), pubs, &mut None);
    (success, segments)    
}

// wots sign byte array using secrets
// mirror of get_assertions_from_signature
pub(crate) fn get_signature_from_assertion(assn: Assertions, secret: &str) -> Signatures {
    println!("get_signature_from_assertion");
    // sign and return Signatures
    let (ps, fs, hs) = (assn.0, assn.1, assn.2);
    
    let mut psig: Vec<wots256::Signature> = vec![];
    for i in 0..NUM_PUBS {
        let psi = wots256::get_signature(&format!("{secret}{:04x}", i), &ps[i]);
        psig.push(psi);
    }
    let psig: [wots256::Signature; NUM_PUBS] = psig.try_into().unwrap();

    let mut fsig: Vec<wots256::Signature> = vec![];
    for i in 0..fs.len() {
        let fsi = wots256::get_signature(&format!("{secret}{:04x}", NUM_PUBS + i), &fs[i]);
        fsig.push(fsi);
    }
    let fsig: [wots256::Signature; NUM_U256] = fsig.try_into().unwrap();

    let mut hsig: Vec<wots160::Signature> = vec![];
    for i in 0..hs.len() {
        let hsi =
            wots160::get_signature(&format!("{secret}{:04x}", NUM_PUBS + fs.len() + i), &hs[i]);
        hsig.push(hsi);
    }
    let hsig: [wots160::Signature; NUM_U160] = hsig.try_into().unwrap();
    
    (psig, fsig, hsig)
}

// decode signature to assertion
// mirror of get_signature_from_assertion
pub(crate) fn get_assertions_from_signature(signed_asserts: Signatures) -> Assertions {
    println!("get_assertions_from_signature");
    let mut ks: Vec<[u8;32]> = vec![];
    for i in 0..NUM_PUBS {
        let nibs = wots256_sig_to_byte_array(signed_asserts.0[i]);
        let nibs:[u8;32] = nibs.try_into().unwrap();
        ks.push(nibs);
    }
    let ks:[[u8;32]; NUM_PUBS] = ks.try_into().unwrap();

    let mut numfqs: Vec<[u8;32]> = vec![];
    for i in 0..NUM_U256 {
        let nibs = wots256_sig_to_byte_array(signed_asserts.1[i]);
        let nibs:[u8;32] = nibs.try_into().unwrap();
        numfqs.push(nibs);
    }
    let num_fqs: [[u8;32]; NUM_U256] = numfqs.try_into().unwrap();

    let mut numhashes: Vec<[u8;20]> = vec![];
    for i in 0..NUM_U160 {
        let nibs = wots160_sig_to_byte_array(signed_asserts.2[i]);
        let nibs: [u8;20] = nibs.try_into().unwrap();
        numhashes.push(nibs);
    }

    let num_hashes: [[u8;20]; NUM_U160] = numhashes.try_into().unwrap();

    let asst: Assertions = (ks, num_fqs, num_hashes);
    asst
}


fn utils_collect_mul_hints_per_segment(segments: &Vec<Segment>) -> Vec<Vec<Hint>> {
    let aux_hints: Vec<Vec<Hint>> = segments.iter().map(|seg| {
        let mut hints = seg.hints.clone();
        // hashing preimage for input
        seg.parameter_ids.iter().rev().for_each(|(param_seg_id, param_seg_type)| {
            let param_seg = &segments[*(param_seg_id) as usize];
            if !param_seg.result.0.output_is_field_element() {
                let preimage_hints = param_seg.result.0.to_witness(*param_seg_type);
                hints.extend_from_slice(&preimage_hints);
            }
        });
        // hashing preimage for output
        if seg.scr_type == ScriptType::FoldedFp12Multiply || seg.scr_type == ScriptType::MillerSquaring || seg.scr_type == ScriptType::MillerPointOpsStep2 {
            hints.extend_from_slice(&seg.result.0.to_witness(seg.result.1));
        }
        hints
    }).collect();
    aux_hints
}

fn utils_execute_chunked_g16(aux_hints: Vec<Vec<Hint>>, bc_hints: Vec<Script>, segments: &Vec<Segment>, disprove_scripts: &[Script; NUM_TAPS]) -> Option<(usize, Script)> {
    let mut tap_script_index = 0;
    for i in 0..aux_hints.len() {
        if segments[i].scr_type == ScriptType::NonDeterministic  {
            continue;
        }
        let hint_script = script!{
            for h in &aux_hints[i] {
                {h.push()}
            }
            {bc_hints[i].clone()}
        };
        let total_script = script!{
            {hint_script.clone()}
            {disprove_scripts[tap_script_index].clone()}
        };
        let exec_result = execute_script(total_script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
        if !exec_result.success {
            if exec_result.final_stack.len() != 1 {
                println!("final {:?}", i);
                println!("final {:?}", segments[i].scr_type);
                assert!(false);
            }
        } else {
            println!("disprove script {}: tapindex {}, {:?}",i,tap_script_index, segments[i].scr_type);
            let disprove_hint = (
                tap_script_index,
                hint_script,
            );
            return Some(disprove_hint);
        }
        tap_script_index += 1;
    }
    None
}

pub(crate) fn execute_script_from_assertion(segments: &Vec<Segment>, assts: Assertions) -> Option<(usize, Script)> {

    // if there is partial disprove script; with no locking script; i can directly push hashes
    // segments and assertions
    fn collect_wots_msg_as_witness_per_segment(segments: &Vec<Segment>, assts: Assertions) -> Vec<Script> {
        let bitcom_msg = utils_deserialize_assertions(assts);
        let mut bitcom_msg_arr = vec![];
        bitcom_msg_arr.extend_from_slice(&bitcom_msg.0);
        bitcom_msg_arr.extend_from_slice(&bitcom_msg.1);
        bitcom_msg_arr.extend_from_slice(&bitcom_msg.2);

        let mut all_bc_hints = vec![];
        for i in 0..segments.len() {
            let mut index_of_bitcommitted_msg: Vec<u32> = vec![];

            let seg = &segments[i];

            // final script doesn't have output
            if !seg.scr_type.is_final_script() {
                let sec_out = (seg.id, segments[seg.id as usize].result.0.output_is_field_element());
                index_of_bitcommitted_msg.push(sec_out.0);
            }

            let sec_in: Vec<u32> = seg.parameter_ids.iter().map(|(k, _)| {*k}).collect();
            index_of_bitcommitted_msg.extend_from_slice(&sec_in);
            // index_of_bitcom_msg => [output, inputn-1, ..input0]

            let mut bc_hint = script!();
            for skey in index_of_bitcommitted_msg {
                let bcelem = bitcom_msg_arr[skey as usize].clone();
                let h = bcelem.as_hint_type();
                bc_hint = script!(
                    {bc_hint}
                    {h.push()}
                    {Fq::toaltstack()}
                ); // Altstack: [outputhash, inputN-1Hash, ..., input0Hash]
            }  

            all_bc_hints.push(bc_hint);
        }
        all_bc_hints
    }

    // collect partial scripts
    let partial_scripts: Vec<Script> = partial_scripts_from_segments(segments).into_iter().collect();
    let partial_scripts: [Script; NUM_TAPS] = partial_scripts.try_into().unwrap();
    // collect witness
    let mul_hints = utils_collect_mul_hints_per_segment(segments);
    let bc_hints = collect_wots_msg_as_witness_per_segment(segments, assts);
    
    // execute_chunked_g16
    utils_execute_chunked_g16(mul_hints, bc_hints, segments, &partial_scripts)
}

pub(crate) fn execute_script_from_signature(segments: &Vec<Segment>, signed_assts: Signatures, disprove_scripts: &[Script; NUM_TAPS]) -> Option<(usize, Script)> {
    
    // if there is a disprove script; with locking script; i can use bitcom witness
    // segments and signatures
    fn collect_wots_sig_as_witness_per_segment(segments: &Vec<Segment>, signed_asserts: Signatures) -> Vec<Script> {
        let scalar_sigs: Vec<SigData> = signed_asserts.0.iter().map(|f| SigData::Sig256(*f)).collect();
        let felts_sigs: Vec<SigData> = signed_asserts.1.iter().map(|f| SigData::Sig256(*f)).collect();
        let hash_sigs: Vec<SigData> = signed_asserts.2.iter().map(|f| SigData::Sig160(*f)).collect();
        let mut bitcom_sig_arr = vec![];
        bitcom_sig_arr.extend_from_slice(&scalar_sigs);
        bitcom_sig_arr.extend_from_slice(&felts_sigs);
        bitcom_sig_arr.extend_from_slice(&hash_sigs);


        let mut bitcom_sig_as_witness = vec![];

        for i in 0..segments.len() {
            let mut index_of_bitcommitted_msg: Vec<u32> = vec![];

            let seg = &segments[i];
            let sec_in: Vec<u32> = seg.parameter_ids.iter().rev().map(|(k, _)| {*k}).collect();
            index_of_bitcommitted_msg.extend_from_slice(&sec_in);

            if !seg.scr_type.is_final_script() { // final script doesn't have output
                let sec_out = (seg.id, segments[seg.id as usize].result.0.output_is_field_element());
                index_of_bitcommitted_msg.push(sec_out.0);
            }

            let mut sig_preimages = script!();
            for index in index_of_bitcommitted_msg {
                let sig_data = &bitcom_sig_arr[index as usize];
                let sig_preimage = match sig_data {
                    SigData::Sig160(signature) => signature.to_compact_script(),
                    SigData::Sig256(signature) => signature.to_compact_script(),
                };
                sig_preimages = script!(
                    {sig_preimages}
                    {sig_preimage}
                );
            }
            bitcom_sig_as_witness.push(sig_preimages);
        }
        bitcom_sig_as_witness
    }


    // collect witness
    let mul_hints = utils_collect_mul_hints_per_segment(segments);
    let bc_hints = collect_wots_sig_as_witness_per_segment(segments, signed_assts);
    
    // execute_chunked_g16
    utils_execute_chunked_g16(mul_hints, bc_hints, segments, disprove_scripts)
}

pub(crate) fn get_pubkeys(secret_key: &str) -> PublicKeys {

    let mut pubins = vec![];
    for i in 0..NUM_PUBS {
        pubins.push(wots256::generate_public_key(&format!("{secret_key}{:04x}", i)));
    }
    let mut fq_arr = vec![];
    for i in 0..NUM_U256 {
        let p256 = wots256::generate_public_key(&format!("{secret_key}{:04x}", NUM_PUBS + i));
        fq_arr.push(p256);
    }
    let mut h_arr = vec![];
    for i in 0..NUM_U160 {
        let p160 = wots160::generate_public_key(&format!("{secret_key}{:04x}", NUM_U256 + NUM_PUBS + i));
        h_arr.push(p160);
    }
    let wotspubkey: PublicKeys = (
        pubins.try_into().unwrap(),
        fq_arr.try_into().unwrap(),
        h_arr.try_into().unwrap(),
    );
    wotspubkey
}


#[cfg(test)]
mod test {
    use ark_serialize::CanonicalDeserialize;
    use crate::chunk::api_compiletime_utils::append_bitcom_locking_script_to_partial_scripts;

    use super::*;

    #[test]
    fn test_runtime_execution_looped() {
        let vk_bytes = [115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188, 59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161].to_vec();
        let proof_bytes: Vec<u8> = [162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90, 122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218, 218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122, 206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94, 59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226, 132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29, 120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183, 5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63, 133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157, 82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214, 220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255, 188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2, 133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131, 92, 103, 103, 176, 212, 223, 177, 242, 94, 14].to_vec();
        let scalar = [232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48].to_vec();


        println!("Preparing Input");
        let proof: ark_groth16::Proof<Bn254> = ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> = ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        // generate segments
        println!("get_segments_from_groth16_proof");
        let (success, segments) = get_segments_from_groth16_proof(proof, scalars.to_vec(), &vk);
        assert!(success);

        // segments to assertion
        println!("get_assertion_from_segments");
        let assts = get_assertion_from_segments(&segments);
        println!("execute_script_from_assertion");
        let res = execute_script_from_assertion(&segments, assts);
        assert!(res.is_none());

        println!("get_segments_from_assertion");
        let (success, new_segments) = get_segments_from_assertion(assts, vk);
        assert!(success);
        println!("again get_assertion_from_segments");
        let new_assts = get_assertion_from_segments(&new_segments);
        println!("again execute_script_from_assertion");
        let res = execute_script_from_assertion(&new_segments, new_assts);
        assert!(res.is_none());

        println!("ensure reruns match");
        assert_eq!(assts, new_assts);


        // get_sig from assts
        const MOCK_SECRET: &str = "a238982ce17ac813d505a5b40b665d404e9528e7";
        println!("get_signature_from_assertion");
        let signed_assts = get_signature_from_assertion(assts, MOCK_SECRET);
        println!("get_assertions_from_signature");
        let new_assts = get_assertions_from_signature(signed_assts);
        assert_eq!(assts, new_assts);


        println!("get_pubkeys");
        let pubkeys = get_pubkeys(MOCK_SECRET);
        println!("execute_script_from_signature");
        let partial_scripts: Vec<Script> = partial_scripts_from_segments(&segments).into_iter().collect();
        let disprove_scripts = append_bitcom_locking_script_to_partial_scripts( pubkeys, partial_scripts.to_vec());
        let disprove_scripts: [Script; NUM_TAPS] = disprove_scripts.try_into().unwrap();

        let res = execute_script_from_signature(&segments, signed_assts, &disprove_scripts);
        assert!(res.is_none());
        println!("finished test");
    }
}