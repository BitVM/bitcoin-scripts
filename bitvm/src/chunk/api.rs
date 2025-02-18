use crate::chunk::api_runtime_utils::{execute_script_from_signature, get_assertion_from_segments, get_assertions_from_signature, get_segments_from_assertion, get_segments_from_groth16_proof};
use crate::chunk::api_compiletime_utils::{ append_bitcom_locking_script_to_partial_scripts, generate_partial_script, partial_scripts_from_segments, NUM_TAPS};

use crate::signatures::wots_api::{wots160, wots256};
use crate::treepp::*;
use ark_bn254::Bn254;
use ark_ec::bn::Bn;


use super::api_compiletime_utils::{NUM_PUBS, NUM_U160, NUM_U256};
use super::api_runtime_utils::{execute_script_from_assertion, get_pubkeys, get_signature_from_assertion};

pub type PublicInputs = [ark_bn254::Fr; NUM_PUBS];

pub type PublicKeys = (
    [wots256::PublicKey; NUM_PUBS],
    [wots256::PublicKey; NUM_U256],
    [wots160::PublicKey; NUM_U160],
);

pub type Signatures = (
    [wots256::Signature; NUM_PUBS],
    [wots256::Signature; NUM_U256],
    [wots160::Signature; NUM_U160],
);

pub type Assertions = (
    [[u8; 32]; NUM_PUBS],
    [[u8; 32]; NUM_U256],
    [[u8; 20]; NUM_U160],
);


// Step 1
// The function takes public parameters (here verifying key) and generates partial script
// partial script is essentially disprove script minus the bitcommitment locking script
pub fn api_generate_partial_script(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<Script> {
    generate_partial_script(vk)
}

// Step 2
// given public keys and the partial scripts generated in api_generate_partial_script()
// it generates the complete disprove scripts
pub fn api_generate_full_tapscripts(
    inpubkeys: PublicKeys,
    ops_scripts_per_link: &[Script],
) -> Vec<Script> {
    println!("api_generate_full_tapscripts; append_bitcom_locking_script_to_partial_scripts");
    let taps_per_link = append_bitcom_locking_script_to_partial_scripts(
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
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    let assts = get_assertion_from_segments(&segments);
    let exec_res = execute_script_from_assertion(&segments, assts);
    if exec_res.is_some() {
        let fault = exec_res.unwrap();
        println!("execute_script_from_assertion return fault at script index {}", fault.0);
        panic!();
    } else {
        println!("generate_assertions; validated assertion by executing all scripts");
    }
    assts
}


// Alternate Step 3
// given public and runtime parameters (proof and scalars) generate Assertions
pub fn generate_signatures(
    proof: ark_groth16::Proof<Bn<ark_bn254::Config>>,
    scalars: Vec<ark_bn254::Fr>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    secret: &str,
) -> Signatures {
    println!("generate_signatures; get_segments_from_groth16_proof");
    let (success, segments) = get_segments_from_groth16_proof(proof, scalars, vk);
    assert!(success);
    println!("generate_signatures; get_assertion_from_segments");
    let assn = get_assertion_from_segments(&segments);
    println!("generate_signatures; get_signature_from_assertion");
    let sigs = get_signature_from_assertion(assn, secret);
    println!("generate_signatures; get_pubkeys");
    let pubkeys = get_pubkeys(secret);

    println!("generate_signatures; partial_scripts_from_segments");
    let partial_scripts: Vec<Script> = partial_scripts_from_segments(&segments).into_iter().collect();
    let partial_scripts: [Script; NUM_TAPS] = partial_scripts.try_into().unwrap();
    println!("generate_signatures; append_bitcom_locking_script_to_partial_scripts");
    let disprove_scripts = append_bitcom_locking_script_to_partial_scripts( pubkeys, partial_scripts.to_vec());
    let disprove_scripts: [Script; NUM_TAPS] = disprove_scripts.try_into().unwrap();

    println!("generate_signatures; execute_script_from_signature");
    let exec_res = execute_script_from_signature(&segments, sigs, &disprove_scripts);
    if exec_res.is_some() {
        let fault = exec_res.unwrap();
        println!("execute_script_from_assertion return fault at script index {}", fault.0);
        panic!();
    } else {
        println!("generate_signatures; validated signatures by executing all scripts");
    }
    sigs
}

// Step 4
// validate signed assertions
// returns index of disprove script generated in Step 2 
// and the witness required to execute this Disprove Script incase of failure
pub fn validate_assertions(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    signed_asserts: Signatures,
    _inpubkeys: PublicKeys,
    disprove_scripts: &[Script; NUM_TAPS],
) -> Option<(usize, Script)> {
    println!("validate_assertions; get_assertions_from_signature");
    let asserts = get_assertions_from_signature(signed_asserts);
    println!("validate_assertions; get_segments_from_assertion");
    let (success, segments) = get_segments_from_assertion(asserts, vk.clone());
    if !success {
        println!("invalid tapscript at segment {}", segments.len());
    }
    println!("validate_assertions; execute_script_from_signature");
    let exec_result = execute_script_from_signature(&segments, signed_asserts, disprove_scripts);
    assert_eq!(success, exec_result.is_none(), "ensure script execution matches rust execution match");
    exec_result
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_serialize::CanonicalDeserialize;
    use bitcoin_script::script;
    use rand::Rng;
    use crate::treepp::Script;

    use crate::{chunk::{api::{api_generate_full_tapscripts, api_generate_partial_script, generate_assertions, generate_signatures, validate_assertions, Assertions}, api_compiletime_utils::{NUM_PUBS, NUM_TAPS, NUM_U160, NUM_U256}, api_runtime_utils::{get_assertions_from_signature, get_pubkeys, get_signature_from_assertion}}, execute_script};


    #[test]
    fn full_e2e_execution() {
        println!("Use mock groth16 proof");
        let vk_bytes = [115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65, 107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76, 241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125, 108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235, 118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155, 121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219, 221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213, 135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224, 98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207, 22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149, 113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239, 96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59, 193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46, 249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176, 96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161, 110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116, 57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99, 132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3, 176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132, 226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78, 41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188, 59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204, 164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0, 0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140, 72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69, 52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214, 99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50, 243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39, 198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7, 84, 59, 151, 47, 178, 165, 112, 251, 161].to_vec();
        let proof_bytes: Vec<u8> = [162, 50, 57, 98, 3, 171, 250, 108, 49, 206, 73, 126, 25, 35, 178, 148, 35, 219, 98, 90, 122, 177, 16, 91, 233, 215, 222, 12, 72, 184, 53, 2, 62, 166, 50, 68, 98, 171, 218, 218, 151, 177, 133, 223, 129, 53, 114, 236, 181, 215, 223, 91, 102, 225, 52, 122, 122, 206, 36, 122, 213, 38, 186, 170, 235, 210, 179, 221, 122, 37, 74, 38, 79, 0, 26, 94, 59, 146, 46, 252, 70, 153, 236, 126, 194, 169, 17, 144, 100, 218, 118, 22, 99, 226, 132, 40, 24, 248, 232, 197, 195, 220, 254, 52, 36, 248, 18, 167, 167, 206, 108, 29, 120, 188, 18, 78, 86, 8, 121, 217, 144, 185, 122, 58, 12, 34, 44, 6, 233, 80, 177, 183, 5, 8, 150, 74, 241, 141, 65, 150, 35, 98, 15, 150, 137, 254, 132, 167, 228, 104, 63, 133, 11, 209, 39, 79, 138, 185, 88, 20, 242, 102, 69, 73, 243, 88, 29, 91, 127, 157, 82, 192, 52, 95, 143, 49, 227, 83, 19, 26, 108, 63, 232, 213, 169, 64, 221, 159, 214, 220, 246, 174, 35, 43, 143, 80, 168, 142, 29, 103, 179, 58, 235, 33, 163, 198, 255, 188, 20, 3, 91, 47, 158, 122, 226, 201, 175, 138, 18, 24, 178, 219, 78, 12, 96, 10, 2, 133, 35, 230, 149, 235, 206, 1, 177, 211, 245, 168, 74, 62, 25, 115, 70, 42, 38, 131, 92, 103, 103, 176, 212, 223, 177, 242, 94, 14].to_vec();
        let scalar = [232, 255, 255, 239, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48].to_vec();


        let proof: ark_groth16::Proof<Bn254> = ark_groth16::Proof::deserialize_uncompressed(&proof_bytes[..]).unwrap();
        let vk: ark_groth16::VerifyingKey<Bn254> = ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).unwrap();
        let scalar: ark_bn254::Fr = ark_bn254::Fr::deserialize_uncompressed(&scalar[..]).unwrap();
        let scalars = [scalar];

        println!("STEP 1 GENERATE TAPSCRIPTS");
        let secret_key: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
        let pubkeys = get_pubkeys(secret_key);

        let partial_scripts = api_generate_partial_script(&vk);
        let disprove_scripts = api_generate_full_tapscripts(pubkeys, &partial_scripts);

        println!("STEP 2 GENERATE SIGNED ASSERTIONS");
        let proof_sigs = generate_signatures(proof, scalars.to_vec(), &vk, secret_key);

        println!("num assertion; 256-bit numbers {}", NUM_PUBS + NUM_U256);
        println!("num assertion; 160-bit numbers {}", NUM_U160);

        println!("STEP 3 CORRUPT AND DISPROVE SIGNED ASSERTIONS");
        let mut proof_asserts = get_assertions_from_signature(proof_sigs);
        corrupt_at_random_index(&mut proof_asserts);
        let corrupt_signed_asserts = get_signature_from_assertion(proof_asserts, secret_key);
        let disprove_scripts: [Script; NUM_TAPS] = disprove_scripts.try_into().unwrap();

        let invalid_tap = validate_assertions(&vk, corrupt_signed_asserts, pubkeys, &disprove_scripts);
        assert!(invalid_tap.is_some());
        let (index, hint_script) = invalid_tap.unwrap();
        println!("STEP 4 EXECUTING DISPROVE SCRIPT at index {}", index);
        let scr = script!(
            {hint_script.clone()}
            {disprove_scripts[index].clone()}
        );
        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            println!("Stack ");
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }

        assert_eq!(res.final_stack.len(), 1);
        assert!(res.success);
        println!("DONE");

        fn corrupt_at_random_index(proof_asserts: &mut Assertions) {
            let mut rng = rand::thread_rng();
            let index = rng.gen_range(0..NUM_PUBS + NUM_U256 + NUM_U160);
            let mut scramble: [u8; 32] = [0u8; 32];
            scramble[16] = 37;
            let mut scramble2: [u8; 20] = [0u8; 20];
            scramble2[10] = 37;
            println!("demo: manually corrupt assertion at index at {:?}", index);
            if index < NUM_PUBS {
                if index == 0 {
                    if proof_asserts.0[0] == scramble {
                        scramble[16] += 1;
                    }
                    proof_asserts.0[0] = scramble;
                } 
            } else if index < NUM_PUBS + NUM_U256 {
                let index = index - NUM_PUBS;
                if proof_asserts.1[index] == scramble {
                    scramble[16] += 1;
                }
                proof_asserts.1[index] = scramble;
            } else if index < NUM_PUBS + NUM_U256+NUM_U160 {
                let index = index - NUM_PUBS - NUM_U256;
                if proof_asserts.2[index] == scramble2 {
                    scramble2[10] += 1;
                }
                proof_asserts.2[index] = scramble2;
            }
        }


    }
}