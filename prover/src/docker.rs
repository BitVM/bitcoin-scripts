use hex::ToHex;
use num_bigint::BigUint;
use num_traits::Num;
use risc0_groth16::{to_json, ProofJson, Seal};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    sha::Digest, ReceiptClaim, SuccinctReceipt, SuccinctReceiptVerifierParameters, SystemState,
};
use serde_json::Value;
use std::{
    env::consts::ARCH,
    fs,
    path::Path,
    process::{Command, Stdio},
};

use tempfile::tempdir;

pub fn stark_to_succinct(
    succinct_receipt: SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> (Seal, [u8; 31]) {
    let ident_receipt = risc0_zkvm::recursion::identity_p254(&succinct_receipt).unwrap();
    let identity_p254_seal_bytes = ident_receipt.get_seal_bytes();
    let receipt_claim = succinct_receipt.claim.value().unwrap();

    // This part is from risc0-groth16
    if !is_x86_architecture() {
        panic!("stark_to_snark is only supported on x86 architecture.")
    }
    if !is_docker_installed() {
        panic!("Please install docker first.")
    }

    let tmp_dir = tempdir().unwrap();
    let work_dir = std::env::var("RISC0_WORK_DIR");
    let work_dir = work_dir.as_ref().map(Path::new).unwrap_or(tmp_dir.path());
    println!("work_dir: {:?}", work_dir);
    std::fs::write(work_dir.join("seal.r0"), identity_p254_seal_bytes.clone()).unwrap();
    let seal_path = work_dir.join("input.json");
    let proof_path = work_dir.join("proof.json");
    let output_path = work_dir.join("public.json");
    let mut seal_json = Vec::new();
    to_json(&*identity_p254_seal_bytes, &mut seal_json).unwrap();
    std::fs::write(seal_path.clone(), seal_json).unwrap();

    let pre_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().pre;
    println!("pre_state: {:?}", pre_state);
    let pre_state_digest: Digest = pre_state.clone().digest();
    println!("pre_state_digest: {:?}", pre_state_digest);
    let pre_state_digest_bits: Vec<String> = pre_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    println!("pre_state_digest_bits: {:?}", pre_state_digest_bits);
    let post_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().post;
    println!("post_state: {:?}", post_state);
    let post_state_digest: Digest = post_state.clone().digest();
    let post_state_digest_bits: Vec<String> = post_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    println!("post_state_digest_bits: {:?}", post_state_digest_bits);

    let mut journal_bits = Vec::new();
    for byte in journal {
        for i in 0..8 {
            journal_bits.push((byte >> (7 - i)) & 1);
        }
    }
    println!("journal_bits len: {:?}", journal_bits.len());

    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    println!("Succinct verifier params: {:?}", succinct_verifier_params);
    let succinct_control_root = succinct_verifier_params.control_root;
    println!("Succinct control root: {:?}", succinct_control_root);
    let mut succinct_control_root_bytes: [u8; 32] =
        succinct_control_root.as_bytes().try_into().unwrap();
    succinct_control_root_bytes.reverse();
    let succinct_control_root_bytes: String = succinct_control_root_bytes.encode_hex();
    let a1_str = succinct_control_root_bytes[0..32].to_string();
    let a0_str = succinct_control_root_bytes[32..64].to_string();
    println!("Succinct control root a0: {:?}", a0_str);
    println!("Succinct control root a1: {:?}", a1_str);
    let a0_dec = to_decimal(&a0_str).unwrap();
    let a1_dec = to_decimal(&a1_str).unwrap();
    println!("Succinct control root a0 dec: {:?}", a0_dec);
    println!("Succinct control root a1 dec: {:?}", a1_dec);
    println!("CONTROL_ID: {:?}", ident_receipt.control_id);
    let id_bn254_fr_bits: Vec<String> = ident_receipt
        .control_id
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    println!("id_bn254_fr_bits: {:?}", id_bn254_fr_bits);

    let mut seal_json: Value = {
        let file_content = fs::read_to_string(&seal_path).unwrap();
        serde_json::from_str(&file_content).unwrap()
    };

    seal_json["journal_digest_bits"] = journal_bits.into();
    seal_json["pre_state_digest_bits"] = pre_state_digest_bits.into();
    seal_json["post_state_digest_bits"] = post_state_digest_bits.into();
    seal_json["id_bn254_fr_bits"] = id_bn254_fr_bits.into();
    seal_json["control_root"] = vec![a0_dec, a1_dec].into();
    std::fs::write(seal_path, serde_json::to_string_pretty(&seal_json).unwrap()).unwrap();

    let output = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
        .arg("risc0-groth16-prover")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    println!("Output: {:?}", output);

    if !output.status.success() {
        eprintln!(
            "docker returned failure exit code: {:?}",
            output.status.code()
        );
    }
    println!("proof_path: {:?}", proof_path);
    let proof_content = std::fs::read_to_string(proof_path).unwrap();
    let output_content_dec = std::fs::read_to_string(output_path).unwrap();
    let proof_json: ProofJson = serde_json::from_str(&proof_content).unwrap();
    // let output_json: Value = serde_json::from_str(&output_content).unwrap();
    // Convert output_content_dec from decimal to hex
    let parsed_json: Value = serde_json::from_str(&output_content_dec).unwrap();
    let output_str = parsed_json[0].as_str().unwrap(); // Extracts the string from the JSON array

    // Step 2: Convert the decimal string to BigUint and then to hexadecimal
    let output_content_hex = BigUint::from_str_radix(output_str, 10)
        .unwrap()
        .to_str_radix(16);

    // If the length of the hexadecimal string is odd, add a leading zero
    let output_content_hex = if output_content_hex.len() % 2 == 0 {
        output_content_hex
    } else {
        format!("0{}", output_content_hex)
    };

    // Step 3: Decode the hexadecimal string to a byte vector
    let output_byte_vec = hex::decode(&output_content_hex).unwrap();
    // let output_byte_vec = hex::decode(output_hex).unwrap();
    let output_bytes: [u8; 31] = output_byte_vec.as_slice().try_into().unwrap();
    (proof_json.try_into().unwrap(), output_bytes)
}

fn is_docker_installed() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn is_x86_architecture() -> bool {
    ARCH == "x86_64" || ARCH == "x86"
}

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}
