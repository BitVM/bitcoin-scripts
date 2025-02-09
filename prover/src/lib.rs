use borsh::BorshDeserialize;
use header_chain::{
    header_chain::{
        BlockHeaderCircuitOutput, CircuitBlockHeader, HeaderChainCircuitInput,
        HeaderChainPrevProofType,
    },
    risc0_zkvm::{default_prover, ExecutorEnv},
};

use risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID;
use risc0_zkvm::{compute_image_id, sha::Digestible};
use risc0_zkvm::{ProverOpts, Receipt, SuccinctReceiptVerifierParameters, SystemState};
use sha2::Digest;
use sha2::Sha256;
use std::{env, fs};

pub mod docker;

const HEADER_CHAIN_GUEST_ELF: &[u8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            include_bytes!("../elfs/mainnet-header-chain-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            include_bytes!("../elfs/testnet4-header-chain-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            include_bytes!("../elfs/signet-header-chain-guest")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            include_bytes!("../elfs/regtest-header-chain-guest")
        }
        None => include_bytes!("../elfs/mainnet-header-chain-guest"),
        _ => panic!("Invalid path or ELF file"),
    }
};

const HEADERS: &[u8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => {
            include_bytes!("../data/mainnet-headers.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"testnet4") => {
            include_bytes!("../data/testnet4-headers.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"signet") => {
            include_bytes!("../data/signet-headers.bin")
        }
        Some(network) if matches!(network.as_bytes(), b"regtest") => {
            include_bytes!("../data/regtest-headers.bin")
        }
        None => include_bytes!("../data/mainnet-headers.bin"),
        _ => panic!("Invalid network type"),
    }
};

pub fn prove() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: <program> <input_proof> <output_file_path> <batch_size>");
        return;
    }

    let input_proof = &args[1];
    let output_file_path = &args[2];
    let batch_size: usize = args[3].parse().expect("Batch size should be a number");

    let headers = HEADERS
        .chunks(80)
        .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
        .collect::<Vec<CircuitBlockHeader>>();

    let HEADER_CHAIN_GUEST_ID: [u32; 8] = compute_image_id(HEADER_CHAIN_GUEST_ELF)
        .unwrap()
        .as_words()
        .try_into()
        .unwrap();

    // Set the previous proof type based on input_proof argument
    let prev_receipt = if input_proof.to_lowercase() == "none" {
        None
    } else {
        let proof_bytes = fs::read(input_proof).expect("Failed to read input proof file");
        let receipt: Receipt = Receipt::try_from_slice(&proof_bytes).unwrap();
        Some(receipt)
    };

    let mut start = 0;
    let prev_proof = match prev_receipt.clone() {
        Some(receipt) => {
            let output =
                BlockHeaderCircuitOutput::try_from_slice(&receipt.journal.bytes.clone()).unwrap();
            start = output.chain_state.block_height as usize + 1;
            HeaderChainPrevProofType::PrevProof(output)
        }
        None => HeaderChainPrevProofType::GenesisBlock,
    };

    // Prepare the input for the circuit
    let input = HeaderChainCircuitInput {
        method_id: HEADER_CHAIN_GUEST_ID,
        prev_proof,
        block_headers: headers[start..start + batch_size].to_vec(),
    };

    // Build ENV
    let mut binding = ExecutorEnv::builder();
    let mut env = binding.write_slice(&borsh::to_vec(&input).unwrap());
    if let Some(receipt) = prev_receipt {
        env = env.add_assumption(receipt);
    }
    let env = env.build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover
        .prove_with_opts(env, HEADER_CHAIN_GUEST_ELF, &ProverOpts::succinct())
        .unwrap()
        .receipt;

    // Extract journal of receipt
    let output = BlockHeaderCircuitOutput::try_from_slice(&receipt.journal.bytes).unwrap();

    println!("Output: {:#?}", output.method_id);

    // Save the receipt to the specified output file path
    let receipt_bytes = borsh::to_vec(&receipt).unwrap();
    fs::write(output_file_path, &receipt_bytes).expect("Failed to write receipt to output file");
    println!("Receipt saved to {}", output_file_path);
}

/// Sha256(control_root, pre_state_digest, post_state_digest, id_bn254_fr)
pub fn calculate_succinct_output_prefix(method_id: &[u8]) -> [u8; 32] {
    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    let succinct_control_root = succinct_verifier_params.control_root;
    let mut succinct_control_root_bytes: [u8; 32] =
        succinct_control_root.as_bytes().try_into().unwrap();
    for byte in succinct_control_root_bytes.iter_mut() {
        *byte = byte.reverse_bits();
    }
    let pre_state_bytes = method_id.to_vec();
    let control_id_bytes: [u8; 32] = BN254_IDENTITY_CONTROL_ID.into();

    // Expected post state for an execution that halted successfully
    let post_state: SystemState = risc0_binfmt::SystemState {
        pc: 0,
        merkle_root: risc0_zkp::core::digest::Digest::default(),
    };
    let post_state_bytes: [u8; 32] = post_state.digest().into();

    let mut hasher = Sha256::new();
    hasher.update(&succinct_control_root_bytes);
    hasher.update(&pre_state_bytes);
    hasher.update(&post_state_bytes);
    hasher.update(&control_id_bytes);
    let result: [u8; 32] = hasher
        .finalize()
        .try_into()
        .expect("SHA256 should produce a 32-byte output");

    result
}

fn reverse_bits_and_copy(input: &[u8], output: &mut [u8]) {
    for i in 0..8 {
        let temp = u32::from_be_bytes(input[4 * i..4 * i + 4].try_into().unwrap()).reverse_bits();
        output[4 * i..4 * i + 4].copy_from_slice(&temp.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {

    use docker::stark_to_succinct;
    use final_spv::{
        final_circuit::FinalCircuitInput, merkle_tree::BitcoinMerkleTree, spv::SPV,
        transaction::CircuitTransaction,
    };
    use header_chain::mmr_native::MMRNative;
    use hex_literal::hex;
    use risc0_zkvm::compute_image_id;

    const MAINNET_BLOCK_HASHES: [[u8; 32]; 11] = [
        hex!("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"),
        hex!("4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000"),
        hex!("bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a00000000"),
        hex!("4944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b58200000000"),
        hex!("85144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000"),
        hex!("fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000"),
        hex!("8d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a0313000000000"),
        hex!("4494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000"),
        hex!("c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000"),
        hex!("0508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000"),
        hex!("e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c00000000"),
    ];

    use super::*;
    // #[ignore = "This is to only test final proof generation"]
    /// Run this test only when build for the mainnet
    #[test]
    fn test_final_circuit() {
        let final_circuit_elf = include_bytes!("../elfs/final-spv-guest");
        let header_chain_circuit_elf = include_bytes!("../elfs/mainnet-header-chain-guest");
        println!(
            "Header chain circuit id: {:#?}",
            compute_image_id(header_chain_circuit_elf)
                .unwrap()
                .as_words()
        );
        let final_proof = include_bytes!("../data/first_10.bin");
        let final_circuit_id = compute_image_id(final_circuit_elf).unwrap();

        let receipt: Receipt = Receipt::try_from_slice(final_proof).unwrap();

        let mut mmr_native = MMRNative::new();
        for block_hash in MAINNET_BLOCK_HASHES.iter() {
            mmr_native.append(*block_hash);
        }

        let output = BlockHeaderCircuitOutput::try_from_slice(&receipt.journal.bytes).unwrap();
        let tx: CircuitTransaction = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap()).unwrap());
        let block_header: CircuitBlockHeader = CircuitBlockHeader::try_from_slice(hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap().as_slice()).unwrap();
        let bitcoin_merkle_tree: BitcoinMerkleTree = BitcoinMerkleTree::new(vec![tx.txid()]);
        let bitcoin_inclusion_proof = bitcoin_merkle_tree.generate_proof(0);
        let (_, mmr_inclusion_proof) = mmr_native.generate_proof(0);
        let spv: SPV = SPV::new(
            tx,
            bitcoin_inclusion_proof,
            block_header,
            mmr_inclusion_proof,
        );
        let final_circuit_input: FinalCircuitInput = FinalCircuitInput {
            block_header_circuit_output: output,
            spv: spv,
        };
        let env = ExecutorEnv::builder()
            .write_slice(&borsh::to_vec(&final_circuit_input).unwrap())
            .add_assumption(receipt)
            .build()
            .unwrap();

        let prover = default_prover();

        let receipt = prover
            .prove_with_opts(env, final_circuit_elf, &ProverOpts::succinct())
            .unwrap()
            .receipt;

        let succinct_receipt = receipt.inner.succinct().unwrap().clone();
        let receipt_claim = succinct_receipt.clone().claim;
        println!("Receipt claim: {:#?}", receipt_claim);
        // let journal: [u8; 32] = receipt.journal.bytes.clone().try_into().unwrap();
        // let (proof, output_json_bytes) =
        //     stark_to_succinct(succinct_receipt, &receipt.journal.bytes);
        // print!("Proof: {:#?}", proof);
        // let constants_digest = calculate_succinct_output_prefix(final_circuit_id.as_bytes());
        // println!("Constants digest: {:#?}", constants_digest);
        // println!("Journal: {:#?}", receipt.journal);
        // let mut constants_blake3_input = [0u8; 32];
        // let mut journal_blake3_input = [0u8; 32];

        // reverse_bits_and_copy(&constants_digest, &mut constants_blake3_input);
        // reverse_bits_and_copy(&journal, &mut journal_blake3_input);
        // let mut hasher = blake3::Hasher::new();
        // hasher.update(&constants_blake3_input);
        // hasher.update(&journal_blake3_input);
        // let final_output = hasher.finalize();
        // let final_output_bytes: [u8; 32] = final_output.try_into().unwrap();
        // let final_output_trimmed: [u8; 31] = final_output_bytes[..31].try_into().unwrap();
        // assert_eq!(final_output_trimmed, output_json_bytes);
    }
}
