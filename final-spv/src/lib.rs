use final_circuit::FinalCircuitInput;
use risc0_zkvm::guest::env;
use zkvm::ZkvmGuest;

pub mod final_circuit;
pub mod merkle_tree;
pub mod spv;
pub mod transaction;
pub mod utils;
pub mod zkvm;
pub use risc0_zkvm;

/// The method ID for the header chain circuit.
const HEADER_CHAIN_GUEST_ID: [u32; 8] = {
    match option_env!("BITCOIN_NETWORK") {
        Some(network) if matches!(network.as_bytes(), b"mainnet") => [
            768536068, 2727401796, 106262116, 4126899915, 3657723419, 937893488, 1320702396,
            741759054,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            697144841, 1975658746, 502088199, 1528242910, 2219927211, 3007897287, 670689013,
            1003162707,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            2429117237, 3252745227, 1101335279, 2980039782, 522565757, 1958690289, 1247735107,
            3854206245,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            141372475, 2811869749, 2297818804, 992041055, 3878854789, 3740048630, 1587608976,
            3369201583,
        ],
        None => [
            768536068, 2727401796, 106262116, 4126899915, 3657723419, 937893488, 1320702396,
            741759054,
        ],
        _ => panic!("Invalid network type"),
    }
};

/// The final circuit that verifies the output of the header chain circuit.
pub fn final_circuit(guest: &impl ZkvmGuest) {
    let start = env::cycle_count();
    let input: FinalCircuitInput = guest.read_from_host::<FinalCircuitInput>();
    guest.verify(HEADER_CHAIN_GUEST_ID, &input.block_header_circuit_output);
    input.spv.verify(
        input
            .block_header_circuit_output
            .chain_state
            .block_hashes_mmr,
    );
    let mut hasher = blake3::Hasher::new();

    hasher.update(&input.spv.transaction.txid());
    hasher.update(
        &input
            .block_header_circuit_output
            .chain_state
            .best_block_hash,
    );
    hasher.update(&input.block_header_circuit_output.chain_state.total_work);
    let final_output = hasher.finalize();
    guest.commit(final_output.as_bytes());
    let end = env::cycle_count();
    println!("Final circuit took {:?} cycles", end - start);
}