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
            2270796390, 1182871638, 1279521157, 536004066, 1441889709, 2101052289, 2939847752,
            613044085,
        ],
        Some(network) if matches!(network.as_bytes(), b"testnet4") => [
            810594638, 3428391573, 2402727861, 2747549677, 2885659487, 2080306410, 795554066,
            964841963,
        ],
        Some(network) if matches!(network.as_bytes(), b"signet") => [
            328960562, 2543785274, 2711600643, 3544131166, 687804847, 1385553050, 2938303965,
            2265052206,
        ],
        Some(network) if matches!(network.as_bytes(), b"regtest") => [
            3856118450, 1566698315, 1094137686, 449376115, 2427890433, 3495936576, 155530056,
            1772143032,
        ],
        None => [
            2270796390, 1182871638, 1279521157, 536004066, 1441889709, 2101052289, 2939847752,
            613044085,
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
