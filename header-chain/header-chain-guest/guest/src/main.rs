#![no_main]
header_chain::risc0_zkvm::guest::entry!(main);
fn main() {
    let zkvm_guest = header_chain::zkvm::Risc0Guest::new();
    header_chain::header_chain_circuit(&zkvm_guest);
}