#![no_main]
final_spv::risc0_zkvm::guest::entry!(main);
fn main() {
    let zkvm_guest = final_spv::zkvm::Risc0Guest::new();
    final_spv::final_circuit(&zkvm_guest);
}