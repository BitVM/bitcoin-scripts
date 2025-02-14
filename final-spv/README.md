# Final SPV
This library contains the necessary functionalities for verifying the header chain of Bitcoin,
proving the inclusion of a Bitcoin transaction in the given header chain, and then compressing
the public values into 32 bytes using `Blake3`.
You need to have `Risc0` toolchain installed to build the ELFs.

## Building
At the root of the repository,
```bash
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK> cargo build -p final-spv-circuit --release
```

The ELF file will be at `prover/elfs/<NETWORK>-final-spv-guest`.