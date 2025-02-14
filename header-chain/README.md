# Header Chain Library
This library contains the necessary functionalities for proving the header chain of Bitcoin.
You need to have `Risc0` toolchain installed to build the ELFs.

## Building
At the root of the repository,
```bash
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK> cargo build -p header-chain-circuit --release
```

The ELF file will be at `prover/elfs/<NETWORK>-header-chain-guest`.
