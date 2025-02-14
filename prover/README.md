# Header Chain Prover
## Build and Use
Download the Bitcoin headers and rename it to "mainnet-headers.bin":
```sh
cd prover/data
wget https://zerosync.org/chaindata/headers.bin -O mainnet-headers.bin
cd ../..
```
Install Risc0 toolchain, see [here](https://dev.risczero.com/api/zkvm/install).

To build the prover,
```sh
BITCOIN_NETWORK=<NETWORK> cargo build -p prover --release
```

To prove,
```bash
./target/release/prover None prover/data/first_10.bin 10
```

- The first argument is the previous proof file path (`None` if starting from genesis).
- The second argument is the output proof file path.
- The third argument is the number of headers to prove.

Example: To verify the previous proof and prove the next 90 Bitcoin headers, run the following command:

```bash
./target/release/prover prover/data/first_10.bin prover/data/first_100.bin 90
```

