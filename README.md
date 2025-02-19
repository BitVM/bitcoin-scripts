# BitVM Bridge: A Trust-minimized Bitcoin Bridge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> [!WARNING]
> DO NOT USE IN PRODUCTION!

The official implementation of [BitVM2](https://bitvm.org/bitvm2),
running a [SNARK verifier](https://bitvm.org/snark).

The code follows the implementation of [Arkworks](https://github.com/arkworks-rs)

## Overview

The repository contains the implementation of a groth16 SNARK verifier that is executable via the optimistic BitVM paradigm on Bitcoin without any soft forks.


It is designed to be modular, allowing developers to reuse bitcoin scripts for u32 data types, hashes and curve operations.

## Components

BitVM is composed of several components.
Below is a list of the components and their purpose.

- [**`u32` Operations**](bitvm/src/u32/):
  Basic arithmetic operations of `u32` for hash functions,
  including `add`, `sub`, `or`, `xor`, `rotation`, `shift`.

- [**`u4` Operations**](bitvm/src/u4):
  `u4` version arithmetic operations,
  providing a more efficient way to construct hashes.

- [**Hash Functions**](bitvm/src/hash/):
  Two types of hash functions:

  - `SHA256`: comparing block headers and measuring Bitcoin difficulty.
  - `BLAKE3`: compressing intermediate states in the chunker.

- [**Big Integer**](bitvm/src/bigint/):
  Variable-length big integer operations,
  including of `add`, `sub`, `mul`, `div`, `inverse` and other operations.

- [**BN254**](bitvm/src/bn254/):
  Point expression of BN254 elliptic curves and operations based on BN254,
  including addition, multiplication, pairing.
  The pairing part is related to the "Algorithm 9" in the paper "On Proving Pairings"

- [**Groth16**](bitvm/src/groth16/):
  Groth16 uses BN254 to verify proof, the script is currently around 1 GB.
  Some hints are precomputed in this part, which is related to the paper "On Proving Pairings".

- [**Chunker**](bitvm/src/chunker/):
  Splits Groth16 into chunks.
  These chunks make sure two principles:

  1. Any chunks shouldn't be success with a right proof.
  2. There are always some successful chunks with a wrong proof.

- [**Signatures**](bitvm/src/signatures/):
  Bit commitment using
  [Winternitz signature](https://en.wikipedia.org/wiki/Lamport_signature#Short_keys_and_signature).

- [**Bridge**](bridge/):
  Definitions for the context (roles), connectors, Bitcoin transaction construction,
  Bitcoin client wrapper, etc.

## BitVM1

If you are looking for the deprectated BitVM1 implementation, please check out
[BitVM1](https://github.com/BitVM/BitVM/tree/1dce989d1963b90c35391b77b451c6823302d503).


## BitVM CLI

### Overview

The **BitVM CLI** is a command-line interface for interacting with the BitVM protocol, enabling users to manage Bitcoin keys, initiate peg-ins, retrieve addresses and UTXOs, and monitor the status of transactions within the BitVM network. 

This CLI supports multiple Bitcoin network environments, including `mainnet` and `testnet`.

### Features

- **Manage Bitcoin Keys**: Easily manage keys for different roles (depositor, operator, verifier, withdrawer).
- **Retrieve Depositor Address**: Get the address associated with the registered depositor key.
- **Retrieve Depositor UTXOs**: List unspent transaction outputs (UTXOs) for the depositor.
- **Initiate Peg-Ins**: Start the process of peg-ins by creating peg-in graphs.
- **Broadcast Transactions**: Send various types of transactions related to peg-ins and peg-outs.
- **Interactive Mode**: Use an interactive command-line interface for manual command issuance and management.

## Requirements

- Rust programming language (latest stable version)
- Cargo (Rust package manager)

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```
2. **Build the Project**:
   ```bash
   cargo build --release
   ```
3. **Run the Application**:
   ```bash
   ./target/release/bridge
   ```

## Usage

The BitVM CLI application can be invoked with various commands. The general syntax is:

```
./target/release/bridge [OPTIONS] <SUBCOMMAND>
```

### Global Options

- -r, --verifiers <VERIFIER_PUBKEYS>: Optional; Comma-separated list of public keys for verifiers (max: 1000). Can also be set via the VERIFIERS environment variable.
- -e, --environment <ENVIRONMENT>: Specify the Bitcoin network environment (mainnet, testnet). Defaults to testnet. Can also be set via the ENVIRONMENT environment variable.
- --key-dir <DIRECTORY>: Directory containing the private keys. Can also be set via the KEY_DIR environment variable.

### Available Commands

#### Keys Management:

1. Description: Manage secret keys for different contexts (depositor, operator, verifier, withdrawer).
2. Usage:
```bash
./target/release/bridge keys [OPTIONS]
```

3. Options:
- -d, --depositor <SECRET_KEY>: Secret key for the depositor.
- -o, --operator <SECRET_KEY>: Secret key for the operator.
- -v, --verifier <SECRET_KEY>: Secret key for the verifier.
- -w, --withdrawer <SECRET_KEY>: Secret key for the withdrawer.

#### Get Depositor Address:
1. Description: Retrieve the address spendable by the registered depositor key.
2. Usage:
```bash
./target/release/bridge get-depositor-address
```

#### Get Depositor UTXOs:
1. Description: Retrieve a list of the depositor's UTXOs.
2. Usage:
```bash
./target/release/bridge get-depositor-utxos
```

#### Initiate Peg-In:
1. Description: Start the peg-in process by creating a peg-in graph.
2. Usage:
```bash
./target/release/bridge initiate-peg-in --utxo <TXID>:<VOUT> --destination_address <EVM_ADDRESS>
```

#### Broadcast Transactions:
1. Description: Send various types of transactions related to peg-ins and peg-outs.
2. Usage:
```bash
./target/release/bridge broadcast [COMMAND] [OPTIONS]
```

#### Automatic Mode:
1. Description: Enable automatic mode to poll for status updates and handle transactions.
2. Usage:
```bash
./target/release/bridge automatic
```

#### Interactive Mode:
1. Description: Enter into an interactive command prompt for manual command execution.
2. Usage:
```bash
./target/release/bridge interactive
```

#### Show Status:
1. Description: Display the current status of the BitVM client.
2. Usage:
```bash
./target/release/bridge status
```

### Environment Variables

You can set the following environment variables to configure the CLI:

#### General Environment Variables

- BRIDGE_DATA_STORE_CLIENT_DATA_SUFFIX : Specifies the suffix for the bridge client data file. Default value is "bridge-client-data.json".
- BRIDGE_AWS_ACCESS_KEY_ID : Your AWS access key ID for authenticating with AWS services. Required if using AWS for storage.
- BRIDGE_AWS_SECRET_ACCESS_KEY : Your AWS secret access key for authenticating with AWS services. Required if using AWS for storage.
- BRIDGE_AWS_REGION : The AWS region where your storage bucket is located. Required if using AWS for storage.
- BRIDGE_AWS_BUCKET : The name of the S3 bucket where files will be stored. Required if using AWS for storage.

- KEY_DIR: Directory containing private keys.
- VERIFIERS: Comma-separated list of public keys for verifiers.
- ENVIRONMENT: Bitcoin network environment (default: mainnet).

#### FTP/SFTP Environment Variables

- BRIDGE_SFTP_HOST : Hostname or IP address of the SFTP server for secure file transfers.
- BRIDGE_SFTP_PORT : Port number for the SFTP connection. Default is 22.
- BRIDGE_SFTP_USERNAME : Username for authenticating to the SFTP server.
- BRIDGE_SFTP_KEYFILE_PATH : Path to the private key file used for authenticating to the SFTP server.
BRIDGE_SFTP_BASE_PATH : Base path on the SFTP server where BitVM data will be stored. Default is /bitvm.
- BRIDGE_FTP_HOST : Hostname or IP address of the FTP server for file transfers.
- BRIDGE_FTP_PORT : Port number for the FTP connection. Default is 21.
- BRIDGE_FTP_USERNAME : Username for authenticating to the FTP server.
- BRIDGE_FTP_PASSWORD : Password for authenticating to the FTP server.
- BRIDGE_FTP_BASE_PATH : Base path on the FTP server where BitVM data will be stored. Default is /bitvm.
- BRIDGE_FTPS_HOST : Hostname or IP address of the FTPS server for secure file transfers over FTP.
- BRIDGE_FTPS_PORT : Port number for the FTPS connection. Default is 21.
- BRIDGE_FTPS_USERNAME : Username for authenticating to the FTPS server.
- BRIDGE_FTPS_PASSWORD : Password for authenticating to the FTPS server.
- BRIDGE_FTPS_BASE_PATH : Base path on the FTPS server where BitVM data will be stored. Default is /bitvm.

### Configuration File
The BitVM Bridge CLI uses a configuration file (bridge.toml) located in the specified key directory (default: `~/.bitvm-bridge/`). This file is used to store the keys for the depositor, operator, verifier, and withdrawer.
