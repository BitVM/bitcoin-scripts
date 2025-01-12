use std::collections::HashMap;

use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitcoin_script::script;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::{
    graphs::peg_out::CommitmentMessageId,
    superblock::{SUPERBLOCK_HASH_MESSAGE_LENGTH, SUPERBLOCK_MESSAGE_LENGTH},
};

use bitvm::signatures::signing_winternitz::{
    winternitz_message_checksig_verify, WinternitzPublicKey,
};

use super::{
    super::{
        constants::{NUM_BLOCKS_PER_2_WEEKS, NUM_BLOCKS_PER_6_HOURS, NUM_BLOCKS_PER_DAY},
        scripts::*,
        transactions::base::Input,
        utils::num_blocks_per_network,
    },
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Connector1 {
    pub network: Network,
    pub operator_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub commitment_public_keys: HashMap<CommitmentMessageId, WinternitzPublicKey>,
    pub num_blocks_timelock_leaf_0: u32,
    pub num_blocks_timelock_leaf_1: u32,
    pub num_blocks_timelock_leaf_2: u32,
}

impl Connector1 {
    pub fn new(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        Connector1 {
            network,
            operator_taproot_public_key: *operator_taproot_public_key,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
            num_blocks_timelock_leaf_0: num_blocks_per_network(network, NUM_BLOCKS_PER_2_WEEKS),
            num_blocks_timelock_leaf_1: num_blocks_per_network(
                network,
                NUM_BLOCKS_PER_2_WEEKS + NUM_BLOCKS_PER_DAY,
            ),
            num_blocks_timelock_leaf_2: num_blocks_per_network(network, NUM_BLOCKS_PER_6_HOURS),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        let superblock_public_key = &self.commitment_public_keys[&CommitmentMessageId::Superblock];
        let superblock_hash_public_key =
            &self.commitment_public_keys[&CommitmentMessageId::SuperblockHash];

        script! {
            { winternitz_message_checksig_verify(superblock_hash_public_key, SUPERBLOCK_HASH_MESSAGE_LENGTH * 2) }
            { winternitz_message_checksig_verify(superblock_public_key, SUPERBLOCK_MESSAGE_LENGTH * 2) }
            { self.num_blocks_timelock_leaf_0 }
            OP_CSV
            OP_DROP
            { self.operator_taproot_public_key }
            OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock_leaf_0)
    }

    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.num_blocks_timelock_leaf_1,
        )
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock_leaf_1)
    }

    fn generate_taproot_leaf_2_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.n_of_n_taproot_public_key,
            self.num_blocks_timelock_leaf_2,
        )
    }

    fn generate_taproot_leaf_2_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock_leaf_2)
    }
}

impl TaprootConnector for Connector1 {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            2 => self.generate_taproot_leaf_2_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            2 => self.generate_taproot_leaf_2_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(2, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(2, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .add_leaf(1, self.generate_taproot_leaf_2_script())
            .expect("Unable to add leaf 2")
            .finalize(SECP256K1, self.n_of_n_taproot_public_key)
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
