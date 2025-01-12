use crate::{constants::NUM_BLOCKS_PER_2_WEEKS, utils::num_blocks_per_network};
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf, TxIn, XOnlyPublicKey,
};
use bitvm::treepp::script;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorZ {
    pub network: Network,
    pub depositor_taproot_public_key: XOnlyPublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
    pub evm_address: String,
    pub num_blocks_timelock_0: u32,
}

impl ConnectorZ {
    pub fn new(
        network: Network,
        evm_address: &str,
        depositor_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
    ) -> Self {
        ConnectorZ {
            network,
            depositor_taproot_public_key: *depositor_taproot_public_key,
            n_of_n_taproot_public_key: *n_of_n_taproot_public_key,
            evm_address: evm_address.to_string(),
            num_blocks_timelock_0: num_blocks_per_network(network, NUM_BLOCKS_PER_2_WEEKS),
        }
    }

    fn generate_taproot_leaf_0_script(&self) -> ScriptBuf {
        generate_timelock_taproot_script(
            &self.depositor_taproot_public_key,
            self.num_blocks_timelock_0,
        )
    }

    fn generate_taproot_leaf_0_tx_in(&self, input: &Input) -> TxIn {
        generate_timelock_tx_in(input, self.num_blocks_timelock_0)
    }

    // leaf[1] is spendable by a multisig of depositor and OPK and VPK[1…N]
    // the transaction script contains an [evm_address] (inscription data)
    fn generate_taproot_leaf_1_script(&self) -> ScriptBuf {
        script! {
        OP_FALSE
        OP_IF
        { self.evm_address.clone().into_bytes() }
        OP_ENDIF
        { self.n_of_n_taproot_public_key }
        OP_CHECKSIGVERIFY
        { self.depositor_taproot_public_key }
        OP_CHECKSIG
        }
        .compile()
    }

    fn generate_taproot_leaf_1_tx_in(&self, input: &Input) -> TxIn { generate_default_tx_in(input) }
}

impl TaprootConnector for ConnectorZ {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_script(),
            1 => self.generate_taproot_leaf_1_script(),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        match leaf_index {
            0 => self.generate_taproot_leaf_0_tx_in(input),
            1 => self.generate_taproot_leaf_1_tx_in(input),
            _ => panic!("Invalid leaf index."),
        }
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.generate_taproot_leaf_0_script())
            .expect("Unable to add leaf 0")
            .add_leaf(1, self.generate_taproot_leaf_1_script())
            .expect("Unable to add leaf 1")
            .finalize(SECP256K1, self.depositor_taproot_public_key) // TODO: should this be depositor or n-of-n
            .expect("Unable to finalize ttaproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
