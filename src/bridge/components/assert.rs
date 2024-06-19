use crate::treepp::*;
use bitcoin::{absolute, Amount, Sequence, Transaction, TxIn, TxOut, Witness};

use super::super::context::BridgeContext;
use super::super::graph::{DUST_AMOUNT, FEE_AMOUNT};

use super::bridge::*;
use super::connector_b::ConnectorB;
use super::helper::*;

pub struct AssertTransaction {
    tx: Transaction,
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<Script>,
}

impl AssertTransaction {
    pub fn new(context: &BridgeContext, input0: Input) -> Self {
        let n_of_n_public_key = context
            .n_of_n_public_key
            .expect("n_of_n_public_key is required in context");

        let n_of_n_taproot_public_key = context
            .n_of_n_taproot_public_key
            .expect("n_of_n_taproot_public_key is required in context");

        let _input0 = TxIn {
            previous_output: input0.outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let total_input_amount = input0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: generate_timelock_script_address(&n_of_n_public_key, 2).script_pubkey(),
        };

        let _output1 = TxOut {
            value: total_input_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: super::connector_c::generate_taproot_pre_sign_address(
                &n_of_n_taproot_public_key,
            )
            .script_pubkey(),
        };

        let _output2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: super::connector_c::generate_taproot_address(&n_of_n_taproot_public_key)
                .script_pubkey(),
        };

        let connector_b = ConnectorB::new(&n_of_n_taproot_public_key, NUM_BLOCKS_PER_WEEK * 4);

        AssertTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input0],
                output: vec![_output0, _output1, _output2],
            },
            prev_outs: vec![TxOut {
                value: input0.amount,
                script_pubkey: connector_b.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_b.generate_taproot_leaf1()],
        }
    }
}

impl BridgeTransaction for AssertTransaction {
    fn pre_sign(&mut self, context: &BridgeContext) {
        todo!();
    }

    fn finalize(&self, context: &BridgeContext) -> Transaction {
        todo!()
    }
}
