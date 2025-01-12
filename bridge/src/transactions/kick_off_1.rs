use bitcoin::{
    absolute, consensus, Amount, Network, ScriptBuf, TapSighashType, Transaction, TxOut,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{
            base::*, connector_1::Connector1, connector_2::Connector2, connector_6::Connector6,
            connector_a::ConnectorA,
        },
        contexts::operator::OperatorContext,
        graphs::base::{DUST_AMOUNT, FEE_AMOUNT, MESSAGE_COMMITMENT_FEE_AMOUNT},
    },
    base::*,
    pre_signed::*,
    signing::{generate_taproot_leaf_schnorr_signature, populate_taproot_input_witness},
};
use bitvm::signatures::signing_winternitz::{generate_winternitz_witness, WinternitzSigningInputs};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct KickOff1Transaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for KickOff1Transaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl KickOff1Transaction {
    pub fn new(
        context: &OperatorContext,
        connector_1: &Connector1,
        connector_2: &Connector2,
        connector_6: &Connector6,
        input_0: Input,
    ) -> Self {
        Self::new_for_validation(
            context.network,
            &context.operator_taproot_public_key,
            &context.n_of_n_taproot_public_key,
            connector_1,
            connector_2,
            connector_6,
            input_0,
        )
    }

    pub fn new_for_validation(
        network: Network,
        operator_taproot_public_key: &XOnlyPublicKey,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        connector_1: &Connector1,
        connector_2: &Connector2,
        connector_6: &Connector6,
        input_0: Input,
    ) -> Self {
        let connector_a = ConnectorA::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );

        let input_0_leaf = 0;
        let _input_0 = connector_6.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount =
            input_0.amount - Amount::from_sat(MESSAGE_COMMITMENT_FEE_AMOUNT * 2 + FEE_AMOUNT);

        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
        };

        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_1.generate_taproot_address().script_pubkey(),
        };

        let _output_2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_2.generate_taproot_address().script_pubkey(),
        };

        KickOff1Transaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_6.generate_taproot_address().script_pubkey(), // TODO: Add address of Commit y
            }],
            prev_scripts: vec![connector_6.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        connector_6: &Connector6,
        source_network_txid_inputs: &WinternitzSigningInputs,
        destination_network_txid_inputs: &WinternitzSigningInputs,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let prev_outs = &self.prev_outs().clone();
        let taproot_spend_info = connector_6.generate_taproot_spend_info();
        let mut unlock_data: Vec<Vec<u8>> = Vec::new();

        // get schnorr signature
        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            self.tx_mut(),
            prev_outs,
            input_index,
            TapSighashType::All,
            script,
            &context.operator_keypair,
        );
        unlock_data.push(schnorr_signature.to_vec());

        // get winternitz signature for source network txid
        unlock_data.extend(generate_winternitz_witness(source_network_txid_inputs).to_vec());

        // get winternitz signature for destination network txid
        unlock_data.extend(generate_winternitz_witness(destination_network_txid_inputs).to_vec());

        populate_taproot_input_witness(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            unlock_data,
        );
    }

    pub fn sign(
        &mut self,
        context: &OperatorContext,
        connector_6: &Connector6,
        source_network_txid_inputs: &WinternitzSigningInputs,
        destination_network_txid_inputs: &WinternitzSigningInputs,
    ) {
        self.sign_input_0(
            context,
            connector_6,
            source_network_txid_inputs,
            destination_network_txid_inputs,
        );
    }
}

impl BaseTransaction for KickOff1Transaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
