use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use serde::{Deserialize, Serialize};

use super::{
    super::{
        connectors::{base::*, connector_z::ConnectorZ},
        contexts::depositor::DepositorContext,
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    signing::populate_taproot_input_witness_with_signature,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInRefundTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegInRefundTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PegInRefundTransaction {
    pub fn new(context: &DepositorContext, connector_z: &ConnectorZ, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.depositor_public_key,
            connector_z,
            input_0,
        );

        this.sign_input_0(context, connector_z);

        this
    }

    pub fn new_with_signature(
        network: Network,
        depositor_public_key: &PublicKey,
        connector_z: &ConnectorZ,
        input_0: Input,
        signature: bitcoin::taproot::Signature,
    ) -> Self {
        let mut this =
            Self::new_for_validation(network, depositor_public_key, connector_z, input_0);

        this.sign_input_0_with_signature(connector_z, signature);

        this
    }

    pub fn new_for_validation(
        network: Network,
        depositor_public_key: &PublicKey,
        connector_z: &ConnectorZ,
        input_0: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, depositor_public_key)
                .script_pubkey(),
        };

        PegInRefundTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_z.generate_taproot_leaf_script(input_0_leaf)],
        }
    }

    fn sign_input_0(&mut self, context: &DepositorContext, connector_z: &ConnectorZ) {
        pre_sign_taproot_input_default(
            self,
            0,
            TapSighashType::All,
            connector_z.generate_taproot_spend_info(),
            &vec![&context.depositor_keypair],
        );
    }

    fn sign_input_0_with_signature(
        &mut self,
        connector_z: &ConnectorZ,
        signature: bitcoin::taproot::Signature,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let taproot_spend_info = connector_z.generate_taproot_spend_info();

        populate_taproot_input_witness_with_signature(
            self.tx_mut(),
            input_index,
            &taproot_spend_info,
            script,
            &[signature],
        );
    }
}

impl BaseTransaction for PegInRefundTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
