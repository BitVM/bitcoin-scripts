use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, Transaction,
    TxOut,
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
    signing::populate_p2wsh_witness_with_signatures,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInDepositTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
}

impl PreSignedTransaction for PegInDepositTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PegInDepositTransaction {
    pub fn new(context: &DepositorContext, connector_z: &ConnectorZ, input_0: Input) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.depositor_public_key,
            connector_z,
            input_0,
        );

        this.sign_input_0(context);

        this
    }

    pub fn new_with_signature(
        network: Network,
        depositor_public_key: &PublicKey,
        connector_z: &ConnectorZ,
        input_0: Input,
        signature: bitcoin::ecdsa::Signature,
    ) -> Self {
        let mut this =
            Self::new_for_validation(network, depositor_public_key, connector_z, input_0);

        this.sign_input_0_with_signature(signature);

        this
    }

    pub fn new_for_validation(
        network: Network,
        depositor_public_key: &PublicKey,
        connector_z: &ConnectorZ,
        input_0: Input,
    ) -> Self {
        let _input_0 = generate_default_tx_in(&input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
        };

        PegInDepositTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: generate_pay_to_pubkey_script_address(network, depositor_public_key)
                    .script_pubkey(),
            }],
            prev_scripts: vec![generate_pay_to_pubkey_script(depositor_public_key)],
        }
    }

    fn sign_input_0(&mut self, context: &DepositorContext) {
        let input_index = 0;
        pre_sign_p2wsh_input(
            self,
            input_index,
            EcdsaSighashType::All,
            &vec![&context.depositor_keypair],
        );
    }

    fn sign_input_0_with_signature(&mut self, signature: bitcoin::ecdsa::Signature) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        populate_p2wsh_witness_with_signatures(
            self.tx_mut(),
            input_index,
            script,
            &vec![signature],
        );
    }
}

impl BaseTransaction for PegInDepositTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
