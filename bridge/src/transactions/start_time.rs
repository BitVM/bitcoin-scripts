use bitcoin::{
    absolute, consensus, Amount, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::connectors::{base::TaprootConnector, connector_2::Connector2};

use super::{
    super::{contexts::operator::OperatorContext, graphs::base::FEE_AMOUNT, scripts::*},
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
    signing::{generate_taproot_leaf_schnorr_signature, populate_taproot_input_witness},
};

use bitvm::signatures::signing_winternitz::{
    generate_winternitz_witness, WinternitzSecret, WinternitzSigningInputs,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct StartTimeTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for StartTimeTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for StartTimeTransaction {
    fn musig2_nonces(&self) -> &HashMap<usize, HashMap<PublicKey, PubNonce>> { &self.musig2_nonces }
    fn musig2_nonces_mut(&mut self) -> &mut HashMap<usize, HashMap<PublicKey, PubNonce>> {
        &mut self.musig2_nonces
    }
    fn musig2_nonce_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, Signature>> {
        &self.musig2_nonce_signatures
    }
    fn musig2_nonce_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, Signature>> {
        &mut self.musig2_nonce_signatures
    }
    fn musig2_signatures(&self) -> &HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &self.musig2_signatures
    }
    fn musig2_signatures_mut(
        &mut self,
    ) -> &mut HashMap<usize, HashMap<PublicKey, PartialSignature>> {
        &mut self.musig2_signatures
    }
    fn verifier_inputs(&self) -> Vec<usize> { vec![] }
}

impl StartTimeTransaction {
    pub fn new(context: &OperatorContext, connector_2: &Connector2, input_0: Input) -> Self {
        Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            connector_2,
            input_0,
        )
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        connector_2: &Connector2,
        input_0: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_2.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        StartTimeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![TxOut {
                value: input_0.amount,
                script_pubkey: connector_2.generate_taproot_address().script_pubkey(),
            }],
            prev_scripts: vec![connector_2.generate_taproot_leaf_script(input_0_leaf)],
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn sign_input_0(
        &mut self,
        context: &OperatorContext,
        connector_2: &Connector2,
        start_time_signing_inputs: &WinternitzSigningInputs,
    ) {
        let input_index = 0;
        let script = &self.prev_scripts()[input_index].clone();
        let prev_outs = &self.prev_outs().clone();
        let taproot_spend_info = connector_2.generate_taproot_spend_info();
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

        // get winternitz signature
        unlock_data.extend(generate_winternitz_witness(start_time_signing_inputs).to_vec());

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
        connector_2: &Connector2,
        start_time_block_number: u32,
        start_time_commitment_secret: &WinternitzSecret,
    ) {
        self.tx_mut().lock_time = absolute::LockTime::from_height(start_time_block_number)
            .expect("Failed to set lock time from block.");
        self.sign_input_0(
            context,
            connector_2,
            &WinternitzSigningInputs {
                message: &start_time_block_number.to_le_bytes(),
                signing_key: start_time_commitment_secret,
            },
        );
    }

    pub fn merge(&mut self, burn: &StartTimeTransaction) {
        merge_transactions(&mut self.tx, &burn.tx);
        merge_musig2_nonces_and_signatures(self, burn);
    }
}

impl BaseTransaction for StartTimeTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
