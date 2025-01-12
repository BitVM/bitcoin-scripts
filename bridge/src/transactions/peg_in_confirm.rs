use bitcoin::{
    absolute, consensus, Amount, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    super::{
        connectors::{base::*, connector_0::Connector0, connector_z::ConnectorZ},
        contexts::{base::BaseContext, depositor::DepositorContext, verifier::VerifierContext},
        graphs::base::FEE_AMOUNT,
    },
    base::*,
    pre_signed::*,
    pre_signed_musig2::*,
    signing::*,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegInConfirmTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    n_of_n_public_keys: Vec<PublicKey>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for PegInConfirmTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for PegInConfirmTransaction {
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
    fn verifier_inputs(&self) -> Vec<usize> { vec![0] }
}

impl PegInConfirmTransaction {
    pub fn new(
        context: &DepositorContext,
        connector_0: &Connector0,
        connector_z: &ConnectorZ,
        input_0: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            connector_0,
            connector_z,
            input_0,
            context.n_of_n_public_keys.clone(),
        );

        this.generate_and_push_depositor_signature_input_0(context);

        this
    }

    pub fn new_with_depositor_signature(
        connector_0: &Connector0,
        connector_z: &ConnectorZ,
        input_0: Input,
        n_of_n_public_keys: &[PublicKey],
        depositor_signature: bitcoin::taproot::Signature,
    ) -> Self {
        let mut this = Self::new_for_validation(
            connector_0,
            connector_z,
            input_0,
            n_of_n_public_keys.to_owned(),
        );

        this.push_depositor_signature_input(0, depositor_signature);

        this
    }

    pub fn new_for_validation(
        connector_0: &Connector0,
        connector_z: &ConnectorZ,
        input_0: Input,
        n_of_n_public_keys: Vec<PublicKey>,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_z.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount = input_0.amount - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: connector_0.generate_taproot_address().script_pubkey(),
        };

        PegInConfirmTransaction {
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
            n_of_n_public_keys,
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn generate_and_push_depositor_signature_input_0(&mut self, context: &DepositorContext) {
        let input_index = 0;
        let schnorr_signature = generate_taproot_leaf_schnorr_signature(
            &mut self.tx,
            &self.prev_outs,
            input_index,
            TapSighashType::All,
            &self.prev_scripts[input_index],
            &context.depositor_keypair,
        );

        self.push_depositor_signature_input(input_index, schnorr_signature);
    }

    fn push_depositor_signature_input(
        &mut self,
        input_index: usize,
        signature: bitcoin::taproot::Signature,
    ) {
        let unlock_data: Vec<Vec<u8>> = vec![signature.to_vec()];

        push_taproot_leaf_unlock_data_to_witness(&mut self.tx, input_index, unlock_data);
    }

    fn push_verifier_signature_input_0(
        &mut self,
        context: &VerifierContext,
        connector_z: &ConnectorZ,
        secret_nonce: &SecNonce,
    ) {
        let input_index = 0;
        pre_sign_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            secret_nonce,
        );

        // TODO: Consider verifying the final signature against the n-of-n public key and the tx.
        if self.musig2_signatures[&input_index].len() == context.n_of_n_public_keys.len() {
            self.finalize_input_0(context, connector_z);
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext, connector_z: &ConnectorZ) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            connector_z.generate_taproot_spend_info(),
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        connector_z: &ConnectorZ,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.push_verifier_signature_input_0(context, connector_z, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, peg_in_confirm: &PegInConfirmTransaction) {
        merge_transactions(&mut self.tx, &peg_in_confirm.tx);
        merge_musig2_nonces_and_signatures(self, peg_in_confirm);
    }

    pub fn has_nonce_of(&self, context: &VerifierContext) -> bool {
        let input_index = 0;

        self.musig2_nonces.contains_key(&input_index)
            && self.musig2_nonces[&input_index].contains_key(&context.verifier_public_key)
    }
    pub fn has_all_nonces(&self) -> bool {
        let input_index = 0;

        self.n_of_n_public_keys.iter().all(|verifier_key| {
            self.musig2_nonces.contains_key(&input_index)
                && self.musig2_nonces[&input_index].contains_key(verifier_key)
        })
    }
    pub fn has_signature_of(&self, context: &VerifierContext) -> bool {
        let input_index = 0;

        self.musig2_signatures.contains_key(&input_index)
            && self.musig2_signatures[&input_index].contains_key(&context.verifier_public_key)
    }
    pub fn has_all_signatures(&self) -> bool {
        let input_index = 0;

        self.n_of_n_public_keys.iter().all(|verifier_key| {
            self.musig2_signatures.contains_key(&input_index)
                && self.musig2_signatures[&input_index].contains_key(verifier_key)
        })
    }
}

impl BaseTransaction for PegInConfirmTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
