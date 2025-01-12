use bitcoin::{
    absolute, consensus, Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType,
    Transaction, TxOut,
};
use musig2::{secp256k1::schnorr::Signature, PartialSignature, PubNonce, SecNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{connectors::connector_d::ConnectorD, contexts::operator::OperatorContext};

use super::{
    super::{
        super::{
            connectors::{
                base::*, connector_4::Connector4, connector_5::Connector5, connector_c::ConnectorC,
            },
            contexts::{base::BaseContext, verifier::VerifierContext},
            graphs::base::{DUST_AMOUNT, FEE_AMOUNT},
        },
        base::*,
        pre_signed::*,
        pre_signed_musig2::*,
    },
    utils::AssertCommitConnectorsF,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AssertFinalTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,

    musig2_nonces: HashMap<usize, HashMap<PublicKey, PubNonce>>,
    musig2_nonce_signatures: HashMap<usize, HashMap<PublicKey, Signature>>,
    musig2_signatures: HashMap<usize, HashMap<PublicKey, PartialSignature>>,
}

impl PreSignedTransaction for AssertFinalTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl PreSignedMusig2Transaction for AssertFinalTransaction {
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

impl AssertFinalTransaction {
    pub fn new(
        context: &OperatorContext,
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_c: &ConnectorC,
        connector_d: &ConnectorD,
        assert_commit_connectors_f: &AssertCommitConnectorsF,
        input_0: Input,
        input_1: Input,
        input_2: Input,
    ) -> Self {
        let mut this = Self::new_for_validation(
            connector_4,
            connector_5,
            connector_c,
            connector_d,
            assert_commit_connectors_f,
            input_0,
            input_1,
            input_2,
        );

        this.sign_commit_inputs(context);

        this
    }

    pub fn new_for_validation(
        connector_4: &Connector4,
        connector_5: &Connector5,
        connector_c: &ConnectorC,
        connector_d: &ConnectorD,
        assert_commit_connectors_f: &AssertCommitConnectorsF,
        input_0: Input,
        input_1: Input,
        input_2: Input,
    ) -> Self {
        let input_0_leaf = 0;
        let _input_0 = connector_d.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        // simple inputs from assert_commit txs
        let _input_1 = assert_commit_connectors_f
            .connector_f_1
            .generate_tx_in(&input_1);
        let _input_2 = assert_commit_connectors_f
            .connector_f_2
            .generate_tx_in(&input_2);

        let total_output_amount =
            input_1.amount + input_2.amount + input_0.amount - Amount::from_sat(FEE_AMOUNT);

        // goes to take_2 tx
        let _output_0 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_4.generate_address().script_pubkey(),
        };

        // goes to take_2 tx or disprove tx
        let _output_1 = TxOut {
            value: total_output_amount - Amount::from_sat(DUST_AMOUNT) * 2,
            script_pubkey: connector_5.generate_taproot_address().script_pubkey(),
        };

        // goes to take_2 tx or disprove tx
        let _output_2 = TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: connector_c.generate_taproot_address().script_pubkey(),
        };

        AssertFinalTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0, _input_1, _input_2],
                output: vec![_output_0, _output_1, _output_2],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_d.generate_taproot_address().script_pubkey(),
                },
                TxOut {
                    value: input_1.amount,
                    script_pubkey: assert_commit_connectors_f
                        .connector_f_1
                        .generate_address()
                        .script_pubkey(),
                },
                TxOut {
                    value: input_2.amount,
                    script_pubkey: assert_commit_connectors_f
                        .connector_f_2
                        .generate_address()
                        .script_pubkey(),
                },
            ],
            prev_scripts: vec![
                connector_d.generate_taproot_leaf_script(input_0_leaf),
                assert_commit_connectors_f.connector_f_1.generate_script(),
                assert_commit_connectors_f.connector_f_2.generate_script(),
            ],
            musig2_nonces: HashMap::new(),
            musig2_nonce_signatures: HashMap::new(),
            musig2_signatures: HashMap::new(),
        }
    }

    fn sign_input_0(
        &mut self,
        context: &VerifierContext,
        connector_d: &ConnectorD,
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
            self.finalize_input_0(context, connector_d);
        }
    }

    fn sign_commit_inputs(&mut self, context: &OperatorContext) {
        let input_indexes = [1, 2];
        for input_index in input_indexes {
            pre_sign_p2wsh_input(
                self,
                input_index,
                EcdsaSighashType::All,
                &vec![&context.operator_keypair],
            );
        }
    }

    fn finalize_input_0(&mut self, context: &dyn BaseContext, connector_d: &ConnectorD) {
        let input_index = 0;
        finalize_musig2_taproot_input(
            self,
            context,
            input_index,
            TapSighashType::All,
            connector_d.generate_taproot_spend_info(),
        );
    }

    pub fn pre_sign(
        &mut self,
        context: &VerifierContext,
        connector_d: &ConnectorD,
        secret_nonces: &HashMap<usize, SecNonce>,
    ) {
        let input_index = 0;
        self.sign_input_0(context, connector_d, &secret_nonces[&input_index]);
    }

    pub fn merge(&mut self, assert: &AssertFinalTransaction) {
        merge_transactions(&mut self.tx, &assert.tx);
        merge_musig2_nonces_and_signatures(self, assert);
    }
}

impl BaseTransaction for AssertFinalTransaction {
    fn finalize(&self) -> Transaction { self.tx.clone() }
}
