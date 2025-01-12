use bitcoin::{
    absolute, consensus, key::Keypair, Amount, Network, PublicKey, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use super::{
    super::{
        connectors::{base::*, connector_a::ConnectorA},
        contexts::operator::OperatorContext,
        graphs::base::FEE_AMOUNT,
        scripts::*,
    },
    base::*,
    pre_signed::*,
    signing::populate_p2wsh_witness,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ChallengeTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    tx: Transaction,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    prev_outs: Vec<TxOut>,
    prev_scripts: Vec<ScriptBuf>,
    input_amount_crowdfunding: Amount,
}

impl PreSignedTransaction for ChallengeTransaction {
    fn tx(&self) -> &Transaction { &self.tx }

    fn tx_mut(&mut self) -> &mut Transaction { &mut self.tx }

    fn prev_outs(&self) -> &Vec<TxOut> { &self.prev_outs }

    fn prev_scripts(&self) -> &Vec<ScriptBuf> { &self.prev_scripts }
}

impl ChallengeTransaction {
    pub fn new(
        context: &OperatorContext,
        connector_a: &ConnectorA,
        input_0: Input,
        input_amount_crowdfunding: Amount,
    ) -> Self {
        let mut this = Self::new_for_validation(
            context.network,
            &context.operator_public_key,
            connector_a,
            input_0,
            input_amount_crowdfunding,
        );

        this.sign_input_0(context, connector_a);

        this
    }

    pub fn new_for_validation(
        network: Network,
        operator_public_key: &PublicKey,
        connector_a: &ConnectorA,
        input_0: Input,
        input_amount_crowdfunding: Amount,
    ) -> Self {
        let input_0_leaf = 1;
        let _input_0 = connector_a.generate_taproot_leaf_tx_in(input_0_leaf, &input_0);

        let total_output_amount =
            input_0.amount + input_amount_crowdfunding - Amount::from_sat(FEE_AMOUNT);

        let _output_0 = TxOut {
            value: total_output_amount,
            script_pubkey: generate_pay_to_pubkey_script_address(network, operator_public_key)
                .script_pubkey(),
        };

        ChallengeTransaction {
            tx: Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: absolute::LockTime::ZERO,
                input: vec![_input_0],
                output: vec![_output_0],
            },
            prev_outs: vec![
                TxOut {
                    value: input_0.amount,
                    script_pubkey: connector_a.generate_taproot_address().script_pubkey(),
                },
                // input 1 will be added later
            ],
            prev_scripts: vec![
                connector_a.generate_taproot_leaf_script(input_0_leaf),
                // input 1's script will be added later
            ],
            input_amount_crowdfunding,
        }
    }

    fn sign_input_0(&mut self, context: &OperatorContext, connector_a: &ConnectorA) {
        pre_sign_taproot_input_default(
            self,
            0,
            TapSighashType::SinglePlusAnyoneCanPay,
            connector_a.generate_taproot_spend_info(),
            &vec![&context.operator_keypair],
        );
    }

    // allows for aggregating multiple inputs and one refund output
    pub fn add_inputs_and_output(
        &mut self,
        inputs: &Vec<InputWithScript>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        if self.tx.input.len() > 1 {
            panic!("Cannot add any more inputs or outputs.");
        }

        // check total input amount
        let mut total_input_amount = Amount::from_sat(0);
        for input in inputs {
            total_input_amount += input.amount;
        }
        match total_input_amount.cmp(&self.input_amount_crowdfunding) {
            Ordering::Less => panic!("Total input amount too low. Add additional input."),
            Ordering::Greater => {
                // add refund output
                let _output = TxOut {
                    value: total_input_amount - self.input_amount_crowdfunding,
                    script_pubkey: output_script_pubkey,
                };
                self.tx.output.push(_output);
            }
            Ordering::Equal => {}
        }

        // add crowdfunding inputs
        let sighash_type = bitcoin::EcdsaSighashType::AllPlusAnyoneCanPay;
        let mut input_index = self.tx.input.len();
        for input in inputs {
            let _input = TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            self.tx.input.push(_input);

            // add witness
            populate_p2wsh_witness(
                &mut self.tx,
                input_index,
                sighash_type,
                input.script,
                input.amount,
                &vec![&keypair],
            );

            input_index += 1;
        }
    }

    pub fn merge(&mut self, challenge: &ChallengeTransaction) {
        merge_transactions(&mut self.tx, &challenge.tx);
    }
}

impl BaseTransaction for ChallengeTransaction {
    fn finalize(&self) -> Transaction {
        if self.tx.input.len() < 2 {
            panic!("Missing input. Call add_inputs_and_output before finalizing");
        }

        self.tx.clone()
    }
}
