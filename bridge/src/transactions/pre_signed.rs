use bitcoin::{
    key::Keypair, taproot::TaprootSpendInfo, EcdsaSighashType, PublicKey, ScriptBuf,
    TapSighashType, Transaction, TxOut,
};

use super::{
    super::contexts::base::BaseContext,
    signing::{
        populate_p2wpkh_witness, populate_p2wsh_witness, populate_taproot_input_witness_default,
    },
};

pub trait PreSignedTransaction {
    fn tx(&self) -> &Transaction;
    fn tx_mut(&mut self) -> &mut Transaction;
    fn prev_outs(&self) -> &Vec<TxOut>;
    fn prev_scripts(&self) -> &Vec<ScriptBuf>;
}

pub fn pre_sign_p2wsh_input<T: PreSignedTransaction>(
    tx: &mut T,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    keypairs: &Vec<&Keypair>,
) {
    let script = &tx.prev_scripts()[input_index].clone();
    let value = tx.prev_outs()[input_index].value;

    populate_p2wsh_witness(
        tx.tx_mut(),
        input_index,
        sighash_type,
        script,
        value,
        keypairs,
    );
}

pub fn pre_sign_p2wpkh_input<T: PreSignedTransaction>(
    tx: &mut T,
    context: &dyn BaseContext,
    input_index: usize,
    sighash_type: EcdsaSighashType,
    public_key: &PublicKey,
    keypair: &Keypair,
) {
    let value = tx.prev_outs()[input_index].value;

    populate_p2wpkh_witness(
        context,
        tx.tx_mut(),
        input_index,
        sighash_type,
        value,
        public_key,
        keypair,
    );
}

pub fn pre_sign_taproot_input_default<T: PreSignedTransaction>(
    tx: &mut T,
    input_index: usize,
    sighash_type: TapSighashType,
    taproot_spend_info: TaprootSpendInfo,
    keypairs: &Vec<&Keypair>,
) {
    let prev_outs = &tx.prev_outs().clone();
    let script = &tx.prev_scripts()[input_index].clone();

    populate_taproot_input_witness_default(
        tx.tx_mut(),
        prev_outs,
        input_index,
        sighash_type,
        &taproot_spend_info,
        script,
        keypairs,
    );
}
