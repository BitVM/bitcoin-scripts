use std::str::FromStr;

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid};
use bridge::{
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{Input, InputWithScript},
        challenge::ChallengeTransaction,
        pre_signed::PreSignedTransaction,
    },
};

use crate::bridge::setup::setup_test;

#[tokio::test]
// TODO: test merging signatures after Musig2 feature is ready
async fn test_merge_add_new_input_and_output() {
    // Arrange
    let config = setup_test().await;

    let amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT + 1);

    let outpoint = OutPoint {
        txid: Txid::from_str("0e6719ac074b0e3cac76d057643506faa1c266b322aa9cf4c6f635fe63b14327")
            .unwrap(),
        vout: 0,
    };
    let mut destination_challenge_tx = ChallengeTransaction::new(
        &config.operator_context,
        &config.connector_a,
        Input { outpoint, amount },
        amount,
    );

    let mut source_challenge_tx = destination_challenge_tx.clone();
    let refund_script = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        &config.depositor_context.depositor_public_key,
    )
    .script_pubkey();
    let input_script =
        generate_pay_to_pubkey_script(&config.depositor_context.depositor_public_key);
    source_challenge_tx.add_inputs_and_output(
        &vec![InputWithScript {
            outpoint,
            amount: amount * 2,
            script: &input_script,
        }],
        &config.depositor_context.depositor_keypair,
        refund_script.clone(),
    );

    let input_length_before = destination_challenge_tx.tx().input.len();
    let output_length_before = destination_challenge_tx.tx().output.len();

    // Act
    destination_challenge_tx.merge(&source_challenge_tx);

    // Assert
    let input_length_after = destination_challenge_tx.tx().input.len();
    let output_length_after = destination_challenge_tx.tx().output.len();

    assert_eq!(input_length_before, input_length_after - 1);
    assert_eq!(output_length_before, output_length_after - 1);
    let added_input = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: source_challenge_tx.tx().input[1].witness.clone(),
    };
    let added_output = TxOut {
        value: amount,
        script_pubkey: refund_script,
    };

    assert!(destination_challenge_tx.tx().input[1].eq(&added_input));
    assert!(destination_challenge_tx.tx().output[1].eq(&added_output));
}
