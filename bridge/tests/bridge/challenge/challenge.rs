use bitcoin::{consensus::encode::serialize_hex, Address, Amount};

use bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input, InputWithScript},
        challenge::ChallengeTransaction,
    },
};

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{generate_stub_outpoint, generate_stub_outpoints},
    setup::setup_test,
};

#[tokio::test]
async fn test_challenge_tx() {
    let config = setup_test().await;

    // We re-use the depositor private key to imitate a third-party
    let crowdfunding_keypair = &config.depositor_context.depositor_keypair;
    let crowdfunding_public_key = &config.depositor_context.depositor_public_key;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let amount_0 = Amount::from_sat(DUST_AMOUNT);
    let connector_a_address = config.connector_a.generate_taproot_address();
    funding_inputs.push((&connector_a_address, amount_0));

    // Create two inputs that exceed the crowdfunding total
    let input_amount_crowdfunding_total = Amount::from_sat(INITIAL_AMOUNT);
    let amount_1 = Amount::from_sat(INITIAL_AMOUNT * 2 / 3);
    let crowdfunding_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        crowdfunding_public_key,
    );
    funding_inputs.push((&crowdfunding_address, amount_1));
    funding_inputs.push((&crowdfunding_address, amount_1));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    let outpoint_0 = generate_stub_outpoint(&config.client_0, &connector_a_address, amount_0).await;

    let crowdfunding_outpoints =
        generate_stub_outpoints(&config.client_0, &crowdfunding_address, amount_1).await;

    let refund_address = generate_pay_to_pubkey_script_address(
        config.depositor_context.network,
        crowdfunding_public_key,
    );

    let mut challenge_tx = ChallengeTransaction::new(
        &config.operator_context,
        &config.connector_a,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        input_amount_crowdfunding_total,
    );

    challenge_tx.add_inputs_and_output(
        &vec![
            InputWithScript {
                outpoint: crowdfunding_outpoints[0],
                amount: amount_1,
                script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
            },
            InputWithScript {
                outpoint: crowdfunding_outpoints[1],
                amount: amount_1,
                script: &generate_pay_to_pubkey_script(crowdfunding_public_key),
            },
        ],
        crowdfunding_keypair,
        refund_address.script_pubkey(),
    );

    let tx = challenge_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());

    // assert refund balance
    let challenge_txid = tx.compute_txid();
    let refund_utxos = config
        .client_0
        .esplora
        .get_address_utxo(refund_address)
        .await
        .unwrap();
    let refund_utxo = refund_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == challenge_txid);
    assert!(refund_utxo.is_some());
    assert_eq!(
        refund_utxo.unwrap().value,
        amount_1 * 2 - input_amount_crowdfunding_total
    );
}
