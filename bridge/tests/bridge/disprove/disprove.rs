use bitcoin::{
    consensus::encode::serialize_hex, key::Keypair, Amount, Network, PrivateKey, PublicKey, TxOut,
};

use bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{DUST_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input},
        disprove::DisproveTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use secp256k1::SECP256K1;

use crate::bridge::faucet::{Faucet, FaucetType};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_disprove_tx_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount_0 = Amount::from_sat(DUST_AMOUNT);
    let connector_5_address = config.connector_5.generate_taproot_address();
    faucet.fund_input(&connector_5_address, amount_0).await;

    let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
    let connector_c_address = config.connector_c.generate_taproot_address();
    faucet
        .fund_input(&connector_c_address, amount_1)
        .await
        .wait()
        .await;

    let outpoint_0 = generate_stub_outpoint(&config.client_0, &connector_5_address, amount_0).await;
    let outpoint_1 = generate_stub_outpoint(&config.client_0, &connector_c_address, amount_1).await;

    let mut disprove_tx = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        Input {
            outpoint: outpoint_1,
            amount: amount_1,
        },
        1,
    );

    let secret_nonces_0 = disprove_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_tx.push_nonces(&config.verifier_1_context);

    disprove_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove_tx.add_input_output(&config.connector_c, 1, vec![], verifier_reward_script);

    let tx = disprove_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_disprove_tx_with_verifier_added_to_output_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    let amount_0 = Amount::from_sat(DUST_AMOUNT);
    let connector_5_address = config.connector_5.generate_taproot_address();
    faucet.fund_input(&connector_5_address, amount_0).await;

    let amount_1 = Amount::from_sat(INITIAL_AMOUNT);
    let connector_c_address = config.connector_c.generate_taproot_address();
    faucet
        .fund_input(&connector_c_address, amount_0)
        .await
        .wait()
        .await;

    let outpoint_0 = generate_stub_outpoint(&config.client_0, &connector_5_address, amount_0).await;
    let outpoint_1 = generate_stub_outpoint(&config.client_0, &connector_c_address, amount_1).await;

    let mut disprove_tx = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        Input {
            outpoint: outpoint_0,
            amount: amount_0,
        },
        Input {
            outpoint: outpoint_1,
            amount: amount_1,
        },
        1,
    );

    let secret_nonces_0 = disprove_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_tx.push_nonces(&config.verifier_1_context);

    disprove_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove_tx.add_input_output(&config.connector_c, 1, vec![], verifier_reward_script);

    let mut tx = disprove_tx.finalize();

    let secp = SECP256K1;
    let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
    let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
    let verifier_private_key = PrivateKey::new(verifier_keypair.secret_key(), Network::Testnet);
    let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key);

    let verifier_output = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: generate_pay_to_pubkey_script(&verifier_pubkey),
    };

    tx.output.push(verifier_output);

    println!("Script Path Spend Transaction: {:?}\n", tx);
    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}
