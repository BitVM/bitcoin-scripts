use bitcoin::{
    consensus::encode::serialize_hex, key::Keypair, Amount, PrivateKey, PublicKey, TxOut,
};

use bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::{generate_pay_to_pubkey_script, generate_pay_to_pubkey_script_address},
    transactions::{
        base::{BaseTransaction, Input},
        disprove_chain::DisproveChainTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};
use secp256k1::SECP256K1;

use crate::bridge::faucet::{Faucet, FaucetType};

use super::super::{helper::generate_stub_outpoint, setup::setup_test};

#[tokio::test]
async fn test_disprove_chain_tx_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let amount = Amount::from_sat(INITIAL_AMOUNT);
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), amount)
        .await
        .wait()
        .await;

    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut disprove_chain_tx = DisproveChainTransaction::new(
        &config.operator_context,
        &config.connector_b,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

    disprove_chain_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    disprove_chain_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    disprove_chain_tx.add_output(reward_address.script_pubkey());

    let tx = disprove_chain_tx.finalize();
    println!("Script Path Spend Transaction: {:?}\n", tx);

    let result = config.client_0.esplora.broadcast(&tx).await;
    println!("Txid: {:?}", tx.compute_txid());
    println!("Broadcast result: {:?}\n", result);
    println!("Transaction hex: \n{}", serialize_hex(&tx));
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_disprove_chain_tx_with_verifier_added_to_output_success() {
    let config = setup_test().await;

    let faucet = Faucet::new(FaucetType::EsploraRegtest);
    let amount = Amount::from_sat(INITIAL_AMOUNT)
        + (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) * 5 / 100;
    faucet
        .fund_input(&config.connector_b.generate_taproot_address(), amount)
        .await
        .wait()
        .await;
    let outpoint = generate_stub_outpoint(
        &config.client_0,
        &config.connector_b.generate_taproot_address(),
        amount,
    )
    .await;

    let mut disprove_chain_tx = DisproveChainTransaction::new(
        &config.operator_context,
        &config.connector_b,
        Input { outpoint, amount },
    );

    let secret_nonces_0 = disprove_chain_tx.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove_chain_tx.push_nonces(&config.verifier_1_context);

    disprove_chain_tx.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    disprove_chain_tx.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    disprove_chain_tx.add_output(reward_address.script_pubkey());

    let mut tx = disprove_chain_tx.finalize();

    let secp = SECP256K1;
    let verifier_secret: &str = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffff1234";
    let verifier_keypair = Keypair::from_seckey_str(&secp, verifier_secret).unwrap();
    let verifier_private_key = PrivateKey::new(
        verifier_keypair.secret_key(),
        config.verifier_0_context.network,
    );
    let verifier_pubkey = PublicKey::from_private_key(&secp, &verifier_private_key);

    let verifier_output = TxOut {
        value: (Amount::from_sat(INITIAL_AMOUNT) - Amount::from_sat(FEE_AMOUNT)) * 5 / 100,
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
