use std::time::Duration;

use ark_bn254::G1Affine;
use ark_ff::UniformRand as _;
use ark_std::test_rng;
use bitcoin::{Address, Amount, OutPoint};
use bitvm::chunker::disprove_execution::{disprove_exec, RawProof};
use bridge::{
    connectors::base::TaprootConnector,
    graphs::base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT},
    scripts::generate_pay_to_pubkey_script_address,
    transactions::{
        assert_transactions::{
            assert_commit_1::AssertCommit1Transaction, assert_commit_2::AssertCommit2Transaction,
            assert_final::AssertFinalTransaction, assert_initial::AssertInitialTransaction,
            utils::sign_assert_tx_with_groth16_proof,
        },
        base::{BaseTransaction, Input},
        disprove::DisproveTransaction,
        kick_off_2::MIN_RELAY_FEE_AMOUNT,
        pre_signed::PreSignedTransaction,
        pre_signed_musig2::PreSignedMusig2Transaction,
        take_2::Take2Transaction,
    },
};
use num_traits::ToPrimitive;
use rand::{RngCore as _, SeedableRng as _};
use tokio::time::sleep;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::verify_funding_inputs,
    integration::peg_out::utils::{
        create_and_mine_kick_off_2_tx, create_and_mine_peg_in_confirm_tx,
    },
    setup::setup_test,
};

fn correct_proof_gen() -> RawProof {
    let right_proof = RawProof::default();
    assert!(right_proof.valid_proof());
    right_proof
}

fn wrong_proof_gen() -> RawProof {
    let mut right_proof = RawProof::default();
    assert!(right_proof.valid_proof());
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    right_proof.proof.a = G1Affine::rand(&mut rng);
    let wrong_proof = right_proof;
    wrong_proof
}

#[tokio::test]
async fn test_disprove_fail() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(
        INITIAL_AMOUNT + 300 * FEE_AMOUNT + MIN_RELAY_FEE_AMOUNT + 2000 * DUST_AMOUNT,
    );
    let kick_off_2_funding_utxo_address = config.connector_1.generate_taproot_address();
    funding_inputs.push((&kick_off_2_funding_utxo_address, kick_off_2_input_amount));

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + FEE_AMOUNT);
    let peg_in_confirm_funding_address = config.connector_z.generate_taproot_address();
    funding_inputs.push((&peg_in_confirm_funding_address, deposit_input_amount));

    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &config.client_0,
        &config.operator_context,
        &config.connector_1,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // assert initial
    let vout = 1; // connector B
    let assert_initial_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let mut assert_initial = AssertInitialTransaction::new(
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_e_2,
        assert_initial_input_0,
    );

    let secret_nonces_0 = assert_initial.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_initial.push_nonces(&config.verifier_1_context);

    assert_initial.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_initial.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let assert_initial_tx = assert_initial.finalize();
    let assert_initial_txid = assert_initial_tx.compute_txid();
    println!(
        "txid: {}, assert_initial_tx inputs {}, outputs {}",
        assert_initial_txid,
        assert_initial.tx().input.len(),
        assert_initial.tx().output.len()
    );
    let assert_initial_result = config.client_0.esplora.broadcast(&assert_initial_tx).await;
    assert!(
        assert_initial_result.is_ok(),
        "error: {:?}",
        assert_initial_result.err()
    );

    // gen right proof and witness
    let wrong_proof = correct_proof_gen();
    let (witness_for_commit1, witness_for_commit2) =
        sign_assert_tx_with_groth16_proof(&config.commitment_secrets, &wrong_proof);

    // assert commit 1
    let mut vout_base = 1; // connector E
    let mut assert_commit_1 = AssertCommit1Transaction::new(
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_f.connector_f_1,
        (0..config.assert_commit_connectors_e_1.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_1.sign(
        &config.assert_commit_connectors_e_1,
        witness_for_commit1.clone(),
    );
    let assert_commit_1_tx = assert_commit_1.finalize();
    let assert_commit_1_txid = assert_commit_1_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_1_tx inputs {}, outputs {}",
        assert_commit_1_txid,
        assert_commit_1.tx().input.len(),
        assert_commit_1.tx().output.len()
    );
    let assert_commit_1_result = config.client_0.esplora.broadcast(&assert_commit_1_tx).await;
    assert!(
        assert_commit_1_result.is_ok(),
        "error: {:?}",
        assert_commit_1_result.err()
    );

    // assert commit 2
    vout_base += config.assert_commit_connectors_e_1.connectors_num(); // connector E
    let assert_commit_2_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let mut assert_commit_2 = AssertCommit2Transaction::new(
        &config.assert_commit_connectors_e_2,
        &config.assert_commit_connectors_f.connector_f_2,
        (0..config.assert_commit_connectors_e_2.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_2.sign(
        &config.assert_commit_connectors_e_2,
        witness_for_commit2.clone(),
    );
    let assert_commit_2_tx = assert_commit_2.finalize();
    let assert_commit_2_txid = assert_commit_2_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_2_tx inputs {}, outputs {}",
        assert_commit_2_txid,
        assert_commit_2.tx().input.len(),
        assert_commit_2.tx().output.len()
    );
    let assert_commit_2_result = config.client_0.esplora.broadcast(&assert_commit_2_tx).await;
    assert!(
        assert_commit_2_result.is_ok(),
        "error: {:?}",
        assert_commit_2_result.err()
    );

    // assert final
    let vout_0 = 0; // connector D
    let vout_1 = 0; // connector F
    let vout_2 = 0; // connector F
    let assert_final_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout: vout_0,
        },
        amount: assert_initial_tx.output[vout_0 as usize].value,
    };
    let assert_final_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_commit_1_txid,
            vout: vout_1,
        },
        amount: assert_commit_1_tx.output[vout_1 as usize].value,
    };
    let assert_final_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_commit_2_txid,
            vout: vout_2,
        },
        amount: assert_commit_2_tx.output[vout_2 as usize].value,
    };
    let mut assert_final = AssertFinalTransaction::new(
        &config.operator_context,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        &config.connector_d,
        &config.assert_commit_connectors_f,
        assert_final_input_0,
        assert_final_input_1,
        assert_final_input_2,
    );

    let secret_nonces_0 = assert_final.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_final.push_nonces(&config.verifier_1_context);

    assert_final.pre_sign(
        &config.verifier_0_context,
        &config.connector_d,
        &secret_nonces_0,
    );
    assert_final.pre_sign(
        &config.verifier_1_context,
        &config.connector_d,
        &secret_nonces_1,
    );

    let assert_final_tx = assert_final.finalize();
    let assert_final_txid = assert_final_tx.compute_txid();
    let assert_final_result = config.client_0.esplora.broadcast(&assert_final_tx).await;
    assert!(
        assert_final_result.is_ok(),
        "error: {:?}",
        assert_final_result.err()
    );

    // try to disprove
    assert!(config
        .connector_c
        .generate_disprove_witness(
            witness_for_commit1,
            witness_for_commit2,
            wrong_proof.vk.clone(),
        )
        .is_none());
    // let script_index = 1;

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_txid) = create_and_mine_peg_in_confirm_tx(
        &config.client_0,
        &config.depositor_context,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_z,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // take 2
    let vout = 0; // connector 0
    let take_2_input_0 = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_txid,
            vout,
        },
        amount: peg_in_confirm_tx.output[vout as usize].value,
    };
    let vout = 0; // connector 4
    let take_2_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };
    let vout = 1; // connector 5
    let take_2_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };
    let vout = 2; // connector c
    let take_2_input_3 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };

    let mut take_2 = Take2Transaction::new(
        &config.operator_context,
        &config.connector_0,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        take_2_input_0,
        take_2_input_1,
        take_2_input_2,
        take_2_input_3,
    );

    let secret_nonces_0 = take_2.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = take_2.push_nonces(&config.verifier_1_context);

    take_2.pre_sign(
        &config.verifier_0_context,
        &config.connector_0,
        &config.connector_5,
        &secret_nonces_0,
    );
    take_2.pre_sign(
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_5,
        &secret_nonces_1,
    );

    take_2.sign(&config.operator_context, &config.connector_c);

    let take_2_tx = take_2.finalize();
    let take_2_txid = take_2_tx.compute_txid();

    // mine take 2
    let take_2_wait_timeout = Duration::from_secs(20);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting take 2 tx...",
        take_2_wait_timeout
    );
    sleep(take_2_wait_timeout).await;
    let take_2_result = config.client_0.esplora.broadcast(&take_2_tx).await;
    println!("Broadcast result: {:?}\n", take_2_result);
    assert!(take_2_result.is_ok());

    // operator balance
    let operator_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    let operator_utxos = config
        .client_0
        .esplora
        .get_address_utxo(operator_address.clone())
        .await
        .unwrap();
    let operator_utxo = operator_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == take_2_txid);

    // assert
    assert!(operator_utxo.is_some());
}

#[tokio::test]
async fn test_disprove_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];
    let kick_off_2_input_amount = Amount::from_sat(
        INITIAL_AMOUNT + 300 * FEE_AMOUNT + MIN_RELAY_FEE_AMOUNT + 2000 * DUST_AMOUNT,
    );
    let kick_off_2_funding_utxo_address = config.connector_1.generate_taproot_address();
    funding_inputs.push((&kick_off_2_funding_utxo_address, kick_off_2_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // kick-off 2
    let (kick_off_2_tx, kick_off_2_txid) = create_and_mine_kick_off_2_tx(
        &config.client_0,
        &config.operator_context,
        &config.connector_1,
        &kick_off_2_funding_utxo_address,
        kick_off_2_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // assert initial
    let vout = 1; // connector B
    let assert_initial_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let mut assert_initial = AssertInitialTransaction::new(
        &config.connector_b,
        &config.connector_d,
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_e_2,
        assert_initial_input_0,
    );

    let secret_nonces_0 = assert_initial.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_initial.push_nonces(&config.verifier_1_context);

    assert_initial.pre_sign(
        &config.verifier_0_context,
        &config.connector_b,
        &secret_nonces_0,
    );
    assert_initial.pre_sign(
        &config.verifier_1_context,
        &config.connector_b,
        &secret_nonces_1,
    );

    let assert_initial_tx = assert_initial.finalize();
    let assert_initial_txid = assert_initial_tx.compute_txid();
    println!(
        "txid: {}, assert_initial_tx inputs {}, outputs {}",
        assert_initial_txid,
        assert_initial.tx().input.len(),
        assert_initial.tx().output.len()
    );
    let assert_initial_result = config.client_0.esplora.broadcast(&assert_initial_tx).await;
    assert!(
        assert_initial_result.is_ok(),
        "error: {:?}",
        assert_initial_result.err()
    );

    // gen wrong proof and witness
    let wrong_proof = wrong_proof_gen();
    let (witness_for_commit1, witness_for_commit2) =
        sign_assert_tx_with_groth16_proof(&config.commitment_secrets, &wrong_proof);

    // assert commit 1
    let mut vout_base = 1; // connector E
    let mut assert_commit_1 = AssertCommit1Transaction::new(
        &config.assert_commit_connectors_e_1,
        &config.assert_commit_connectors_f.connector_f_1,
        (0..config.assert_commit_connectors_e_1.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_1.sign(
        &config.assert_commit_connectors_e_1,
        witness_for_commit1.clone(),
    );
    let assert_commit_1_tx = assert_commit_1.finalize();
    let assert_commit_1_txid = assert_commit_1_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_1_tx inputs {}, outputs {}",
        assert_commit_1_txid,
        assert_commit_1.tx().input.len(),
        assert_commit_1.tx().output.len()
    );
    let assert_commit_1_result = config.client_0.esplora.broadcast(&assert_commit_1_tx).await;
    assert!(
        assert_commit_1_result.is_ok(),
        "error: {:?}",
        assert_commit_1_result.err()
    );

    // assert commit 2
    vout_base += config.assert_commit_connectors_e_1.connectors_num(); // connector E
    let assert_commit_2_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout,
        },
        amount: assert_initial_tx.output[vout as usize].value,
    };
    let mut assert_commit_2 = AssertCommit2Transaction::new(
        &config.assert_commit_connectors_e_2,
        &config.assert_commit_connectors_f.connector_f_2,
        (0..config.assert_commit_connectors_e_2.connectors_num())
            .map(|idx| Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: (idx + vout_base).to_u32().unwrap(),
                },
                amount: assert_initial_tx.output[idx + vout_base].value,
            })
            .collect(),
    );
    assert_commit_2.sign(
        &config.assert_commit_connectors_e_2,
        witness_for_commit2.clone(),
    );
    let assert_commit_2_tx = assert_commit_2.finalize();
    let assert_commit_2_txid = assert_commit_2_tx.compute_txid();
    println!(
        "txid: {}, assert_commit_2_tx inputs {}, outputs {}",
        assert_commit_2_txid,
        assert_commit_2.tx().input.len(),
        assert_commit_2.tx().output.len()
    );
    let assert_commit_2_result = config.client_0.esplora.broadcast(&assert_commit_2_tx).await;
    assert!(
        assert_commit_2_result.is_ok(),
        "error: {:?}",
        assert_commit_2_result.err()
    );

    // assert final
    let vout_0 = 0; // connector D
    let vout_1 = 0; // connector F
    let vout_2 = 0; // connector F
    let assert_final_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_initial_txid,
            vout: vout_0,
        },
        amount: assert_initial_tx.output[vout_0 as usize].value,
    };
    let assert_final_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_commit_1_txid,
            vout: vout_1,
        },
        amount: assert_commit_1_tx.output[vout_1 as usize].value,
    };
    let assert_final_input_2 = Input {
        outpoint: OutPoint {
            txid: assert_commit_2_txid,
            vout: vout_2,
        },
        amount: assert_commit_2_tx.output[vout_2 as usize].value,
    };
    let mut assert_final = AssertFinalTransaction::new(
        &config.operator_context,
        &config.connector_4,
        &config.connector_5,
        &config.connector_c,
        &config.connector_d,
        &config.assert_commit_connectors_f,
        assert_final_input_0,
        assert_final_input_1,
        assert_final_input_2,
    );

    let secret_nonces_0 = assert_final.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = assert_final.push_nonces(&config.verifier_1_context);

    assert_final.pre_sign(
        &config.verifier_0_context,
        &config.connector_d,
        &secret_nonces_0,
    );
    assert_final.pre_sign(
        &config.verifier_1_context,
        &config.connector_d,
        &secret_nonces_1,
    );

    let assert_final_tx = assert_final.finalize();
    let assert_final_txid = assert_final_tx.compute_txid();
    let assert_final_result = config.client_0.esplora.broadcast(&assert_final_tx).await;
    assert!(
        assert_final_result.is_ok(),
        "error: {:?}",
        assert_final_result.err()
    );

    // disprove
    let vout = 1;

    let (script_index, disprove_witness) = config
        .connector_c
        .generate_disprove_witness(
            witness_for_commit1,
            witness_for_commit2,
            wrong_proof.vk.clone(),
        )
        .unwrap();
    // let script_index = 1;

    let disprove_input_0 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };

    let vout = 2;
    let disprove_input_1 = Input {
        outpoint: OutPoint {
            txid: assert_final_txid,
            vout,
        },
        amount: assert_final_tx.output[vout as usize].value,
    };

    let mut disprove = DisproveTransaction::new(
        &config.operator_context,
        &config.connector_5,
        &config.connector_c,
        disprove_input_0,
        disprove_input_1,
        script_index as u32,
    );

    let secret_nonces_0 = disprove.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = disprove.push_nonces(&config.verifier_1_context);

    disprove.pre_sign(
        &config.verifier_0_context,
        &config.connector_5,
        &secret_nonces_0,
    );
    disprove.pre_sign(
        &config.verifier_1_context,
        &config.connector_5,
        &secret_nonces_1,
    );

    let reward_address = generate_pay_to_pubkey_script_address(
        config.withdrawer_context.network,
        &config.withdrawer_context.withdrawer_public_key,
    );
    let verifier_reward_script = reward_address.script_pubkey(); // send reward to withdrawer address
    disprove.add_input_output(
        &config.connector_c,
        script_index as u32,
        disprove_witness,
        verifier_reward_script,
    );

    let disprove_tx = disprove.finalize();
    let disprove_txid = disprove_tx.compute_txid();

    // mine disprove
    let disprove_result = config.client_0.esplora.broadcast(&disprove_tx).await;
    assert!(
        disprove_result.is_ok(),
        "error: {:?}",
        disprove_result.err()
    );

    // reward balance
    let reward_utxos = config
        .client_0
        .esplora
        .get_address_utxo(reward_address)
        .await
        .unwrap();
    let reward_utxo = reward_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == disprove_txid);

    // assert
    assert!(reward_utxo.is_some());
    assert_eq!(reward_utxo.unwrap().value, disprove_tx.output[1].value);
}
