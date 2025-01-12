use std::collections::HashMap;

use bitcoin::{Network, PublicKey};

use bitvm::{
    chunker::assigner::BridgeAssigner,
    signatures::signing_winternitz::{WinternitzPublicKey, WinternitzSecret},
    signatures::winternitz::Parameters,
};

use bridge::{
    client::client::BitVMClient,
    connectors::{
        connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
        connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
        connector_6::Connector6, connector_a::ConnectorA, connector_b::ConnectorB,
        connector_c::ConnectorC, connector_d::ConnectorD, connector_e::ConnectorE,
        connector_f_1::ConnectorF1, connector_f_2::ConnectorF2, connector_z::ConnectorZ,
    },
    constants::{
        DestinationNetwork, DESTINATION_NETWORK_TXID_LENGTH, SOURCE_NETWORK_TXID_LENGTH,
        START_TIME_MESSAGE_LENGTH,
    },
    contexts::{
        base::generate_keys_from_secret, depositor::DepositorContext, operator::OperatorContext,
        verifier::VerifierContext, withdrawer::WithdrawerContext,
    },
    graphs::{
        base::{
            DEPOSITOR_EVM_ADDRESS, DEPOSITOR_SECRET, OPERATOR_SECRET, VERIFIER_0_SECRET,
            VERIFIER_1_SECRET, WITHDRAWER_EVM_ADDRESS, WITHDRAWER_SECRET,
        },
        peg_out::CommitmentMessageId,
    },
    superblock::{SUPERBLOCK_HASH_MESSAGE_LENGTH, SUPERBLOCK_MESSAGE_LENGTH},
    transactions::assert_transactions::utils::{
        groth16_commitment_secrets_to_public_keys, merge_to_connector_c_commits_public_key,
        AssertCommit1ConnectorsE, AssertCommit2ConnectorsE, AssertCommitConnectorsF,
    },
};

pub struct SetupConfig {
    pub client_0: BitVMClient,
    pub client_1: BitVMClient,
    pub depositor_context: DepositorContext,
    pub operator_context: OperatorContext,
    pub verifier_0_context: VerifierContext,
    pub verifier_1_context: VerifierContext,
    pub withdrawer_context: WithdrawerContext,
    pub connector_a: ConnectorA,
    pub connector_b: ConnectorB,
    pub connector_c: ConnectorC,
    pub connector_d: ConnectorD,
    pub assert_commit_connectors_e_1: AssertCommit1ConnectorsE,
    pub assert_commit_connectors_e_2: AssertCommit2ConnectorsE,
    pub assert_commit_connectors_f: AssertCommitConnectorsF,
    pub connector_z: ConnectorZ,
    pub connector_0: Connector0,
    pub connector_1: Connector1,
    pub connector_2: Connector2,
    pub connector_3: Connector3,
    pub connector_4: Connector4,
    pub connector_5: Connector5,
    pub connector_6: Connector6,
    pub depositor_evm_address: String,
    pub withdrawer_evm_address: String,
    pub commitment_secrets: HashMap<CommitmentMessageId, WinternitzSecret>,
}

pub async fn setup_test() -> SetupConfig {
    let source_network = Network::Regtest;
    let destination_network = DestinationNetwork::Local;

    let commitment_secrets = get_test_commitment_secrets();

    let (_, verifier_0_public_key) = generate_keys_from_secret(source_network, VERIFIER_0_SECRET);
    let (_, verifier_1_public_key) = generate_keys_from_secret(source_network, VERIFIER_1_SECRET);
    let mut n_of_n_public_keys: Vec<PublicKey> = Vec::new();
    n_of_n_public_keys.push(verifier_0_public_key);
    n_of_n_public_keys.push(verifier_1_public_key);

    let depositor_context =
        DepositorContext::new(source_network, DEPOSITOR_SECRET, &n_of_n_public_keys);
    let operator_context =
        OperatorContext::new(source_network, OPERATOR_SECRET, &n_of_n_public_keys);
    let verifier_0_context =
        VerifierContext::new(source_network, VERIFIER_0_SECRET, &n_of_n_public_keys);
    let verifier_1_context =
        VerifierContext::new(source_network, VERIFIER_1_SECRET, &n_of_n_public_keys);
    let withdrawer_context =
        WithdrawerContext::new(source_network, WITHDRAWER_SECRET, &n_of_n_public_keys);

    let client_0 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_0_SECRET),
        Some(WITHDRAWER_SECRET),
        None,
    )
    .await;

    let client_1 = BitVMClient::new(
        source_network,
        destination_network,
        &n_of_n_public_keys,
        Some(DEPOSITOR_SECRET),
        Some(OPERATOR_SECRET),
        Some(VERIFIER_1_SECRET),
        Some(WITHDRAWER_SECRET),
        None,
    )
    .await;

    let connector_a = ConnectorA::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b = ConnectorB::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_d = ConnectorD::new(source_network, &operator_context.n_of_n_taproot_public_key);

    let (connector_e1_commitment_public_keys, connector_e2_commitment_public_keys) =
        groth16_commitment_secrets_to_public_keys(&commitment_secrets);

    let assert_commit_connectors_e_1 = AssertCommit1ConnectorsE {
        connectors_e: connector_e1_commitment_public_keys
            .iter()
            .map(|x| ConnectorE::new(source_network, &operator_context.operator_public_key, x))
            .collect(),
    };
    let assert_commit_connectors_e_2 = AssertCommit2ConnectorsE {
        connectors_e: connector_e2_commitment_public_keys
            .iter()
            .map(|x| ConnectorE::new(source_network, &operator_context.operator_public_key, x))
            .collect(),
    };

    let connector_f_1 = ConnectorF1::new(source_network, &operator_context.operator_public_key);
    let connector_f_2 = ConnectorF2::new(source_network, &operator_context.operator_public_key);

    let assert_commit_connectors_f = AssertCommitConnectorsF {
        connector_f_1,
        connector_f_2,
    };

    let connector_c = ConnectorC::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &merge_to_connector_c_commits_public_key(
            &connector_e1_commitment_public_keys,
            &connector_e2_commitment_public_keys,
        ),
    );

    let connector_z = ConnectorZ::new(
        source_network,
        DEPOSITOR_EVM_ADDRESS,
        &depositor_context.depositor_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_0 = Connector0::new(source_network, &operator_context.n_of_n_taproot_public_key);

    let connector_1 = Connector1::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
        &HashMap::from([
            (
                CommitmentMessageId::Superblock,
                WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::Superblock]),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::SuperblockHash],
                ),
            ),
        ]),
    );
    let connector_2 = Connector2::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
        &HashMap::from([(
            CommitmentMessageId::StartTime,
            WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::StartTime]),
        )]),
    );
    let connector_3 = Connector3::new(source_network, &operator_context.operator_public_key);
    let connector_4 = Connector4::new(source_network, &operator_context.operator_public_key);
    let connector_5 = Connector5::new(source_network, &operator_context.n_of_n_taproot_public_key);
    let connector_6 = Connector6::new(
        source_network,
        &operator_context.operator_taproot_public_key,
        &HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdSourceNetwork],
                ),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzPublicKey::from(
                    &commitment_secrets[&CommitmentMessageId::PegOutTxIdDestinationNetwork],
                ),
            ),
        ]),
    );

    SetupConfig {
        client_0,
        client_1,
        depositor_context,
        operator_context,
        verifier_0_context,
        verifier_1_context,
        withdrawer_context,
        connector_a,
        connector_b,
        connector_c,
        connector_d,
        assert_commit_connectors_e_1,
        assert_commit_connectors_e_2,
        assert_commit_connectors_f,
        connector_z,
        connector_0,
        connector_1,
        connector_2,
        connector_3,
        connector_4,
        connector_5,
        connector_6,
        depositor_evm_address: DEPOSITOR_EVM_ADDRESS.to_string(),
        withdrawer_evm_address: WITHDRAWER_EVM_ADDRESS.to_string(),
        commitment_secrets,
    }
}

// Use fixed secrets for testing to ensure repeatable spending addresses.
fn get_test_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
    let mut commitment_map = HashMap::from([
        (
            CommitmentMessageId::PegOutTxIdSourceNetwork,
            generate_test_winternitz_secret(0, SOURCE_NETWORK_TXID_LENGTH),
        ),
        (
            CommitmentMessageId::PegOutTxIdDestinationNetwork,
            generate_test_winternitz_secret(1, DESTINATION_NETWORK_TXID_LENGTH),
        ),
        (
            CommitmentMessageId::StartTime,
            generate_test_winternitz_secret(2, START_TIME_MESSAGE_LENGTH),
        ),
        (
            CommitmentMessageId::Superblock,
            generate_test_winternitz_secret(3, SUPERBLOCK_MESSAGE_LENGTH),
        ),
        (
            CommitmentMessageId::SuperblockHash,
            generate_test_winternitz_secret(4, SUPERBLOCK_HASH_MESSAGE_LENGTH),
        ),
    ]);

    // maybe variable cache is more efficient
    let all_variables = BridgeAssigner::default().all_intermediate_variable();
    // split variable to different connectors

    for (v, size) in all_variables {
        commitment_map.insert(
            CommitmentMessageId::Groth16IntermediateValues((v, size)),
            WinternitzSecret::new(size),
        );
    }
    commitment_map
}

fn generate_test_winternitz_secret(index: u8, message_size: usize) -> WinternitzSecret {
    let parameters = Parameters::new((message_size * 2) as u32, 4);
    WinternitzSecret::from_string(
        &format!("b138982ce17ac813d505b5b40b665d404e9528{:02x}", index),
        &parameters,
    )
}
