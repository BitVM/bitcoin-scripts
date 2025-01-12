use bitcoin::{
    hashes::Hash,
    hex::{Case::Upper, DisplayHex},
    key::Keypair,
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Error, TxStatus};
use musig2::SecNonce;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter, Result as FmtResult},
};

use crate::{
    connectors::{
        connector_d::ConnectorD, connector_e::ConnectorE, connector_f_1::ConnectorF1,
        connector_f_2::ConnectorF2,
    },
    constants::{
        DESTINATION_NETWORK_TXID_LENGTH, SOURCE_NETWORK_TXID_LENGTH, START_TIME_MESSAGE_LENGTH,
    },
    superblock::{
        find_superblock, get_start_time_block_number, get_superblock_hash_message,
        get_superblock_message, SUPERBLOCK_HASH_MESSAGE_LENGTH, SUPERBLOCK_MESSAGE_LENGTH,
    },
    transactions::{
        assert_transactions::{
            assert_commit_1::AssertCommit1Transaction,
            assert_commit_2::AssertCommit2Transaction,
            assert_final::AssertFinalTransaction,
            assert_initial::AssertInitialTransaction,
            utils::{
                groth16_commitment_secrets_to_public_keys, merge_to_connector_c_commits_public_key,
                AssertCommit1ConnectorsE, AssertCommit2ConnectorsE, AssertCommitConnectorsF,
            },
        },
        pre_signed_musig2::PreSignedMusig2Transaction,
    },
};

use bitvm::chunker::{
    assigner::BridgeAssigner,
    common::BLAKE3_HASH_LENGTH,
    disprove_execution::{disprove_exec, RawProof},
};
use bitvm::signatures::signing_winternitz::{
    WinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs,
};

use super::{
    super::{
        client::chain::chain::PegOutEvent,
        connectors::{
            connector_0::Connector0, connector_1::Connector1, connector_2::Connector2,
            connector_3::Connector3, connector_4::Connector4, connector_5::Connector5,
            connector_6::Connector6, connector_a::ConnectorA, connector_b::ConnectorB,
            connector_c::ConnectorC,
        },
        contexts::{operator::OperatorContext, verifier::VerifierContext},
        transactions::{
            base::{
                validate_transaction, verify_public_nonces_for_tx, BaseTransaction, Input,
                InputWithScript,
            },
            challenge::ChallengeTransaction,
            disprove::DisproveTransaction,
            disprove_chain::DisproveChainTransaction,
            kick_off_1::KickOff1Transaction,
            kick_off_2::KickOff2Transaction,
            kick_off_timeout::KickOffTimeoutTransaction,
            peg_out::PegOutTransaction,
            peg_out_confirm::PegOutConfirmTransaction,
            pre_signed::PreSignedTransaction,
            start_time::StartTimeTransaction,
            start_time_timeout::StartTimeTimeoutTransaction,
            take_1::Take1Transaction,
            take_2::Take2Transaction,
        },
    },
    base::{
        broadcast_and_verify, get_block_height, verify_if_not_mined, BaseGraph, GraphId,
        GRAPH_VERSION,
    },
    peg_in::PegInGraph,
};

pub type PegOutId = GraphId;

pub enum PegOutWithdrawerStatus {
    PegOutNotStarted, // peg-out transaction not created yet
    PegOutWait,       // peg-out not confirmed yet, wait
    PegOutComplete,   // peg-out complete
}

impl Display for PegOutWithdrawerStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutWithdrawerStatus::PegOutNotStarted => {
                write!(f, "Peg-out available. Request peg-out?")
            }
            PegOutWithdrawerStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutWithdrawerStatus::PegOutComplete => write!(f, "Peg-out complete. Done."),
        }
    }
}

pub enum PegOutVerifierStatus {
    PegOutPresign,            // should presign peg-out graph
    PegOutComplete,           // peg-out complete
    PegOutWait,               // no action required, wait
    PegOutChallengeAvailable, // can call challenge
    PegOutStartTimeTimeoutAvailable,
    PegOutKickOffTimeoutAvailable,
    PegOutDisproveChainAvailable,
    PegOutDisproveAvailable,
    PegOutFailed, // timeouts or disproves executed
}

impl Display for PegOutVerifierStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutVerifierStatus::PegOutPresign => {
                write!(f, "Signatures required. Presign peg-out transactions?")
            }
            PegOutVerifierStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeded. Done.")
            }
            PegOutVerifierStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutVerifierStatus::PegOutChallengeAvailable => {
                write!(
                  f,
                  "Kick-off 1 transaction confirmed, dispute available. Broadcast challenge transaction?"
              )
            }
            PegOutVerifierStatus::PegOutStartTimeTimeoutAvailable => {
                write!(f, "Start time timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutKickOffTimeoutAvailable => {
                write!(f, "Kick-off 1 timed out. Broadcast timeout transaction?")
            }
            PegOutVerifierStatus::PegOutDisproveChainAvailable => {
                write!(
                    f,
                    "Kick-off 2 transaction confirmed. Broadcast disprove chain transaction?"
                )
            }
            PegOutVerifierStatus::PegOutDisproveAvailable => {
                write!(
                    f,
                    "Assert transaction confirmed. Broadcast disprove transaction?"
                )
            }
            PegOutVerifierStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
        }
    }
}

pub enum PegOutOperatorStatus {
    // TODO: add assert initial and assert final
    PegOutWait,
    PegOutComplete,    // peg-out complete
    PegOutFailed,      // timeouts or disproves executed
    PegOutStartPegOut, // should execute peg-out tx
    PegOutPegOutConfirmAvailable,
    PegOutKickOff1Available,
    PegOutStartTimeAvailable,
    PegOutKickOff2Available,
    PegOutAssertAvailable,
    PegOutTake1Available,
    PegOutTake2Available,
}

impl Display for PegOutOperatorStatus {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            PegOutOperatorStatus::PegOutWait => write!(f, "No action available. Wait..."),
            PegOutOperatorStatus::PegOutComplete => {
                write!(f, "Peg-out complete, reimbursement succeded. Done.")
            }
            PegOutOperatorStatus::PegOutFailed => {
                write!(f, "Peg-out complete, reimbursement failed. Done.")
            }
            PegOutOperatorStatus::PegOutStartPegOut => {
                write!(
                    f,
                    "Peg-out requested. Create and broadcast peg-out transaction?"
                )
            }
            PegOutOperatorStatus::PegOutPegOutConfirmAvailable => {
                write!(
                    f,
                    "Peg-out confirmed. Broadcast peg-out-confirm transaction?"
                )
            }
            PegOutOperatorStatus::PegOutKickOff1Available => {
                write!(
                    f,
                    "Peg-out-confirm confirmed. Broadcast kick-off 1 transaction?"
                )
            }
            PegOutOperatorStatus::PegOutStartTimeAvailable => {
                write!(f, "Kick-off confirmed. Broadcast start time transaction?")
            }
            PegOutOperatorStatus::PegOutKickOff2Available => {
                write!(f, "Start time confirmed. Broadcast kick-off 2 transaction?")
            }
            PegOutOperatorStatus::PegOutAssertAvailable => {
                write!(f, "Dispute raised. Broadcast assert transaction?")
            }
            PegOutOperatorStatus::PegOutTake1Available => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 1 transaction?"
            ),
            PegOutOperatorStatus::PegOutTake2Available => write!(
                f,
                "Dispute timed out, reimbursement available. Broadcast take 2 transaction?"
            ),
        }
    }
}

struct PegOutConnectors {
    connector_0: Connector0,
    connector_1: Connector1,
    connector_2: Connector2,
    connector_3: Connector3,
    connector_4: Connector4,
    connector_5: Connector5,
    connector_6: Connector6,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
    connector_c: ConnectorC,
    connector_d: ConnectorD,
    assert_commit_connectors_e_1: AssertCommit1ConnectorsE,
    assert_commit_connectors_e_2: AssertCommit2ConnectorsE,
    assert_commit_connectors_f: AssertCommitConnectorsF,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, PartialOrd, Ord, Debug)]
pub enum CommitmentMessageId {
    PegOutTxIdSourceNetwork,
    PegOutTxIdDestinationNetwork,
    StartTime,
    Superblock,
    SuperblockHash,
    // name of intermediate value and length of message
    Groth16IntermediateValues((String, usize)),
}

impl CommitmentMessageId {
    // btree map is a copy of chunker related commitments
    pub fn generate_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
        let mut commitment_map = HashMap::from([
            (
                CommitmentMessageId::PegOutTxIdSourceNetwork,
                WinternitzSecret::new(SOURCE_NETWORK_TXID_LENGTH),
            ),
            (
                CommitmentMessageId::PegOutTxIdDestinationNetwork,
                WinternitzSecret::new(DESTINATION_NETWORK_TXID_LENGTH),
            ),
            (
                CommitmentMessageId::StartTime,
                WinternitzSecret::new(START_TIME_MESSAGE_LENGTH),
            ),
            (
                CommitmentMessageId::Superblock,
                WinternitzSecret::new(SUPERBLOCK_MESSAGE_LENGTH),
            ),
            (
                CommitmentMessageId::SuperblockHash,
                WinternitzSecret::new(SUPERBLOCK_HASH_MESSAGE_LENGTH),
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
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct PegOutGraph {
    version: String,
    network: Network,
    id: String,

    // state: State,
    // n_of_n_pre_signing_state: PreSigningState,
    n_of_n_presigned: bool,
    n_of_n_public_key: PublicKey,
    n_of_n_taproot_public_key: XOnlyPublicKey,

    pub peg_in_graph_id: String,
    peg_in_confirm_txid: Txid,

    // Note that only the connectors that are used with message commitments are
    // required to be here. They carry the Winternitz public keys, which need
    // to be pushed to remote data store. The remaining connectors can be
    // constructed dynamically.
    connector_0: Connector0,
    connector_1: Connector1,
    connector_2: Connector2,
    connector_3: Connector3,
    connector_4: Connector4,
    connector_5: Connector5,
    connector_6: Connector6,
    connector_a: ConnectorA,
    connector_b: ConnectorB,
    connector_c: ConnectorC,
    connector_d: ConnectorD,
    connector_e_1: AssertCommit1ConnectorsE,
    connector_e_2: AssertCommit2ConnectorsE,
    connector_f_1: ConnectorF1,
    connector_f_2: ConnectorF2,

    peg_out_confirm_transaction: PegOutConfirmTransaction,
    assert_initial_transaction: AssertInitialTransaction,
    assert_final_transaction: AssertFinalTransaction,
    challenge_transaction: ChallengeTransaction,
    disprove_chain_transaction: DisproveChainTransaction,
    disprove_transaction: DisproveTransaction,
    kick_off_1_transaction: KickOff1Transaction,
    kick_off_2_transaction: KickOff2Transaction,
    kick_off_timeout_transaction: KickOffTimeoutTransaction,
    start_time_transaction: StartTimeTransaction,
    start_time_timeout_transaction: StartTimeTimeoutTransaction,
    take_1_transaction: Take1Transaction,
    take_2_transaction: Take2Transaction,

    operator_public_key: PublicKey,
    operator_taproot_public_key: XOnlyPublicKey,

    pub peg_out_chain_event: Option<PegOutEvent>,
    pub peg_out_transaction: Option<PegOutTransaction>,
}

impl BaseGraph for PegOutGraph {
    fn network(&self) -> Network { self.network }

    fn id(&self) -> &String { &self.id }

    fn verifier_sign(
        &mut self,
        verifier_context: &VerifierContext,
        secret_nonces: &HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        self.assert_initial_transaction.pre_sign(
            verifier_context,
            &self.connector_b,
            &secret_nonces[&self.assert_initial_transaction.tx().compute_txid()],
        );
        self.assert_final_transaction.pre_sign(
            verifier_context,
            &self.connector_d,
            &secret_nonces[&self.assert_final_transaction.tx().compute_txid()],
        );
        self.disprove_chain_transaction.pre_sign(
            verifier_context,
            &self.connector_b,
            &secret_nonces[&self.disprove_chain_transaction.tx().compute_txid()],
        );
        self.disprove_transaction.pre_sign(
            verifier_context,
            &self.connector_5,
            &secret_nonces[&self.disprove_transaction.tx().compute_txid()],
        );
        self.kick_off_timeout_transaction.pre_sign(
            verifier_context,
            &self.connector_1,
            &secret_nonces[&self.kick_off_timeout_transaction.tx().compute_txid()],
        );
        self.start_time_timeout_transaction.pre_sign(
            verifier_context,
            &self.connector_1,
            &self.connector_2,
            &secret_nonces[&self.start_time_timeout_transaction.tx().compute_txid()],
        );
        self.take_1_transaction.pre_sign(
            verifier_context,
            &self.connector_0,
            &self.connector_b,
            &secret_nonces[&self.take_1_transaction.tx().compute_txid()],
        );
        self.take_2_transaction.pre_sign(
            verifier_context,
            &self.connector_0,
            &self.connector_5,
            &secret_nonces[&self.take_2_transaction.tx().compute_txid()],
        );

        self.n_of_n_presigned = true; // TODO: set to true after collecting all n of n signatures
    }

    fn push_verifier_nonces(
        &mut self,
        verifier_context: &VerifierContext,
    ) -> HashMap<Txid, HashMap<usize, SecNonce>> {
        self.all_presigned_txs_mut()
            .map(|tx_wrapper| {
                (
                    tx_wrapper.tx().compute_txid(),
                    tx_wrapper.push_nonces(verifier_context),
                )
            })
            .collect()
    }
}

impl PegOutGraph {
    pub fn new(
        context: &OperatorContext,
        peg_in_graph: &PegInGraph,
        peg_out_confirm_input: Input,
    ) -> (Self, HashMap<CommitmentMessageId, WinternitzSecret>) {
        let peg_in_confirm_transaction = peg_in_graph.peg_in_confirm_transaction_ref();
        let peg_in_confirm_txid = peg_in_confirm_transaction.tx().compute_txid();

        let commitment_secrets = CommitmentMessageId::generate_commitment_secrets();
        let connector_1_commitment_public_keys = HashMap::from([
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
        ]);
        let connector_2_commitment_public_keys = HashMap::from([(
            CommitmentMessageId::StartTime,
            WinternitzPublicKey::from(&commitment_secrets[&CommitmentMessageId::StartTime]),
        )]);
        let connector_6_commitment_public_keys = HashMap::from([
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
        ]);

        let (connector_e1_commitment_public_keys, connector_e2_commitment_public_keys) =
            groth16_commitment_secrets_to_public_keys(&commitment_secrets);

        let connectors = Self::create_new_connectors(
            context.network,
            &context.n_of_n_taproot_public_key,
            &context.operator_taproot_public_key,
            &context.operator_public_key,
            &connector_1_commitment_public_keys,
            &connector_2_commitment_public_keys,
            &connector_6_commitment_public_keys,
            &connector_e1_commitment_public_keys,
            &connector_e2_commitment_public_keys,
        );

        let peg_out_confirm_transaction =
            PegOutConfirmTransaction::new(context, &connectors.connector_6, peg_out_confirm_input);
        let peg_out_confirm_txid = peg_out_confirm_transaction.tx().compute_txid();

        let kick_off_1_vout_0 = 0;
        let kick_off_1_transaction = KickOff1Transaction::new(
            context,
            &connectors.connector_1,
            &connectors.connector_2,
            &connectors.connector_6,
            Input {
                outpoint: OutPoint {
                    txid: peg_out_confirm_txid,
                    vout: kick_off_1_vout_0.to_u32().unwrap(),
                },
                amount: peg_out_confirm_transaction.tx().output[kick_off_1_vout_0].value,
            },
        );
        let kick_off_1_txid = kick_off_1_transaction.tx().compute_txid();

        let start_time_vout_0 = 2;
        let start_time_transaction = StartTimeTransaction::new(
            context,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_vout_0].value,
            },
        );

        let start_time_timeout_vout_0 = 2;
        let start_time_timeout_vout_1 = 1;
        let start_time_timeout_transaction = StartTimeTimeoutTransaction::new(
            context,
            &connectors.connector_1,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_1].value,
            },
        );

        let kick_off_2_vout_0 = 1;
        let kick_off_2_transaction = KickOff2Transaction::new(
            context,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_2_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_2_vout_0].value,
            },
        );
        let kick_off_2_txid = kick_off_2_transaction.tx().compute_txid();

        let kick_off_timeout_vout_0 = 1;
        let kick_off_timeout_transaction = KickOffTimeoutTransaction::new(
            context,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_timeout_vout_0].value,
            },
        );

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
        let challenge_vout_0 = 0;
        let challenge_transaction = ChallengeTransaction::new(
            context,
            &connectors.connector_a,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: challenge_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[challenge_vout_0].value,
            },
            input_amount_crowdfunding,
        );

        let take_1_vout_0 = 0;
        let take_1_vout_1 = 0;
        let take_1_vout_2 = 0;
        let take_1_vout_3 = 1;
        let take_1_transaction = Take1Transaction::new(
            context,
            &connectors.connector_0,
            &connectors.connector_3,
            &connectors.connector_a,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_1_vout_0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take_1_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: take_1_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[take_1_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_2.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_3.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_3].value,
            },
        );

        // assert initial
        let assert_initial_vout_0 = 1;
        let assert_initial_transaction = AssertInitialTransaction::new(
            &connectors.connector_b,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_e_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_initial_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_initial_vout_0].value,
            },
        );
        let assert_initial_txid = assert_initial_transaction.tx().compute_txid();

        // assert commit txs
        let mut vout_base = 1;
        let assert_commit1_transaction = AssertCommit1Transaction::new(
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_f.connector_f_1,
            (0..connectors.assert_commit_connectors_e_1.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        vout_base += connectors.assert_commit_connectors_e_1.connectors_num();

        let assert_commit2_transaction = AssertCommit2Transaction::new(
            &connectors.assert_commit_connectors_e_2,
            &connectors.assert_commit_connectors_f.connector_f_2,
            (0..connectors.assert_commit_connectors_e_2.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        // assert final
        let assert_final_vout_0 = 0;
        let assert_final_vout_1 = 0;
        let assert_final_vout_2 = 0;
        let assert_final_transaction = AssertFinalTransaction::new(
            context,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_f,
            Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: assert_final_vout_0.to_u32().unwrap(),
                },
                amount: assert_initial_transaction.tx().output[assert_final_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit1_transaction.tx().compute_txid(),
                    vout: assert_final_vout_1.to_u32().unwrap(),
                },
                amount: assert_commit1_transaction.tx().output[assert_final_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit2_transaction.tx().compute_txid(),
                    vout: assert_final_vout_2.to_u32().unwrap(),
                },
                amount: assert_commit2_transaction.tx().output[assert_final_vout_2].value,
            },
        );
        let assert_final_txid = assert_final_transaction.tx().compute_txid();

        let take_2_vout_0 = 0;
        let take_2_vout_1 = 0;
        let take_2_vout_2 = 1;
        let take_2_vout_3 = 2;
        let take_2_transaction = Take2Transaction::new(
            context,
            &connectors.connector_0,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_2_vout_0.to_u32().unwrap(),
                },
                amount: peg_in_confirm_transaction.tx().output[take_2_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new(
            context,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
        );

        let disprove_chain_vout_0 = 1;
        let disprove_chain_transaction = DisproveChainTransaction::new(
            context,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: disprove_chain_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[disprove_chain_vout_0].value,
            },
        );

        (
            PegOutGraph {
                version: GRAPH_VERSION.to_string(),
                network: context.network,
                id: generate_id(peg_in_graph, &context.operator_public_key),
                n_of_n_presigned: false,
                n_of_n_public_key: context.n_of_n_public_key,
                n_of_n_taproot_public_key: context.n_of_n_taproot_public_key,
                peg_in_graph_id: peg_in_graph.id().clone(),
                peg_in_confirm_txid,
                connector_0: connectors.connector_0,
                connector_1: connectors.connector_1,
                connector_2: connectors.connector_2,
                connector_3: connectors.connector_3,
                connector_4: connectors.connector_4,
                connector_5: connectors.connector_5,
                connector_6: connectors.connector_6,
                connector_a: connectors.connector_a,
                connector_b: connectors.connector_b,
                connector_c: connectors.connector_c,
                connector_d: connectors.connector_d,
                connector_e_1: connectors.assert_commit_connectors_e_1,
                connector_e_2: connectors.assert_commit_connectors_e_2,
                connector_f_1: connectors.assert_commit_connectors_f.connector_f_1,
                connector_f_2: connectors.assert_commit_connectors_f.connector_f_2,
                peg_out_confirm_transaction,
                assert_initial_transaction,
                assert_final_transaction,
                challenge_transaction,
                disprove_chain_transaction,
                disprove_transaction,
                kick_off_1_transaction,
                kick_off_2_transaction,
                kick_off_timeout_transaction,
                start_time_transaction,
                start_time_timeout_transaction,
                take_1_transaction,
                take_2_transaction,
                operator_public_key: context.operator_public_key,
                operator_taproot_public_key: context.operator_taproot_public_key,
                peg_out_chain_event: None,
                peg_out_transaction: None,
            },
            commitment_secrets,
        )
    }

    pub fn new_for_validation(&self) -> Self {
        let peg_in_confirm_txid = self.take_1_transaction.tx().input[0].previous_output.txid; // Self-referencing

        let connectors = Self::create_new_connectors(
            self.network,
            &self.n_of_n_taproot_public_key,
            &self.operator_taproot_public_key,
            &self.operator_public_key,
            &self.connector_1.commitment_public_keys,
            &self.connector_2.commitment_public_keys,
            &self.connector_6.commitment_public_keys,
            &self.connector_e_1.commitment_public_keys(),
            &self.connector_e_2.commitment_public_keys(),
        );

        let peg_out_confirm_vout_0 = 0;
        let peg_out_confirm_transaction = PegOutConfirmTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_6,
            Input {
                outpoint: self.peg_out_confirm_transaction.tx().input[peg_out_confirm_vout_0]
                    .previous_output, // Self-referencing
                amount: self.peg_out_confirm_transaction.prev_outs()[peg_out_confirm_vout_0].value, // Self-referencing
            },
        );

        let kick_off_1_vout_0 = 0;
        let kick_off_1_transaction = KickOff1Transaction::new_for_validation(
            self.network,
            &self.operator_taproot_public_key,
            &self.n_of_n_taproot_public_key,
            &connectors.connector_1,
            &connectors.connector_2,
            &connectors.connector_6,
            Input {
                outpoint: self.kick_off_1_transaction.tx().input[kick_off_1_vout_0].previous_output, // Self-referencing
                amount: self.kick_off_1_transaction.prev_outs()[kick_off_1_vout_0].value, // Self-referencing
            },
        );
        let kick_off_1_txid = kick_off_1_transaction.tx().compute_txid();

        let start_time_vout_0 = 2;
        let start_time_transaction = StartTimeTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_vout_0].value,
            },
        );

        let start_time_timeout_vout_0 = 2;
        let start_time_timeout_vout_1 = 1;
        let start_time_timeout_transaction = StartTimeTimeoutTransaction::new_for_validation(
            self.network,
            &connectors.connector_1,
            &connectors.connector_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: start_time_timeout_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[start_time_timeout_vout_1].value,
            },
        );

        let kick_off_2_vout_0 = 1;
        let kick_off_2_transaction = KickOff2Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.n_of_n_taproot_public_key,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_2_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_2_vout_0].value,
            },
        );
        let kick_off_2_txid = kick_off_2_transaction.tx().compute_txid();

        let kick_off_timeout_vout_0 = 1;
        let kick_off_timeout_transaction = KickOffTimeoutTransaction::new_for_validation(
            self.network,
            &connectors.connector_1,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: kick_off_timeout_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[kick_off_timeout_vout_0].value,
            },
        );

        let input_amount_crowdfunding = Amount::from_btc(1.0).unwrap(); // TODO replace placeholder
        let challenge_vout_0 = 0;
        let challenge_transaction = ChallengeTransaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &self.connector_a,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: challenge_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[challenge_vout_0].value,
            },
            input_amount_crowdfunding,
        );

        let take_1_vout_0 = 0;
        let take_1_vout_1 = 0;
        let take_1_vout_2 = 0;
        let take_1_vout_3 = 1;
        let take_1_transaction = Take1Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_0,
            &connectors.connector_3,
            &connectors.connector_a,
            &connectors.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_1_vout_0.to_u32().unwrap(),
                },
                amount: self.take_1_transaction.prev_outs()[take_1_vout_0].value, // Self-referencing
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_1_txid,
                    vout: take_1_vout_1.to_u32().unwrap(),
                },
                amount: kick_off_1_transaction.tx().output[take_1_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_2.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: take_1_vout_3.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[take_1_vout_3].value,
            },
        );

        // assert initial
        let assert_initial_vout_0 = 1;
        let assert_initial_transaction = AssertInitialTransaction::new_for_validation(
            &connectors.connector_b,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_e_2,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: assert_initial_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[assert_initial_vout_0].value,
            },
        );
        let assert_initial_txid = assert_initial_transaction.tx().compute_txid();

        // assert commit txs
        let mut vout_base = 1;
        let assert_commit_1_transaction = AssertCommit1Transaction::new_for_validation(
            &connectors.assert_commit_connectors_e_1,
            &connectors.assert_commit_connectors_f.connector_f_1,
            (0..connectors.assert_commit_connectors_e_1.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        vout_base += connectors.assert_commit_connectors_e_1.connectors_num();

        let assert_commit_2_transaction = AssertCommit2Transaction::new_for_validation(
            &connectors.assert_commit_connectors_e_2,
            &connectors.assert_commit_connectors_f.connector_f_2,
            (0..connectors.assert_commit_connectors_e_2.connectors_num())
                .map(|idx| Input {
                    outpoint: OutPoint {
                        txid: assert_initial_transaction.tx().compute_txid(),
                        vout: (idx + vout_base).to_u32().unwrap(),
                    },
                    amount: assert_initial_transaction.tx().output[idx + vout_base].value,
                })
                .collect(),
        );

        // assert final
        let assert_final_vout_0 = 0;
        let assert_final_vout_1 = 0;
        let assert_final_vout_2 = 0;
        let assert_final_vout_3 = 0;
        let assert_final_vout_4 = 0;
        let assert_final_vout_5 = 0;
        let assert_final_transaction = AssertFinalTransaction::new_for_validation(
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            &connectors.connector_d,
            &connectors.assert_commit_connectors_f,
            Input {
                outpoint: OutPoint {
                    txid: assert_initial_txid,
                    vout: assert_final_vout_0.to_u32().unwrap(),
                },
                amount: assert_initial_transaction.tx().output[assert_final_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_1_transaction.tx().compute_txid(),
                    vout: assert_final_vout_1.to_u32().unwrap(),
                },
                amount: assert_commit_1_transaction.tx().output[assert_final_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_commit_2_transaction.tx().compute_txid(),
                    vout: assert_final_vout_2.to_u32().unwrap(),
                },
                amount: assert_commit_2_transaction.tx().output[assert_final_vout_2].value,
            },
        );
        let assert_final_txid = assert_final_transaction.tx().compute_txid();

        let take_2_vout_0 = 0;
        let take_2_vout_1 = 0;
        let take_2_vout_2 = 1;
        let take_2_vout_3 = 2;
        let take_2_transaction = Take2Transaction::new_for_validation(
            self.network,
            &self.operator_public_key,
            &connectors.connector_0,
            &connectors.connector_4,
            &connectors.connector_5,
            &connectors.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: peg_in_confirm_txid,
                    vout: take_2_vout_0.to_u32().unwrap(),
                },
                amount: self.take_2_transaction.prev_outs()[take_2_vout_0].value, // Self-referencing
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_1].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_2.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_2].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: take_2_vout_3.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[take_2_vout_3].value,
            },
        );

        let script_index = 1; // TODO replace placeholder
        let disprove_vout_0 = 1;
        let disprove_vout_1 = 2;
        let disprove_transaction = DisproveTransaction::new_for_validation(
            self.network,
            &self.connector_5,
            &self.connector_c,
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_0.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_0].value,
            },
            Input {
                outpoint: OutPoint {
                    txid: assert_final_txid,
                    vout: disprove_vout_1.to_u32().unwrap(),
                },
                amount: assert_final_transaction.tx().output[disprove_vout_1].value,
            },
            script_index,
        );

        let disprove_chain_vout_0 = 1;
        let disprove_chain_transaction = DisproveChainTransaction::new_for_validation(
            self.network,
            &self.connector_b,
            Input {
                outpoint: OutPoint {
                    txid: kick_off_2_txid,
                    vout: disprove_chain_vout_0.to_u32().unwrap(),
                },
                amount: kick_off_2_transaction.tx().output[disprove_chain_vout_0].value,
            },
        );

        PegOutGraph {
            version: GRAPH_VERSION.to_string(),
            network: self.network,
            id: self.id.clone(),
            n_of_n_presigned: false,
            n_of_n_public_key: self.n_of_n_public_key,
            n_of_n_taproot_public_key: self.n_of_n_taproot_public_key,
            peg_in_graph_id: self.peg_in_graph_id.clone(),
            peg_in_confirm_txid,
            connector_0: connectors.connector_0,
            connector_1: connectors.connector_1,
            connector_2: connectors.connector_2,
            connector_3: connectors.connector_3,
            connector_4: connectors.connector_4,
            connector_5: connectors.connector_5,
            connector_6: connectors.connector_6,
            connector_a: connectors.connector_a,
            connector_b: connectors.connector_b,
            connector_c: connectors.connector_c,
            connector_d: connectors.connector_d,
            connector_e_1: connectors.assert_commit_connectors_e_1,
            connector_e_2: connectors.assert_commit_connectors_e_2,
            connector_f_1: connectors.assert_commit_connectors_f.connector_f_1,
            connector_f_2: connectors.assert_commit_connectors_f.connector_f_2,
            peg_out_confirm_transaction,
            assert_initial_transaction,
            assert_final_transaction,
            challenge_transaction,
            disprove_chain_transaction,
            disprove_transaction,
            kick_off_1_transaction,
            kick_off_2_transaction,
            kick_off_timeout_transaction,
            start_time_transaction,
            start_time_timeout_transaction,
            take_1_transaction,
            take_2_transaction,
            operator_public_key: self.operator_public_key,
            operator_taproot_public_key: self.operator_taproot_public_key,
            peg_out_chain_event: None,
            peg_out_transaction: None,
        }
    }

    pub async fn verifier_status(&self, client: &AsyncClient) -> PegOutVerifierStatus {
        if self.n_of_n_presigned {
            let (
                assert_initial_status,
                assert_final_status,
                challenge_status,
                disprove_chain_status,
                disprove_status,
                _,
                kick_off_1_status,
                kick_off_2_status,
                kick_off_timeout_status,
                _,
                start_time_timeout_status,
                start_time_status,
                take_1_status,
                take_2_status,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = get_block_height(client).await;

            if kick_off_2_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if take_1_status.as_ref().is_ok_and(|status| status.confirmed)
                    || take_2_status.as_ref().is_ok_and(|status| status.confirmed)
                {
                    PegOutVerifierStatus::PegOutComplete
                } else if disprove_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                    || disprove_chain_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                } else if assert_final_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutDisproveAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutDisproveChainAvailable;
                }
            } else if kick_off_1_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            {
                if start_time_timeout_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                    || kick_off_timeout_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutFailed; // TODO: can be also `PegOutVerifierStatus::PegOutComplete`
                } else if start_time_status
                    .as_ref()
                    .is_ok_and(|status| !status.confirmed)
                {
                    if kick_off_1_status
                        .as_ref()
                        .unwrap()
                        .block_height
                        .is_some_and(|block_height| {
                            block_height + self.connector_1.num_blocks_timelock_leaf_2
                                > blockchain_height
                        })
                    {
                        return PegOutVerifierStatus::PegOutStartTimeTimeoutAvailable;
                    } else {
                        return PegOutVerifierStatus::PegOutWait;
                    }
                } else if kick_off_1_status
                    .as_ref()
                    .unwrap()
                    .block_height
                    .is_some_and(|block_height| {
                        block_height + self.connector_1.num_blocks_timelock_leaf_1
                            > blockchain_height
                    })
                {
                    return PegOutVerifierStatus::PegOutKickOffTimeoutAvailable;
                } else if challenge_status
                    .as_ref()
                    .is_ok_and(|status| !status.confirmed)
                {
                    return PegOutVerifierStatus::PegOutChallengeAvailable;
                } else {
                    return PegOutVerifierStatus::PegOutWait;
                }
            } else {
                return PegOutVerifierStatus::PegOutWait;
            }
        } else {
            PegOutVerifierStatus::PegOutPresign
        }
    }

    pub async fn operator_status(&self, client: &AsyncClient) -> PegOutOperatorStatus {
        if self.n_of_n_presigned && self.is_peg_out_initiated() {
            let (
                assert_initial_status,
                assert_final_status,
                challenge_status,
                disprove_chain_status,
                disprove_status,
                peg_out_confirm_status,
                kick_off_1_status,
                kick_off_2_status,
                kick_off_timeout_status,
                peg_out_status,
                start_time_timeout_status,
                start_time_status,
                take_1_status,
                take_2_status,
            ) = Self::get_peg_out_statuses(self, client).await;
            let blockchain_height = get_block_height(client).await;

            if peg_out_status.is_some_and(|status| status.unwrap().confirmed) {
                if kick_off_2_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    if take_1_status.as_ref().is_ok_and(|status| status.confirmed)
                        || take_2_status.as_ref().is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutComplete;
                    } else if disprove_chain_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                        || disprove_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also `PegOutOperatorStatus::PegOutComplete`
                    } else if challenge_status.is_ok_and(|status| status.confirmed) {
                        if assert_final_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                        {
                            if assert_final_status
                                .as_ref()
                                .unwrap()
                                .block_height
                                .is_some_and(|block_height| {
                                    block_height + self.connector_4.num_blocks_timelock
                                        <= blockchain_height
                                })
                            {
                                return PegOutOperatorStatus::PegOutTake2Available;
                            } else {
                                return PegOutOperatorStatus::PegOutWait;
                            }
                        } else if kick_off_2_status
                            .as_ref()
                            .unwrap()
                            .block_height
                            .is_some_and(|block_height| {
                                block_height + self.connector_b.num_blocks_timelock_1
                                    <= blockchain_height
                            })
                        {
                            return PegOutOperatorStatus::PegOutAssertAvailable;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    } else if kick_off_2_status
                        .as_ref()
                        .unwrap()
                        .block_height
                        .is_some_and(|block_height| {
                            block_height + self.connector_3.num_blocks_timelock <= blockchain_height
                        })
                    {
                        return PegOutOperatorStatus::PegOutTake1Available;
                    } else {
                        return PegOutOperatorStatus::PegOutWait;
                    }
                } else if kick_off_1_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    if start_time_timeout_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                        || kick_off_timeout_status
                            .as_ref()
                            .is_ok_and(|status| status.confirmed)
                    {
                        return PegOutOperatorStatus::PegOutFailed; // TODO: can be also `PegOutOperatorStatus::PegOutComplete`
                    } else if start_time_status
                        .as_ref()
                        .is_ok_and(|status| status.confirmed)
                    {
                        if kick_off_1_status
                            .as_ref()
                            .unwrap()
                            .block_height
                            .is_some_and(|block_height| {
                                block_height + self.connector_1.num_blocks_timelock_leaf_0
                                    <= blockchain_height
                            })
                        {
                            return PegOutOperatorStatus::PegOutKickOff2Available;
                        } else {
                            return PegOutOperatorStatus::PegOutWait;
                        }
                    } else {
                        return PegOutOperatorStatus::PegOutStartTimeAvailable;
                    }
                } else if peg_out_confirm_status
                    .as_ref()
                    .is_ok_and(|status| status.confirmed)
                {
                    return PegOutOperatorStatus::PegOutKickOff1Available;
                } else {
                    return PegOutOperatorStatus::PegOutPegOutConfirmAvailable;
                }
            } else {
                return PegOutOperatorStatus::PegOutStartPegOut;
            }
        }

        PegOutOperatorStatus::PegOutWait
    }

    pub fn interpret_withdrawer_status(
        &self,
        peg_out_status: Option<&Result<TxStatus, Error>>,
    ) -> PegOutWithdrawerStatus {
        if let Some(peg_out_status) = peg_out_status {
            if peg_out_status.as_ref().is_ok_and(|status| status.confirmed) {
                PegOutWithdrawerStatus::PegOutComplete
            } else {
                PegOutWithdrawerStatus::PegOutWait
            }
        } else {
            PegOutWithdrawerStatus::PegOutNotStarted
        }
    }

    pub async fn withdrawer_status(&self, client: &AsyncClient) -> PegOutWithdrawerStatus {
        let peg_out_status = match self.peg_out_transaction {
            Some(_) => {
                let peg_out_txid = self
                    .peg_out_transaction
                    .as_ref()
                    .unwrap()
                    .tx()
                    .compute_txid();
                let peg_out_status = client.get_tx_status(&peg_out_txid).await;
                Some(peg_out_status)
            }
            None => None,
        };
        self.interpret_withdrawer_status(peg_out_status.as_ref())
    }

    pub async fn peg_out(&mut self, client: &AsyncClient, context: &OperatorContext, input: Input) {
        if !self.is_peg_out_initiated() {
            panic!("Peg out not initiated on L2 chain");
        }

        if self.peg_out_transaction.is_some() {
            let txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            verify_if_not_mined(client, txid).await;
        } else {
            let event = self.peg_out_chain_event.as_ref().unwrap();
            let tx = PegOutTransaction::new(context, event, input);
            self.peg_out_transaction = Some(tx);
        }

        let peg_out_tx = self.peg_out_transaction.as_ref().unwrap().finalize();

        broadcast_and_verify(client, &peg_out_tx).await;
    }

    pub async fn peg_out_confirm(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.peg_out_confirm_transaction.tx().compute_txid()).await;

        if self.peg_out_transaction.as_ref().is_some() {
            let peg_out_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid();
            let peg_out_status = client.get_tx_status(&peg_out_txid).await;

            if peg_out_status.is_ok_and(|status| status.confirmed) {
                // complete peg-out-confirm tx
                let peg_out_confirm_tx = self.peg_out_confirm_transaction.finalize();

                // broadcast peg-out-confirm tx
                broadcast_and_verify(client, &peg_out_confirm_tx).await;
            } else {
                panic!("Peg-out tx has not been confirmed!");
            }
        } else {
            panic!("Peg-out tx has not been created!");
        }
    }

    pub async fn kick_off_1(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        source_network_txid_commitment_secret: &WinternitzSecret,
        destination_network_txid_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(client, self.kick_off_1_transaction.tx().compute_txid()).await;

        let peg_out_confirm_txid = self.peg_out_confirm_transaction.tx().compute_txid();
        let peg_out_confirm_status = client.get_tx_status(&peg_out_confirm_txid).await;

        if peg_out_confirm_status.is_ok_and(|status| status.confirmed) {
            // complete kick-off 1 tx
            let pegout_txid = self
                .peg_out_transaction
                .as_ref()
                .unwrap()
                .tx()
                .compute_txid()
                .as_byte_array()
                .to_owned();
            let source_network_txid_inputs = WinternitzSigningInputs {
                message: &pegout_txid,
                signing_key: source_network_txid_commitment_secret,
            };
            let destination_network_txid_inputs = WinternitzSigningInputs {
                message: self
                    .peg_out_chain_event
                    .as_ref()
                    .unwrap()
                    .tx_hash
                    .as_slice(),
                signing_key: destination_network_txid_commitment_secret,
            };
            self.kick_off_1_transaction.sign(
                context,
                &self.connector_6,
                &source_network_txid_inputs,
                &destination_network_txid_inputs,
            );
            let kick_off_1_tx = self.kick_off_1_transaction.finalize();

            // broadcast kick-off 1 tx
            broadcast_and_verify(client, &kick_off_1_tx).await;
        } else {
            panic!("Peg-out-confirm tx has not been confirmed!");
        }
    }

    pub async fn challenge(
        &mut self,
        client: &AsyncClient,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        keypair: &Keypair,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        if kick_off_1_status.is_ok_and(|status| status.confirmed) {
            // complete challenge tx
            self.challenge_transaction.add_inputs_and_output(
                crowdfundng_inputs,
                keypair,
                output_script_pubkey,
            );
            let challenge_tx = self.challenge_transaction.finalize();

            // broadcast challenge tx
            broadcast_and_verify(client, &challenge_tx).await;
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn start_time(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        start_time_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(client, self.start_time_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        if kick_off_1_status.is_ok_and(|status| status.confirmed) {
            // sign start time tx
            self.start_time_transaction.sign(
                context,
                &self.connector_2,
                get_start_time_block_number(),
                start_time_commitment_secret,
            );

            // complete start time tx
            let start_time_tx = self.start_time_transaction.finalize();

            // broadcast start time tx
            broadcast_and_verify(client, &start_time_tx).await;
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn start_time_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(
            client,
            self.start_time_timeout_transaction.tx().compute_txid(),
        )
        .await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_2 <= blockchain_height
                })
            {
                // complete start time timeout tx
                self.start_time_timeout_transaction
                    .add_output(output_script_pubkey);
                let start_time_timeout_tx = self.start_time_timeout_transaction.finalize();

                // broadcast start time timeout tx
                broadcast_and_verify(client, &start_time_timeout_tx).await;
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn kick_off_2(
        &mut self,
        client: &AsyncClient,
        context: &OperatorContext,
        superblock_commitment_secret: &WinternitzSecret,
        superblock_hash_commitment_secret: &WinternitzSecret,
    ) {
        verify_if_not_mined(client, self.kick_off_2_transaction.tx().compute_txid()).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_0 <= blockchain_height
                })
            {
                // complete kick-off 2 tx
                let superblock_header = find_superblock();
                self.kick_off_2_transaction.sign(
                    context,
                    &self.connector_1,
                    &WinternitzSigningInputs {
                        message: &get_superblock_message(&superblock_header),
                        signing_key: superblock_commitment_secret,
                    },
                    &WinternitzSigningInputs {
                        message: &get_superblock_hash_message(&superblock_header),
                        signing_key: superblock_hash_commitment_secret,
                    },
                );
                let kick_off_2_tx = self.kick_off_2_transaction.finalize();

                // broadcast kick-off 2 tx
                broadcast_and_verify(client, &kick_off_2_tx).await;
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn kick_off_timeout(
        &mut self,
        client: &AsyncClient,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(
            client,
            self.kick_off_timeout_transaction.tx().compute_txid(),
        )
        .await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_1_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_1_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_1.num_blocks_timelock_leaf_1 <= blockchain_height
                })
            {
                // complete kick-off timeout tx
                let kick_off_timeout_tx = self.kick_off_timeout_transaction.finalize();

                // broadcast kick-off timeout tx
                self.kick_off_timeout_transaction
                    .add_output(output_script_pubkey);
                broadcast_and_verify(client, &kick_off_timeout_tx).await;
            } else {
                panic!("Kick-off 1 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 1 tx has not been confirmed!");
        }
    }

    pub async fn assert_initial(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.assert_initial_transaction.tx().compute_txid()).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = get_block_height(client).await;

        if kick_off_2_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            if kick_off_2_status
                .as_ref()
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_b.num_blocks_timelock_1 <= blockchain_height
                })
            {
                // complete assert initial tx
                let assert_initial_tx = self.assert_initial_transaction.finalize();

                // broadcast assert initial tx
                broadcast_and_verify(client, &assert_initial_tx).await;
            } else {
                panic!("Kick-off 2 timelock has not elapsed!");
            }
        } else {
            panic!("Kick-off 2 tx has not been confirmed!");
        }
    }

    pub async fn assert_final(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.assert_final_transaction.tx().compute_txid()).await;

        let assert_initial_txid = self.assert_initial_transaction.tx().compute_txid();
        let assert_initial_status = client.get_tx_status(&assert_initial_txid).await;

        if assert_initial_status
            .as_ref()
            .is_ok_and(|status| status.confirmed)
        {
            // complete assert final tx
            let assert_final_tx = self.assert_final_transaction.finalize();

            // broadcast assert final tx
            broadcast_and_verify(client, &assert_final_tx).await;
        } else {
            panic!("Assert-initial tx has not been confirmed!");
        }
    }

    pub async fn disprove(
        &mut self,
        client: &AsyncClient,
        input_script_index: u32,
        output_script_pubkey: ScriptBuf,
    ) {
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let assert_final_txid = self.assert_final_transaction.tx().compute_txid();
        let assert_final_status = client.get_tx_status(&assert_final_txid).await;

        if assert_final_status.is_ok_and(|status| status.confirmed) {
            // decide if broadcast disprove instead of unwrap directly.
            // TODO: store and read vk
            // TODO: get commit transaction witness from network?
            let (input_script_index, disprove_witness) = self
                .connector_c
                .generate_disprove_witness(vec![], vec![], RawProof::default().vk)
                .unwrap();

            // complete disprove tx
            self.disprove_transaction.add_input_output(
                &self.connector_c,
                input_script_index as u32,
                disprove_witness,
                output_script_pubkey,
            );
            let disprove_tx = self.disprove_transaction.finalize();

            // broadcast disprove tx
            broadcast_and_verify(client, &disprove_tx).await;
        } else {
            panic!("Assert tx has not been confirmed!");
        }
    }

    pub async fn disprove_chain(&mut self, client: &AsyncClient, output_script_pubkey: ScriptBuf) {
        verify_if_not_mined(client, self.disprove_chain_transaction.tx().compute_txid()).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        if kick_off_2_status.is_ok_and(|status| status.confirmed) {
            // complete disprove chain tx
            self.disprove_chain_transaction
                .add_output(output_script_pubkey);
            let disprove_chain_tx = self.disprove_chain_transaction.finalize();

            // broadcast disprove chain tx
            broadcast_and_verify(client, &disprove_chain_tx).await;
        } else {
            panic!("Kick-off 2 tx has not been confirmed!");
        }
    }

    pub async fn take_1(&mut self, client: &AsyncClient) {
        verify_if_not_mined(client, self.take_1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.challenge_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.assert_final_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.disprove_chain_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let kick_off_1_txid = self.kick_off_1_transaction.tx().compute_txid();
        let kick_off_1_status = client.get_tx_status(&kick_off_1_txid).await;

        let kick_off_2_txid = self.kick_off_2_transaction.tx().compute_txid();
        let kick_off_2_status = client.get_tx_status(&kick_off_2_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && kick_off_1_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
            && kick_off_2_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
        {
            if kick_off_2_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_3.num_blocks_timelock <= blockchain_height
                })
            {
                // complete take 1 tx
                let take_1_tx = self.take_1_transaction.finalize();

                // broadcast take 1 tx
                broadcast_and_verify(client, &take_1_tx).await;
            } else {
                panic!("Kick-off 2 tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx, kick-off 1 and kick-off 2 tx have not been confirmed!");
        }
    }

    pub async fn take_2(&mut self, client: &AsyncClient, context: &OperatorContext) {
        verify_if_not_mined(client, self.take_2_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.take_1_transaction.tx().compute_txid()).await;
        verify_if_not_mined(client, self.disprove_transaction.tx().compute_txid()).await;

        let peg_in_confirm_status = client.get_tx_status(&self.peg_in_confirm_txid).await;

        let assert_final_txid = self.assert_final_transaction.tx().compute_txid();
        let assert_final_status = client.get_tx_status(&assert_final_txid).await;

        let blockchain_height = get_block_height(client).await;

        if peg_in_confirm_status.is_ok_and(|status| status.confirmed)
            && assert_final_status
                .as_ref()
                .is_ok_and(|status| status.confirmed)
        {
            if assert_final_status
                .unwrap()
                .block_height
                .is_some_and(|block_height| {
                    block_height + self.connector_4.num_blocks_timelock <= blockchain_height
                })
            {
                // complete take 2 tx
                self.take_2_transaction.sign(context, &self.connector_c);
                let take_2_tx = self.take_2_transaction.finalize();

                // broadcast take 2 tx
                broadcast_and_verify(client, &take_2_tx).await;
            } else {
                panic!("Assert tx timelock has not elapsed!");
            }
        } else {
            panic!("Peg-in confirm tx and assert tx have not been confirmed!");
        }
    }

    pub fn is_peg_out_initiated(&self) -> bool { self.peg_out_chain_event.is_some() }

    pub async fn match_and_set_peg_out_event(
        &mut self,
        all_events: &mut Vec<PegOutEvent>,
    ) -> Result<Option<PegOutEvent>, String> {
        let mut events: Vec<PegOutEvent> = Vec::new();
        let mut ids: Vec<usize> = Vec::new();
        for (i, event) in all_events.iter().enumerate() {
            if self.peg_in_confirm_txid.eq(&event.source_outpoint.txid)
                && self.operator_public_key.eq(&event.operator_public_key)
            {
                events.push(event.clone());
                ids.push(i);
            }
        }
        ids.iter().for_each(|x| {
            all_events.swap_remove(*x);
        });

        match events.len() {
            0 => Ok(None),
            1 => {
                self.peg_out_chain_event = Some(events[0].clone());
                Ok(Some(events[0].clone()))
            }
            _ => Err(String::from("Event from L2 chain is not unique")),
        }
    }

    async fn get_peg_out_statuses(
        &self,
        client: &AsyncClient,
    ) -> (
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Option<Result<TxStatus, Error>>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
        Result<TxStatus, Error>,
    ) {
        let assert_initial_status = client
            .get_tx_status(&self.assert_initial_transaction.tx().compute_txid())
            .await;

        let assert_final_status = client
            .get_tx_status(&self.assert_final_transaction.tx().compute_txid())
            .await;

        let challenge_status = client
            .get_tx_status(&self.challenge_transaction.tx().compute_txid())
            .await;

        let disprove_chain_status = client
            .get_tx_status(&self.disprove_chain_transaction.tx().compute_txid())
            .await;

        let disprove_status = client
            .get_tx_status(&self.disprove_transaction.tx().compute_txid())
            .await;

        let peg_out_confirm_status = client
            .get_tx_status(&self.peg_out_confirm_transaction.tx().compute_txid())
            .await;

        let kick_off_1_status = client
            .get_tx_status(&self.kick_off_1_transaction.tx().compute_txid())
            .await;

        let kick_off_2_status = client
            .get_tx_status(&self.kick_off_2_transaction.tx().compute_txid())
            .await;

        let kick_off_timeout_status = client
            .get_tx_status(&self.kick_off_timeout_transaction.tx().compute_txid())
            .await;

        let mut peg_out_status: Option<Result<TxStatus, Error>> = None;
        if self.peg_out_transaction.is_some() {
            peg_out_status = Some(
                client
                    .get_tx_status(
                        &self
                            .peg_out_transaction
                            .as_ref()
                            .unwrap()
                            .tx()
                            .compute_txid(),
                    )
                    .await,
            );
        }

        let start_time_timeout_status = client
            .get_tx_status(&self.start_time_timeout_transaction.tx().compute_txid())
            .await;

        let start_time_status = client
            .get_tx_status(&self.start_time_transaction.tx().compute_txid())
            .await;

        let take_1_status = client
            .get_tx_status(&self.take_1_transaction.tx().compute_txid())
            .await;

        let take_2_status = client
            .get_tx_status(&self.take_2_transaction.tx().compute_txid())
            .await;

        (
            assert_initial_status,
            assert_final_status,
            challenge_status,
            disprove_chain_status,
            disprove_status,
            peg_out_confirm_status,
            kick_off_1_status,
            kick_off_2_status,
            kick_off_timeout_status,
            peg_out_status,
            start_time_timeout_status,
            start_time_status,
            take_1_status,
            take_2_status,
        )
    }

    pub fn validate(&self) -> bool {
        let mut ret_val = true;
        let peg_out_graph = self.new_for_validation();
        if !validate_transaction(
            self.assert_initial_transaction.tx(),
            peg_out_graph.assert_initial_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.assert_final_transaction.tx(),
            peg_out_graph.assert_final_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.challenge_transaction.tx(),
            peg_out_graph.challenge_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.disprove_chain_transaction.tx(),
            peg_out_graph.disprove_chain_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.disprove_transaction.tx(),
            peg_out_graph.disprove_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.peg_out_confirm_transaction.tx(),
            peg_out_graph.peg_out_confirm_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_1_transaction.tx(),
            peg_out_graph.kick_off_1_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_2_transaction.tx(),
            peg_out_graph.kick_off_2_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.kick_off_timeout_transaction.tx(),
            peg_out_graph.kick_off_timeout_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.start_time_transaction.tx(),
            peg_out_graph.start_time_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.start_time_timeout_transaction.tx(),
            peg_out_graph.start_time_timeout_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.take_1_transaction.tx(),
            peg_out_graph.take_1_transaction.tx(),
        ) {
            ret_val = false;
        }
        if !validate_transaction(
            self.take_2_transaction.tx(),
            peg_out_graph.take_2_transaction.tx(),
        ) {
            ret_val = false;
        }

        if !verify_public_nonces_for_tx(&self.assert_initial_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.assert_final_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.disprove_chain_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.disprove_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.kick_off_timeout_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.start_time_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.start_time_timeout_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.take_1_transaction) {
            ret_val = false;
        }
        if !verify_public_nonces_for_tx(&self.take_2_transaction) {
            ret_val = false;
        }

        ret_val
    }

    pub fn merge(&mut self, source_peg_out_graph: &PegOutGraph) {
        self.assert_initial_transaction
            .merge(&source_peg_out_graph.assert_initial_transaction);

        self.assert_final_transaction
            .merge(&source_peg_out_graph.assert_final_transaction);

        self.challenge_transaction
            .merge(&source_peg_out_graph.challenge_transaction);

        self.disprove_chain_transaction
            .merge(&source_peg_out_graph.disprove_chain_transaction);

        self.disprove_transaction
            .merge(&source_peg_out_graph.disprove_transaction);

        self.kick_off_timeout_transaction
            .merge(&source_peg_out_graph.kick_off_timeout_transaction);

        self.start_time_transaction
            .merge(&source_peg_out_graph.start_time_transaction);

        self.start_time_timeout_transaction
            .merge(&source_peg_out_graph.start_time_timeout_transaction);

        self.take_1_transaction
            .merge(&source_peg_out_graph.take_1_transaction);

        self.take_2_transaction
            .merge(&source_peg_out_graph.take_2_transaction);
    }

    fn create_new_connectors(
        network: Network,
        n_of_n_taproot_public_key: &XOnlyPublicKey,
        operator_taproot_public_key: &XOnlyPublicKey,
        operator_public_key: &PublicKey,
        connector_1_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_2_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_6_commitment_public_keys: &HashMap<CommitmentMessageId, WinternitzPublicKey>,
        connector_e1_commitment_public_keys: &Vec<
            BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
        >,
        connector_e2_commitment_public_keys: &Vec<
            BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
        >,
    ) -> PegOutConnectors {
        let connector_0 = Connector0::new(network, n_of_n_taproot_public_key);
        let connector_1 = Connector1::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
            connector_1_commitment_public_keys,
        );
        let connector_2 = Connector2::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
            connector_2_commitment_public_keys,
        );
        let connector_3 = Connector3::new(network, operator_public_key);
        let connector_4 = Connector4::new(network, operator_public_key);
        let connector_5 = Connector5::new(network, n_of_n_taproot_public_key);
        let connector_6 = Connector6::new(
            network,
            operator_taproot_public_key,
            connector_6_commitment_public_keys,
        );
        let connector_a = ConnectorA::new(
            network,
            operator_taproot_public_key,
            n_of_n_taproot_public_key,
        );
        let connector_b = ConnectorB::new(network, n_of_n_taproot_public_key);

        // connector c pks = connector e1 pks + connector e2 pks
        let connector_c = ConnectorC::new(
            network,
            operator_taproot_public_key,
            &merge_to_connector_c_commits_public_key(
                connector_e1_commitment_public_keys,
                connector_e2_commitment_public_keys,
            ),
        );
        let connector_d = ConnectorD::new(network, n_of_n_taproot_public_key);

        let assert_commit_connectors_e_1 = AssertCommit1ConnectorsE {
            connectors_e: connector_e1_commitment_public_keys
                .iter()
                .map(|x| ConnectorE::new(network, operator_public_key, x))
                .collect(),
        };
        let assert_commit_connectors_e_2 = AssertCommit2ConnectorsE {
            connectors_e: connector_e2_commitment_public_keys
                .iter()
                .map(|x| ConnectorE::new(network, operator_public_key, x))
                .collect(),
        };

        let connector_f_1 = ConnectorF1::new(network, operator_public_key);
        let connector_f_2 = ConnectorF2::new(network, operator_public_key);

        PegOutConnectors {
            connector_0,
            connector_1,
            connector_2,
            connector_3,
            connector_4,
            connector_5,
            connector_6,
            connector_a,
            connector_b,
            connector_c,
            connector_d,
            assert_commit_connectors_e_1,
            assert_commit_connectors_e_2,
            assert_commit_connectors_f: AssertCommitConnectorsF {
                connector_f_1,
                connector_f_2,
            },
        }
    }

    fn all_presigned_txs(&self) -> impl Iterator<Item = &dyn PreSignedMusig2Transaction> {
        let all_txs: Vec<&dyn PreSignedMusig2Transaction> = vec![
            &self.assert_initial_transaction,
            &self.assert_final_transaction,
            &self.disprove_chain_transaction,
            &self.disprove_transaction,
            &self.kick_off_timeout_transaction,
            &self.start_time_timeout_transaction,
            &self.take_1_transaction,
            &self.take_2_transaction,
        ];
        all_txs.into_iter()
    }

    fn all_presigned_txs_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut dyn PreSignedMusig2Transaction> {
        let all_txs: Vec<&mut dyn PreSignedMusig2Transaction> = vec![
            &mut self.assert_initial_transaction,
            &mut self.assert_final_transaction,
            &mut self.disprove_chain_transaction,
            &mut self.disprove_transaction,
            &mut self.kick_off_timeout_transaction,
            &mut self.start_time_timeout_transaction,
            &mut self.take_1_transaction,
            &mut self.take_2_transaction,
        ];
        all_txs.into_iter()
    }

    pub fn has_all_nonces_of(&self, context: &VerifierContext) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_nonces_for(context.verifier_public_key))
    }
    pub fn has_all_nonces(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_all_nonces(verifier_pubkeys))
    }
    pub fn has_all_signatures_of(&self, context: &VerifierContext) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_signatures_for(context.verifier_public_key))
    }
    pub fn has_all_signatures(&self, verifier_pubkeys: &[PublicKey]) -> bool {
        self.all_presigned_txs()
            .all(|x| x.has_all_signatures(verifier_pubkeys))
    }
}

pub fn generate_id(peg_in_graph: &PegInGraph, operator_public_key: &PublicKey) -> String {
    let mut hasher = Sha256::new();

    hasher.update(peg_in_graph.id().to_string() + &operator_public_key.to_string());

    hasher.finalize().to_hex_string(Upper)
}
