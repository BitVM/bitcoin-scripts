#![allow(clippy::too_many_arguments)]
use futures::future::join_all;
use musig2::SecNonce;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self},
    path::Path,
};

use bitcoin::{
    absolute::Height, consensus::encode::serialize_hex, Address, Amount, Network, OutPoint,
    PublicKey, ScriptBuf, Txid, XOnlyPublicKey,
};
use esplora_client::{AsyncClient, Builder, TxStatus, Utxo};

use crate::{
    constants::DestinationNetwork,
    contexts::base::generate_n_of_n_public_key,
    graphs::{
        base::{get_tx_statuses, GraphId},
        peg_in::{PegInDepositorStatus, PegInVerifierStatus},
        peg_out::{CommitmentMessageId, PegOutOperatorStatus},
    },
    scripts::generate_pay_to_pubkey_script_address,
};

use bitvm::signatures::signing_winternitz::WinternitzSecret;

use super::{
    super::{
        contexts::{
            depositor::DepositorContext, operator::OperatorContext, verifier::VerifierContext,
            withdrawer::WithdrawerContext,
        },
        graphs::{
            base::BaseGraph,
            peg_in::{generate_id as peg_in_generate_id, PegInGraph},
            peg_out::{generate_id as peg_out_generate_id, PegOutGraph},
        },
        serialization::{serialize, try_deserialize},
        transactions::{
            base::{Input, InputWithScript},
            pre_signed::PreSignedTransaction,
        },
    },
    chain::chain::Chain,
    data_store::data_store::DataStore,
    sdk::{
        query::{ClientCliQuery, GraphCliQuery},
        query_contexts::depositor_signatures::DepositorSignatures,
    },
};

// const ESPLORA_URL: &str = "https://mutinynet.com/api";
const ESPLORA_URL: &str = "http://localhost:8094/regtest/api/";
// const ESPLORA_URL: &str = "https://esploraapi53d3659b.devnet-annapurna.stratabtc.org";
const TEN_MINUTES: u64 = 10 * 60;

const PRIVATE_DATA_FILE_NAME: &str = "secret_data.json";

pub type UtxoSet = HashMap<OutPoint, Height>;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct BitVMClientPublicData {
    pub version: u32,
    pub peg_in_graphs: Vec<PegInGraph>,
    pub peg_out_graphs: Vec<PegOutGraph>,
}

impl BitVMClientPublicData {
    pub fn get_graph_mut(&mut self, graph_id: &GraphId) -> &mut dyn BaseGraph {
        if let Some(peg_in) = self.peg_in_graphs.iter_mut().find(|x| x.id() == graph_id) {
            return peg_in;
        }
        if let Some(peg_out) = self.peg_out_graphs.iter_mut().find(|x| x.id() == graph_id) {
            return peg_out;
        }
        panic!("graph id not found");
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct BitVMClientPrivateData {
    // Peg in and peg out nonces all go into the same file for now
    // Verifier public key -> Graph ID -> Tx ID -> Input index -> Secret nonce
    #[allow(clippy::type_complexity)]
    pub secret_nonces: HashMap<PublicKey, HashMap<String, HashMap<Txid, HashMap<usize, SecNonce>>>>,
    // Operator Winternitz secrets for all the graphs.
    // Operator public key -> Graph ID -> Message ID -> Winternitz secret
    pub commitment_secrets:
        HashMap<PublicKey, HashMap<String, HashMap<CommitmentMessageId, WinternitzSecret>>>,
}

pub struct BitVMClient {
    pub esplora: AsyncClient,

    depositor_context: Option<DepositorContext>,
    operator_context: Option<OperatorContext>,
    verifier_context: Option<VerifierContext>,
    withdrawer_context: Option<WithdrawerContext>,

    data_store: DataStore,
    data: BitVMClientPublicData,
    pub fetched_file_name: Option<String>,
    pub file_path: String,
    pub file_path_prefix: String,

    private_data: BitVMClientPrivateData,

    chain_adaptor: Chain,
}

impl BitVMClient {
    pub async fn new(
        source_network: Network,
        destination_network: DestinationNetwork,
        n_of_n_public_keys: &Vec<PublicKey>,
        depositor_secret: Option<&str>,
        operator_secret: Option<&str>,
        verifier_secret: Option<&str>,
        withdrawer_secret: Option<&str>,
        file_path_prefix: Option<&str>,
    ) -> Self {
        let mut depositor_context = None;
        if depositor_secret.is_some() {
            depositor_context = Some(DepositorContext::new(
                source_network,
                depositor_secret.unwrap(),
                n_of_n_public_keys,
            ));
        }

        let mut operator_context = None;
        if operator_secret.is_some() {
            operator_context = Some(OperatorContext::new(
                source_network,
                operator_secret.unwrap(),
                n_of_n_public_keys,
            ));
        }

        let mut verifier_context = None;
        if verifier_secret.is_some() {
            verifier_context = Some(VerifierContext::new(
                source_network,
                verifier_secret.unwrap(),
                n_of_n_public_keys,
            ));
        }

        let mut withdrawer_context = None;
        if withdrawer_secret.is_some() {
            withdrawer_context = Some(WithdrawerContext::new(
                source_network,
                withdrawer_secret.unwrap(),
                n_of_n_public_keys,
            ));
        }

        // TODO scope data and private data by n of n public keys
        // Prepend files with prefix
        let (n_of_n_public_key, _) = generate_n_of_n_public_key(n_of_n_public_keys);
        let file_path_prefix = file_path_prefix.unwrap_or("").to_string();
        let file_path =
            format! {"bridge_data/{source_network}/{destination_network}/{n_of_n_public_key}"};
        let full_path = format! {"{file_path_prefix}{file_path}"};
        Self::create_directories_if_non_existent(&full_path);

        let data = BitVMClientPublicData {
            version: 1,
            peg_in_graphs: vec![],
            peg_out_graphs: vec![],
        };

        let data_store = DataStore::new().await;

        let private_data = Self::get_private_data(&file_path);

        let chain_adaptor = Chain::new();

        Self {
            esplora: Builder::new(ESPLORA_URL)
                .build_async()
                .expect("Could not build esplora client"),

            depositor_context,
            operator_context,
            verifier_context,
            withdrawer_context,

            data_store,
            data,
            fetched_file_name: None,
            file_path,
            file_path_prefix,

            private_data,

            chain_adaptor,
        }
    }

    pub fn get_data(&self) -> &BitVMClientPublicData { &self.data }

    pub async fn sync(&mut self) { self.read().await; }

    pub async fn sync_l2(&mut self) { self.read_from_l2().await; }

    pub async fn flush(&mut self) { self.save().await; }

    /*
    File syncing flow with data store
     1. Fetch the latest file
     2. Fetch all files within 10 minutes (use timestamp)
     3. Merge files
     4. Client modifies file and clicks save
     5. Fetch files that were created after fetching 1-2.
     6. Merge with your file
     7. Push the file to the server
    */

    async fn read(&mut self) {
        let latest_file_names_result = Self::get_latest_file_names(
            &self.data_store,
            Some(&self.file_path),
            self.fetched_file_name.clone(),
        )
        .await;

        if latest_file_names_result.is_ok() {
            let mut latest_file_names = latest_file_names_result.unwrap();
            if !latest_file_names.is_empty() {
                // fetch latest valid file
                let (latest_file, latest_file_name) = Self::fetch_latest_valid_file(
                    &self.data_store,
                    &mut latest_file_names,
                    Some(&self.file_path),
                )
                .await;
                if latest_file.is_some() && latest_file_name.is_some() {
                    Self::save_local_public_file(
                        &self.file_path,
                        latest_file_name.as_ref().unwrap(),
                        &serialize(&latest_file.as_ref().unwrap()),
                    );
                    self.fetched_file_name = latest_file_name;

                    // fetch and process all the previous files if latest valid file exists
                    let result =
                        Self::process_files_by_timestamp(self, latest_file_names, TEN_MINUTES)
                            .await;
                    match result {
                        Ok(_) => (), // println!("Ok"),
                        Err(err) => println!("Error: {}", err),
                    }

                    self.merge_data(latest_file.unwrap()); // merge the latest data at the end
                }
            }
        } else {
            println!("Error: {}", latest_file_names_result.unwrap_err());
        }
    }

    pub fn set_chain_adaptor(&mut self, chain_adaptor: Chain) {
        self.chain_adaptor = chain_adaptor;
    }

    async fn read_from_l2(&mut self) {
        let peg_out_result = self.chain_adaptor.get_peg_out_init().await;
        if peg_out_result.is_ok() {
            let mut events = peg_out_result.unwrap();
            for peg_out_graph in self.data.peg_out_graphs.iter_mut() {
                if !peg_out_graph.is_peg_out_initiated() {
                    match peg_out_graph.match_and_set_peg_out_event(&mut events).await {
                        Ok(_) => {
                            if peg_out_graph.peg_out_chain_event.is_some() {
                                println!(
                                    "Peg Out Graph id: {} Event Matched, Event: {:?}",
                                    peg_out_graph.id(),
                                    peg_out_graph.peg_out_chain_event
                                )
                            }
                        }
                        Err(err) => println!("Error: {}", err),
                    }
                }
            }
        } else {
            panic!("Get event failed from L2 chain: {:?}", peg_out_result.err());
        }
    }

    async fn get_latest_file_names(
        data_store: &DataStore,
        file_path: Option<&str>,
        fetched_file_name: Option<String>,
    ) -> Result<Vec<String>, String> {
        let all_file_names_result = data_store.get_file_names(file_path).await;
        if all_file_names_result.is_ok() {
            let mut all_file_names = all_file_names_result.unwrap();

            if fetched_file_name.is_some() {
                let fetched_file_position = all_file_names
                    .iter()
                    .position(|file_name| file_name.eq(fetched_file_name.as_ref().unwrap()));
                if fetched_file_position.is_some() {
                    let unfetched_file_position = fetched_file_position.unwrap() + 1;
                    if all_file_names.len() > unfetched_file_position {
                        all_file_names = all_file_names.split_off(unfetched_file_position);
                    } else {
                        all_file_names.clear(); // no files to process
                    }
                }
            }

            Ok(all_file_names)
        } else {
            Err(all_file_names_result.unwrap_err())
        }
    }

    async fn filter_files_names_by_timestamp(
        &self,
        latest_file_names: Vec<String>,
        period: u64,
    ) -> Result<Vec<String>, String> {
        if self.fetched_file_name.is_some() {
            let latest_timestamp = self
                .data_store
                .get_file_timestamp(self.fetched_file_name.as_ref().unwrap());
            if latest_timestamp.is_err() {
                return Err(latest_timestamp.unwrap_err());
            }

            let past_max_file_name = self
                .data_store
                .get_past_max_file_name_by_timestamp(latest_timestamp.unwrap(), period);

            let mut previous_max_position = latest_file_names
                .iter()
                .position(|file_name| file_name >= &past_max_file_name);
            if previous_max_position.is_none() {
                previous_max_position = Some(latest_file_names.len());
            }

            let file_names_to_process = latest_file_names
                .clone()
                .split_off(previous_max_position.unwrap());

            Ok(file_names_to_process)
        } else {
            Err(String::from(
                "No latest file data. Must fetch the latest file first.",
            ))
        }
    }

    async fn process_files_by_timestamp(
        &mut self,
        latest_file_names: Vec<String>,
        period: u64,
    ) -> Result<String, String> {
        let file_names_to_process_result = self
            .filter_files_names_by_timestamp(latest_file_names, period)
            .await;

        if file_names_to_process_result.is_err() {
            return Err(file_names_to_process_result.unwrap_err());
        }

        let file_names_to_process = file_names_to_process_result.unwrap();

        Self::process_files(self, file_names_to_process).await;

        Ok(String::from("Files processed"))
    }

    async fn process_files(&mut self, file_names: Vec<String>) -> Option<String> {
        let mut latest_valid_file_name: Option<String> = None;
        if file_names.is_empty() {
            // println!("No additional files to process")
        } else {
            // TODO: can be optimized to fetch all data at once?
            for file_name in file_names.iter() {
                let result = self
                    .data_store
                    .fetch_data_by_key(file_name, Some(&self.file_path))
                    .await; // TODO: use `fetch_by_key()` function
                if result.is_ok() && result.as_ref().unwrap().is_some() {
                    let data =
                        try_deserialize::<BitVMClientPublicData>(&(result.unwrap()).unwrap());
                    if data.is_ok() && Self::validate_data(data.as_ref().unwrap()) {
                        // merge the file if the data is valid
                        println!("Merging {} data...", { file_name });
                        self.merge_data(data.unwrap());
                        if latest_valid_file_name.is_none() {
                            latest_valid_file_name = Some(file_name.clone());
                        }
                    } else {
                        // skip the file if the data is invalid
                        println!("Invalid file {}, Skipping...", file_name);
                    }
                }
            }
        }

        latest_valid_file_name
    }

    async fn fetch_latest_valid_file(
        data_store: &DataStore,
        file_names: &mut Vec<String>,
        file_path: Option<&str>,
    ) -> (Option<BitVMClientPublicData>, Option<String>) {
        let mut latest_valid_file: Option<BitVMClientPublicData> = None;
        let mut latest_valid_file_name: Option<String> = None;

        while !file_names.is_empty() {
            let file_name_result = file_names.pop();
            if file_name_result.is_some() {
                let file_name = file_name_result.unwrap();
                let (latest_data, latest_data_len) =
                    Self::fetch_by_key(data_store, &file_name, file_path).await;
                if latest_data.is_some() && Self::validate_data(latest_data.as_ref().unwrap()) {
                    // data is valid
                    println!(
                        "Fetched valid file: {} (size: {})",
                        file_name, latest_data_len
                    );
                    latest_valid_file = latest_data;
                    latest_valid_file_name = Some(file_name);
                    break;
                } else {
                    println!("Invalid file: {}", file_name); // TODO: can be removed
                }
                // for invalid data try another file
            }
        }

        (latest_valid_file, latest_valid_file_name)
    }

    async fn fetch_by_key(
        data_store: &DataStore,
        key: &String,
        file_path: Option<&str>,
    ) -> (Option<BitVMClientPublicData>, usize) {
        let result = data_store.fetch_data_by_key(key, file_path).await;
        if result.is_ok() {
            if let Some(json) = result.unwrap() {
                let data = try_deserialize::<BitVMClientPublicData>(&json);
                if data.is_ok() {
                    return (Some(data.unwrap()), json.len());
                }
            }
        }

        (None, 0)
    }

    async fn save(&mut self) {
        // read newly created data before pushing
        let latest_file_names_result = Self::get_latest_file_names(
            &self.data_store,
            Some(&self.file_path),
            self.fetched_file_name.clone(),
        )
        .await;

        if latest_file_names_result.is_ok() {
            let mut latest_file_names = latest_file_names_result.unwrap();
            latest_file_names.reverse();
            let latest_valid_file_name = Self::process_files(self, latest_file_names).await;
            self.fetched_file_name = latest_valid_file_name;
        }

        // push data
        self.data.version += 1;

        let json = serialize(&self.data);
        let result = self
            .data_store
            .write_data(json.clone(), Some(&self.file_path))
            .await;
        match result {
            Ok(key) => {
                println!("Pushed new file: {} (size: {})", key, json.len());
                Self::save_local_public_file(&self.file_path, &key, &json);
            }
            Err(err) => println!("Failed to push: {}", err),
        }
    }

    pub fn validate_data(data: &BitVMClientPublicData) -> bool {
        for peg_in_graph in data.peg_in_graphs.iter() {
            if !peg_in_graph.validate() {
                println!(
                    "Encountered invalid peg in graph (Graph id: {})",
                    peg_in_graph.id()
                );
                return false;
            }
        }
        for peg_out_graph in data.peg_out_graphs.iter() {
            if !peg_out_graph.validate() {
                println!(
                    "Encountered invalid peg out graph (Graph id: {})",
                    peg_out_graph.id()
                );
                return false;
            }
        }

        // println!("All graph data is valid");
        true
    }

    /// Merges `data` into `self.data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Must be valid data verified via `BitVMClient::validate_data()` function
    pub fn merge_data(&mut self, data: BitVMClientPublicData) {
        // peg-in graphs
        let mut peg_in_graphs_by_id: HashMap<String, &mut PegInGraph> = HashMap::new();
        for peg_in_graph in self.data.peg_in_graphs.iter_mut() {
            peg_in_graphs_by_id.insert(peg_in_graph.id().clone(), peg_in_graph);
        }

        let mut peg_in_graphs_to_add: Vec<&PegInGraph> = Vec::new();
        for peg_in_graph in data.peg_in_graphs.iter() {
            let graph = peg_in_graphs_by_id.get_mut(peg_in_graph.id());
            if graph.is_some() {
                graph.unwrap().merge(peg_in_graph);
            } else {
                peg_in_graphs_to_add.push(peg_in_graph);
            }
        }

        for graph in peg_in_graphs_to_add.into_iter() {
            self.data.peg_in_graphs.push(graph.clone());
        }

        // peg-out graphs
        let mut peg_out_graphs_by_id: HashMap<String, &mut PegOutGraph> = HashMap::new();
        for peg_out_graph in self.data.peg_out_graphs.iter_mut() {
            let id = peg_out_graph.id().clone();
            peg_out_graphs_by_id.insert(id, peg_out_graph);
        }

        let mut peg_out_graphs_to_add: Vec<&PegOutGraph> = Vec::new();
        for peg_out_graph in data.peg_out_graphs.iter() {
            let graph = peg_out_graphs_by_id.get_mut(peg_out_graph.id());
            if graph.is_some() {
                graph.unwrap().merge(peg_out_graph);
            } else {
                peg_out_graphs_to_add.push(peg_out_graph);
            }
        }

        for graph in peg_out_graphs_to_add.into_iter() {
            self.data.peg_out_graphs.push(graph.clone());
        }
    }

    // fn process(&self) {
    //     for peg_in_graph in self.data.peg_in_graphs.iter() {
    //         // match graph.get(outpoint) {
    //         //     Some(subsequent_txs) => {
    //         //         for bridge_transaction in subsequent_txs {
    //         //             // TODO: Check whether the transaction is executable
    //         //             let tx = bridge_transaction.finalize();
    //         //             match self.esplora.broadcast(&tx).await {
    //         //                 Ok(_) => {
    //         //                     println!(
    //         //                         "Succesfully broadcast next transaction with id: {}",
    //         //                         tx.compute_txid()
    //         //                     );
    //         //                     remove_utxo = Some(*outpoint);
    //         //                     break;
    //         //                 }
    //         //                 Err(err) => panic!("Tx Broadcast Error: {}", err),
    //         //             }
    //         //         }
    //         //     }
    //         //     None => continue,
    //         // }
    //     }
    // }

    pub async fn status(&self) {
        if self.depositor_context.is_some() {
            self.depositor_status().await;
        }
        if self.operator_context.is_some() {
            self.operator_status().await;
        }
        if self.verifier_context.is_some() {
            self.verifier_status().await;
        }
    }

    async fn depositor_status(&self) {
        if self.depositor_context.is_none() {
            panic!("Depositor context must be initialized");
        }

        let depositor_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .depositor_public_key;
        for peg_in_graph in self.data.peg_in_graphs.iter() {
            if peg_in_graph.depositor_public_key.eq(depositor_public_key) {
                let status = peg_in_graph.depositor_status(&self.esplora).await;
                println!("Graph id: {} status: {}\n", peg_in_graph.id(), status);
            }
        }
    }

    async fn operator_status(&self) {
        if self.operator_context.is_none() {
            panic!("Operator context must be initialized");
        }

        let mut peg_out_graphs_by_id: HashMap<&String, &PegOutGraph> = HashMap::new();
        for peg_out_graph in self.data.peg_out_graphs.iter() {
            peg_out_graphs_by_id.insert(peg_out_graph.id(), peg_out_graph);
        }

        let operator_public_key = &self.operator_context.as_ref().unwrap().operator_public_key;
        for peg_in_graph in self.data.peg_in_graphs.iter() {
            let peg_out_graph_id = peg_out_generate_id(peg_in_graph, operator_public_key);
            if !peg_out_graphs_by_id.contains_key(&peg_out_graph_id) {
                println!(
                    "Graph id: {} status: Missing peg out graph\n",
                    peg_in_graph.id() // TODO update this to ask the operator to create a new peg out graph
                );
            } else {
                let peg_out_graph = peg_out_graphs_by_id.get(&peg_out_graph_id).unwrap();
                let status = peg_out_graph.operator_status(&self.esplora).await;
                println!("Graph id: {} status: {}\n", peg_out_graph.id(), status);
            }
        }
    }

    pub async fn process_peg_in_as_depositor(&mut self, peg_in_graph: &PegInGraph) {
        if let Some(_) = self.depositor_context {
            let status = peg_in_graph.depositor_status(&self.esplora).await;

            match status {
                PegInDepositorStatus::PegInDepositWait => {
                    self.broadcast_peg_in_deposit(peg_in_graph.id()).await;
                }
                PegInDepositorStatus::PegInConfirmWait => {
                    self.broadcast_peg_in_confirm(peg_in_graph.id()).await;
                }
                _ => {
                    println!(
                        "Peg-in graph {} is in status: {}",
                        peg_in_graph.id(),
                        status
                    );
                }
            }
        }
    }

    pub async fn process_peg_in_as_verifier(&mut self, peg_in_graph: &PegInGraph) {
        if let Some(ref context) = self.verifier_context {
            let peg_outs = peg_in_graph
                .peg_out_graphs
                .iter()
                .map(|peg_out_id| {
                    self.data
                        .peg_out_graphs
                        .iter()
                        .find(|x| x.id() == peg_out_id)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            let status = peg_in_graph
                .verifier_status(&self.esplora, Some(context), &peg_outs)
                .await;

            match status {
                PegInVerifierStatus::PendingOurNonces(graph_ids) => {
                    println!("Pushing nonces for graphs {graph_ids:?}");
                    for graph_id in graph_ids {
                        self.push_verifier_nonces(&graph_id);
                    }
                }
                PegInVerifierStatus::PendingOurSignature(graph_ids) => {
                    println!("Pushing signature for graphs {graph_ids:?}");
                    for graph_id in graph_ids {
                        self.push_verifier_signature(&graph_id);
                    }
                }
                PegInVerifierStatus::ReadyToSubmit => {
                    println!("Broadcasting peg-in confirm");
                    self.broadcast_peg_in_confirm(peg_in_graph.id()).await;
                }
                _ => {
                    // nothing to do
                }
            }
        }
    }

    pub async fn process_peg_in_as_operator(&mut self, peg_in_graph: &PegInGraph) {
        if let Some(ref context) = self.operator_context {
            let peg_out_graph_id = peg_out_generate_id(peg_in_graph, &context.operator_public_key);
            if !peg_in_graph
                .peg_out_graphs
                .iter()
                .any(|x| x == &peg_out_graph_id)
            {
                let input = {
                    // todo: don't use a random address
                    let address = generate_pay_to_pubkey_script_address(
                        context.network,
                        &context.operator_public_key,
                    );
                    let utxos = self
                        .esplora
                        .get_address_utxo(address.clone())
                        .await
                        .unwrap();
                    let utxo = utxos
                        .into_iter()
                        .find(|x| x.value.to_sat() >= 300000)
                        .unwrap_or_else(|| {
                            panic!("No utxo found with at least 300000 sats for address {address}")
                        });
                    Input {
                        amount: utxo.value,
                        outpoint: OutPoint {
                            txid: utxo.txid,
                            vout: utxo.vout,
                        },
                    }
                };
                self.create_peg_out_graph(peg_in_graph.id(), input).await;
            }
        }
    }

    pub async fn process_peg_ins(&mut self) {
        let peg_in_graphs = self.get_data().peg_in_graphs.clone();

        for peg_in_graph in peg_in_graphs {
            self.process_peg_in_as_depositor(&peg_in_graph).await;
            self.process_peg_in_as_verifier(&peg_in_graph).await;
            self.process_peg_in_as_operator(&peg_in_graph).await;
        }
    }

    pub async fn process_peg_outs(&mut self) {
        let peg_out_graphs = self.get_data().peg_out_graphs.clone();
        for peg_out_graph in peg_out_graphs.iter() {
            let status = peg_out_graph.operator_status(&self.esplora).await;
            match status {
                PegOutOperatorStatus::PegOutStartTimeAvailable => {
                    self.broadcast_start_time(peg_out_graph.id()).await
                }
                PegOutOperatorStatus::PegOutPegOutConfirmAvailable => {
                    self.broadcast_peg_out_confirm(peg_out_graph.id()).await
                }
                PegOutOperatorStatus::PegOutKickOff1Available => {
                    self.broadcast_kick_off_1(peg_out_graph.id()).await
                }
                PegOutOperatorStatus::PegOutKickOff2Available => {
                    self.broadcast_kick_off_2(peg_out_graph.id()).await
                }
                // TODO: uncomment after assert tx are done
                // PegOutOperatorStatus::PegOutAssertAvailable => {
                //     self.broadcast_assert(peg_out_graph.id()).await
                // }
                PegOutOperatorStatus::PegOutTake1Available => {
                    self.broadcast_take_1(peg_out_graph.id()).await
                }
                PegOutOperatorStatus::PegOutTake2Available => {
                    self.broadcast_take_2(peg_out_graph.id()).await
                }
                _ => {}
            }
        }
    }

    async fn verifier_status(&self) {
        if self.verifier_context.is_none() {
            panic!("Verifier context must be initialized");
        }

        for peg_in_graph in self.data.peg_in_graphs.iter() {
            let peg_outs = peg_in_graph
                .peg_out_graphs
                .iter()
                .map(|peg_out_id| {
                    self.data
                        .peg_out_graphs
                        .iter()
                        .find(|x| x.id() == peg_out_id)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let status = peg_in_graph
                .verifier_status(&self.esplora, self.verifier_context.as_ref(), &peg_outs)
                .await;
            println!("Graph id: {} status: {}\n", peg_in_graph.id(), status);
        }
    }

    pub async fn create_peg_in_graph(&mut self, input: Input, evm_address: &str) -> String {
        if self.depositor_context.is_none() {
            panic!("Depositor context must be initialized");
        }

        let peg_in_graph =
            PegInGraph::new(self.depositor_context.as_ref().unwrap(), input, evm_address);

        let peg_in_graph_id = peg_in_generate_id(&peg_in_graph.peg_in_deposit_transaction);

        let graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_in_graph_id));
        if graph.is_some() {
            panic!("Peg in graph already exists");
        }

        self.data.peg_in_graphs.push(peg_in_graph);

        peg_in_graph_id
    }

    pub async fn broadcast_peg_in_deposit(&mut self, peg_in_graph_id: &str) -> Txid {
        let peg_in_graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id));
        if peg_in_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_in_graph.unwrap().deposit(&self.esplora).await
    }

    pub async fn broadcast_peg_in_refund(&mut self, peg_in_graph_id: &str) -> Txid {
        let peg_in_graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id));
        if peg_in_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_in_graph.unwrap().refund(&self.esplora).await
    }

    pub async fn broadcast_peg_in_confirm(&mut self, peg_in_graph_id: &str) -> Txid {
        let peg_in_graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id));
        if peg_in_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_in_graph.unwrap().confirm(&self.esplora).await
    }

    pub async fn create_peg_out_graph(
        &mut self,
        peg_in_graph_id: &str,
        kickoff_input: Input,
    ) -> String {
        if self.operator_context.is_none() {
            panic!("Operator context must be initialized");
        }
        let operator_public_key = &self.operator_context.as_ref().unwrap().operator_public_key;

        let peg_in_graph = self
            .data
            .peg_in_graphs
            .iter_mut()
            .find(|peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
            .unwrap_or_else(|| panic!("Invalid graph id"));

        let peg_out_graph_id = peg_out_generate_id(peg_in_graph, operator_public_key);
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_out_graph_id));
        if peg_out_graph.is_some() {
            panic!("Peg out graph already exists");
        }

        let (peg_out_graph, commitment_secrets) = PegOutGraph::new(
            self.operator_context.as_ref().unwrap(),
            peg_in_graph,
            kickoff_input,
        );

        self.private_data.commitment_secrets = HashMap::from([(
            *operator_public_key,
            HashMap::from([(peg_out_graph_id.to_string(), commitment_secrets)]),
        )]);
        Self::save_local_private_file(&self.file_path, &serialize(&self.private_data));

        self.data.peg_out_graphs.push(peg_out_graph);
        peg_in_graph.peg_out_graphs.push(peg_out_graph_id.clone());

        peg_out_graph_id
    }

    pub async fn broadcast_peg_out(&mut self, peg_out_graph_id: &str, input: Input) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        if self.operator_context.is_some() {
            peg_out_graph
                .unwrap()
                .peg_out(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    input,
                )
                .await;
        }
    }

    pub async fn broadcast_peg_out_confirm(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph.unwrap().peg_out_confirm(&self.esplora).await;
    }

    pub async fn broadcast_kick_off_1(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        if self.operator_context.is_some() {
            peg_out_graph
                .unwrap()
                .kick_off_1(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::PegOutTxIdSourceNetwork],
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::PegOutTxIdDestinationNetwork],
                )
                .await;
        }
    }

    pub async fn broadcast_start_time(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        if self.operator_context.is_some() {
            peg_out_graph
                .unwrap()
                .start_time(
                    &self.esplora,
                    self.operator_context.as_ref().unwrap(),
                    &self.private_data.commitment_secrets
                        [&self.operator_context.as_ref().unwrap().operator_public_key]
                        [peg_out_graph_id][&CommitmentMessageId::StartTime],
                )
                .await;
        }
    }

    pub async fn broadcast_start_time_timeout(
        &mut self,
        peg_out_graph_id: &str,
        output_script_pubkey: ScriptBuf,
    ) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph
            .unwrap()
            .start_time_timeout(&self.esplora, output_script_pubkey)
            .await;
    }

    pub async fn broadcast_kick_off_2(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph
            .unwrap()
            .kick_off_2(
                &self.esplora,
                self.operator_context.as_ref().unwrap(),
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id][&CommitmentMessageId::Superblock],
                &self.private_data.commitment_secrets
                    [&self.operator_context.as_ref().unwrap().operator_public_key]
                    [peg_out_graph_id][&CommitmentMessageId::SuperblockHash],
            )
            .await;
    }

    pub async fn broadcast_kick_off_timeout(
        &mut self,
        peg_out_graph_id: &str,
        output_script_pubkey: ScriptBuf,
    ) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph
            .unwrap()
            .kick_off_timeout(&self.esplora, output_script_pubkey)
            .await;
    }

    pub async fn broadcast_challenge(
        &mut self,
        peg_out_graph_id: &str,
        crowdfundng_inputs: &Vec<InputWithScript<'_>>,
        output_script_pubkey: ScriptBuf,
    ) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        if self.depositor_context.is_some() {
            peg_out_graph
                .unwrap()
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.depositor_context.as_ref().unwrap().depositor_keypair,
                    output_script_pubkey,
                )
                .await;
        } else if self.operator_context.is_some() {
            peg_out_graph
                .unwrap()
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.operator_context.as_ref().unwrap().operator_keypair,
                    output_script_pubkey,
                )
                .await;
        } else if self.verifier_context.is_some() {
            peg_out_graph
                .unwrap()
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.verifier_context.as_ref().unwrap().verifier_keypair,
                    output_script_pubkey,
                )
                .await;
        } else if self.withdrawer_context.is_some() {
            peg_out_graph
                .unwrap()
                .challenge(
                    &self.esplora,
                    crowdfundng_inputs,
                    &self.withdrawer_context.as_ref().unwrap().withdrawer_keypair,
                    output_script_pubkey,
                )
                .await;
        }
    }

    pub async fn broadcast_assert_initial(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph.unwrap().assert_initial(&self.esplora).await;
    }

    pub async fn broadcast_assert_final(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph.unwrap().assert_final(&self.esplora).await;
    }

    pub async fn broadcast_disprove(
        &mut self,
        peg_out_graph_id: &str,
        input_script_index: u32,
        output_script_pubkey: ScriptBuf,
    ) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph
            .unwrap()
            .disprove(&self.esplora, input_script_index, output_script_pubkey)
            .await;
    }

    pub async fn broadcast_disprove_chain(
        &mut self,
        peg_out_graph_id: &str,
        output_script_pubkey: ScriptBuf,
    ) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph
            .unwrap()
            .disprove_chain(&self.esplora, output_script_pubkey)
            .await;
    }

    pub async fn broadcast_take_1(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        peg_out_graph.unwrap().take_1(&self.esplora).await;
    }

    pub async fn broadcast_take_2(&mut self, peg_out_graph_id: &str) {
        let peg_out_graph = self
            .data
            .peg_out_graphs
            .iter_mut()
            .find(|peg_out_graph| peg_out_graph.id().eq(peg_out_graph_id));
        if peg_out_graph.is_none() {
            panic!("Invalid graph id");
        }

        if self.operator_context.is_some() {
            peg_out_graph
                .unwrap()
                .take_2(&self.esplora, self.operator_context.as_ref().unwrap())
                .await;
        }
    }

    pub async fn get_initial_utxo(&self, address: Address, amount: Amount) -> Option<Utxo> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos[0].clone())
        } else {
            None
        }
    }

    pub async fn get_initial_utxos(&self, address: Address, amount: Amount) -> Option<Vec<Utxo>> {
        let utxos = self.esplora.get_address_utxo(address).await.unwrap();
        let possible_utxos = utxos
            .into_iter()
            .filter(|utxo| utxo.value == amount)
            .collect::<Vec<_>>();
        if !possible_utxos.is_empty() {
            Some(possible_utxos)
        } else {
            None
        }
    }

    pub fn get_depositor_address(&self) -> Address {
        if let Some(ref context) = self.depositor_context {
            generate_pay_to_pubkey_script_address(context.network, &context.depositor_public_key)
        } else {
            panic!("No depositor key set");
        }
    }

    pub async fn get_depositor_utxos(&self) -> Vec<Utxo> {
        self.esplora
            .get_address_utxo(self.get_depositor_address())
            .await
            .unwrap()
    }

    pub fn push_verifier_nonces(&mut self, graph_id: &GraphId) {
        if self.verifier_context.is_none() {
            panic!("Can only be called by a verifier!");
        }

        let graph = self.data.get_graph_mut(graph_id);
        let graph_id = graph.id().clone();

        let secret_nonces = graph.push_verifier_nonces(self.verifier_context.as_ref().unwrap());
        self.merge_secret_nonces(&graph_id, secret_nonces);

        // TODO: Save secret nonces for all txs in the graph to the local file system. Later, when pre-signing the tx,
        // we'll need to retrieve these nonces for this graph ID.

        let json = serialize(&self.private_data);
        Self::save_local_private_file(&self.file_path, &json);
    }

    fn merge_secret_nonces(
        &mut self,
        graph_id: &str,
        secret_nonces: HashMap<Txid, HashMap<usize, SecNonce>>,
    ) {
        if self
            .private_data
            .secret_nonces
            .get(&self.verifier_context.as_ref().unwrap().verifier_public_key)
            .is_none()
        {
            self.private_data.secret_nonces.insert(
                self.verifier_context.as_ref().unwrap().verifier_public_key,
                HashMap::new(),
            );
        }

        if self.private_data.secret_nonces
            [&self.verifier_context.as_ref().unwrap().verifier_public_key]
            .get(graph_id)
            .is_none()
        {
            self.private_data
                .secret_nonces
                .get_mut(&self.verifier_context.as_ref().unwrap().verifier_public_key)
                .unwrap()
                .insert(graph_id.to_string(), HashMap::new());
        }

        self.private_data
            .secret_nonces
            .get_mut(&self.verifier_context.as_ref().unwrap().verifier_public_key)
            .unwrap()
            .get_mut(graph_id)
            .unwrap()
            .extend(secret_nonces);
    }

    pub fn push_verifier_signature(&mut self, graph_id: &GraphId) {
        let verifier = self
            .verifier_context
            .as_ref()
            .expect("Can only be called by a verifier!");

        let graph = self.data.get_graph_mut(graph_id);
        let graph_id = graph.id().clone();

        graph.verifier_sign(
            verifier,
            &self.private_data.secret_nonces
                [&self.verifier_context.as_ref().unwrap().verifier_public_key][&graph_id],
        );
    }

    fn get_private_data(file_path: &String) -> BitVMClientPrivateData {
        match Self::read_local_private_file(file_path) {
            Some(data) => try_deserialize::<BitVMClientPrivateData>(&data)
                .expect("Could not deserialize private data"),
            None => {
                println!("New private data will be generated.");
                BitVMClientPrivateData {
                    secret_nonces: HashMap::new(),
                    commitment_secrets: HashMap::new(),
                }
            }
        }
    }

    fn save_local_public_file(file_path: &String, key: &String, json: &String) {
        Self::create_directories_if_non_existent(file_path);
        println!("Saving public data in local file: {}...", key);
        fs::write(format!("{file_path}/public/{key}"), json).expect("Unable to write a file");
    }

    fn save_local_private_file(file_path: &String, json: &String) {
        Self::create_directories_if_non_existent(file_path);
        println!("Saving private data in local file...");
        fs::write(
            format!("{file_path}/private/{PRIVATE_DATA_FILE_NAME}"),
            json,
        )
        .expect("Unable to write a file");
    }

    fn read_local_private_file(file_path: &String) -> Option<String> {
        println!("Reading private data from local file...");
        match fs::read_to_string(format!("{file_path}/private/{PRIVATE_DATA_FILE_NAME}")) {
            Ok(content) => Some(content),
            Err(e) => {
                eprintln!("Could not read file {file_path} due to error: {e}");
                None
            }
        }
    }

    fn create_directories_if_non_existent(file_path: &String) {
        let path_exists = Path::new(file_path).exists();
        if !path_exists {
            fs::create_dir_all(file_path).expect("Failed to create directories");
        }

        let public_path_exists = Path::new(&format! {"{file_path}/public"}).exists();
        let private_path_exists = Path::new(&format! {"{file_path}/private"}).exists();
        if !public_path_exists {
            fs::create_dir(format! {"{file_path}/public"})
                .expect("Failed to create 'public' directory");
        }
        if !private_path_exists {
            fs::create_dir(format! {"{file_path}/private"})
                .expect("Failed to create 'private' directory");
        }
    }

    // pub async fn execute_possible_txs(
    //     &mut self,
    //     context: &dyn BaseContext,
    //     graph: &mut CompiledBitVMGraph,
    // ) {
    //     // Iterate through our UTXO set and execute an executable TX
    //     // TODO: May have to respect an order here.
    //     let mut remove_utxo = None;
    //     for (outpoint, _) in self.utxo_set.iter() {
    //         match graph.get(outpoint) {
    //             Some(subsequent_txs) => {
    //                 for bridge_transaction in subsequent_txs {
    //                     // TODO: Check whether the transaction is executable
    //                     let tx = bridge_transaction.finalize();
    //                     match self.esplora.broadcast(&tx).await {
    //                         Ok(_) => {
    //                             println!(
    //                                 "Succesfully broadcast next transaction with id: {}",
    //                                 tx.compute_txid()
    //                             );
    //                             remove_utxo = Some(*outpoint);
    //                             break;
    //                         }
    //                         Err(err) => panic!("Tx Broadcast Error: {}", err),
    //                     }
    //                 }
    //             }
    //             None => continue,
    //         }
    //     }

    //     if let Some(remove_utxo) = remove_utxo {
    //         self.utxo_set.remove(&remove_utxo);
    //         graph.remove(&remove_utxo);
    //     }
    // }

    // pub async fn listen(
    //     &mut self,
    //     context: &dyn BaseContext,
    //     initial_outpoint: OutPoint,
    //     graph: &mut CompiledBitVMGraph,
    // ) {
    //     let builder = Builder::new(ESPLORA_URL);
    //     let esplora = builder.build_async().unwrap();
    //     let mut latest_hash =
    //         BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    //             .unwrap();
    //     self.utxo_set.insert(initial_outpoint, Height::ZERO);

    //     while !graph.is_empty() {
    //         if let Ok(block_hash) = esplora.get_tip_hash().await {
    //             if block_hash == latest_hash {
    //                 sleep(Duration::from_secs(10));
    //                 continue;
    //             }
    //             latest_hash = block_hash;
    //             // TODO: This assumes that the tip did not increase. There should be a
    //             // better API endpoint like /block-height/{block_hash}
    //             let block_height = esplora.get_height().await.unwrap();
    //             let block = esplora
    //                 .get_block_by_hash(&block_hash)
    //                 .await
    //                 .unwrap()
    //                 .unwrap();

    //             // Handle new block received logic
    //             println!("Received block {}", block_hash);

    //             for tx in block.txdata {
    //                 for (vout, _) in tx.output.iter().enumerate() {
    //                     let outpoint = OutPoint {
    //                         txid: tx.compute_txid(),
    //                         vout: vout as u32,
    //                     };
    //                     if graph.contains_key(&outpoint) {
    //                         // Update our UTXO set
    //                         self.utxo_set
    //                             .insert(outpoint, Height::from_consensus(block_height).unwrap());
    //                     }
    //                 }
    //             }
    //             self.execute_possible_txs(context, graph).await;
    //         }
    //     }
    // }
}

impl ClientCliQuery for BitVMClient {
    async fn get_unused_peg_in_graphs(&self) -> Vec<Value> {
        join_all(self.data.peg_in_graphs.iter().filter_map(|peg_in| {
            Some(async move {
                match peg_in.depositor_status(&self.esplora).await {
                    PegInDepositorStatus::PegInConfirmComplete => match self.data.peg_out_graphs.iter().find(|peg_out| peg_out.peg_in_graph_id == *peg_in.id()) {
                        Some(peg_out) => match peg_out.operator_status(&self.esplora).await {
                            PegOutOperatorStatus::PegOutWait => Some(json!({
                                "graph_id": peg_in.id(),
                                "amount": peg_in.peg_in_confirm_transaction.prev_outs()[0].value.to_sat(),
                                "source_outpoint": {
                                    "txid": peg_in.peg_in_confirm_transaction.tx().compute_txid(),
                                    "vout": 0
                                },
                            })),
                            _ => None,
                        },
                        None => None,
                    },
                    _ => None,
                }
            })
        }))
        .await
        .iter()
        .filter_map(|v| {
            v.clone()
        })
        .collect()
    }

    async fn get_depositor_status(&self, depositor_public_key: &PublicKey) -> Vec<Value> {
        join_all(
            self.data
                .peg_in_graphs
                .iter()
                .filter(|&graph| graph.depositor_public_key.eq(depositor_public_key))
                .map(|graph| async {
                    let tx_ids = vec![
                        graph.peg_in_deposit_transaction.tx().compute_txid(),
                        graph.peg_in_confirm_transaction.tx().compute_txid(),
                        graph.peg_in_refund_transaction.tx().compute_txid(),
                    ];
                    let tx_statuses_results = get_tx_statuses(&self.esplora, &tx_ids).await;
                    let blockchain_height = self.esplora.get_height().await.unwrap();
                    let status = graph.interpret_depositor_status(
                        &tx_statuses_results[0],
                        &tx_statuses_results[1],
                        &tx_statuses_results[2],
                        blockchain_height,
                    );

                    let tx_statuses = tx_statuses_results
                        .iter()
                        .map(|tx_status| {
                            tx_status.as_ref().unwrap_or(&TxStatus {
                                confirmed: false,
                                block_height: None,
                                block_hash: None,
                                block_time: None,
                            })
                        })
                        .collect::<Vec<_>>();
                    let tx_json_values = tx_statuses
                        .iter()
                        .enumerate()
                        .map(|(i, tx_status)| {
                            json!({
                            "type": match i {
                                0 => "peg_in_deposit",
                                1 => "peg_in_confirm",
                                2 => "peg_in_refund",
                                _ => unreachable!(),
                            },
                            "txid": tx_ids[i],
                            "status": {
                                "confirmed": tx_status.confirmed,
                                "block_height": tx_status.block_height.unwrap_or(0),
                                "block_hash": tx_status.block_hash.or(None),
                                "block_time": tx_status.block_time.unwrap_or(0),
                            }})
                        })
                        .collect::<Vec<_>>();

                    json!({
                        "type": "peg_in",
                        "graph_id": graph.id(),
                        "status": status.to_string(),
                        "amount": graph.peg_in_deposit_transaction.prev_outs()[0].value.to_sat(),
                        "destination_address": graph.depositor_evm_address,
                        "txs" : tx_json_values,
                    })
                }),
        )
        .await
    }

    async fn get_withdrawer_status(&self, withdrawer_chain_address: &str) -> Vec<Value> {
        join_all(
            self.data
                .peg_out_graphs
                .iter()
                .filter(|&graph| {
                    if graph.peg_out_chain_event.is_some() {
                        return graph
                            .peg_out_chain_event
                            .as_ref()
                            .unwrap()
                            .withdrawer_chain_address
                            .eq(withdrawer_chain_address);
                    }
                    false
                })
                .map(|graph| async {
                    let (tx_json_value, tx_status_result) = match &graph.peg_out_transaction {
                        Some(tx) => {
                            let txid = tx.tx().compute_txid();
                            let tx_status_result = self.esplora.get_tx_status(&txid).await;
                            let tx_status = tx_status_result.as_ref().unwrap_or(&TxStatus {
                                confirmed: false,
                                block_height: None,
                                block_hash: None,
                                block_time: None,
                            });
                            let tx_json_value = json!({
                                "type": "peg_out",
                                "txid": txid,
                                "status": {
                                    "confirmed": tx_status.confirmed,
                                    "block_height": tx_status.block_height.unwrap_or(0),
                                    "block_hash": tx_status.block_hash.or(None),
                                    "block_time": tx_status.block_time.unwrap_or(0),
                                }
                            });

                            (Some(tx_json_value), Some(tx_status_result))
                        }
                        None => (Some(json!([])), None),
                    };
                    let (peg_out_amount, destination_address) = match &graph.peg_out_chain_event {
                        Some(peg_out_chain_event) => (
                            peg_out_chain_event.amount.to_sat(),
                            peg_out_chain_event.withdrawer_destination_address.clone(),
                        ),
                        None => (0, "".to_string()),
                    };

                    let status = graph.interpret_withdrawer_status(tx_status_result.as_ref());
                    json!({
                        "type": "peg_out",
                        "graph_id": graph.id(),
                        "status": status.to_string(),
                        "amount": peg_out_amount,
                        "destination_address": destination_address,
                        "txs": tx_json_value,
                    })
                }),
        )
        .await
    }

    async fn get_depositor_transactions(
        &self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
    ) -> Result<Value, String> {
        // depositor context should contain pub key of n_of_n
        if self.depositor_context.is_none() {
            return Err("Depositor context must be initialized".into());
        }

        let n_of_n_public_key = &self.depositor_context.as_ref().unwrap().n_of_n_public_key;
        let n_of_n_taproot_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .n_of_n_taproot_public_key;
        let n_of_n_public_keys = &self.depositor_context.as_ref().unwrap().n_of_n_public_keys;
        let peg_in_graph = PegInGraph::new_for_query(
            self.depositor_context.as_ref().unwrap().network,
            depositor_public_key,
            depositor_taproot_public_key,
            n_of_n_public_key,
            n_of_n_public_keys,
            n_of_n_taproot_public_key,
            depositor_evm_address,
            deposit_input,
        );

        Ok(json!({
            "deposit": serialize_hex(peg_in_graph.peg_in_deposit_transaction.tx()),
            "confirm": serialize_hex(peg_in_graph.peg_in_confirm_transaction.tx()),
            "refund": serialize_hex(peg_in_graph.peg_in_refund_transaction.tx()),
        }))
    }

    async fn create_peg_in_graph_with_depositor_signatures(
        &mut self,
        depositor_public_key: &PublicKey,
        depositor_taproot_public_key: &XOnlyPublicKey,
        deposit_input: Input,
        depositor_evm_address: &str,
        signatures: &DepositorSignatures,
    ) -> Result<Value, String> {
        // depositor context should contain pub key of n_of_n
        if self.depositor_context.is_none() {
            return Err("Depositor context must be initialized".into());
        }

        let n_of_n_public_key = &self.depositor_context.as_ref().unwrap().n_of_n_public_key;
        let n_of_n_public_keys = &self.depositor_context.as_ref().unwrap().n_of_n_public_keys;
        let n_of_n_taproot_public_key = &self
            .depositor_context
            .as_ref()
            .unwrap()
            .n_of_n_taproot_public_key;
        let peg_in_graph = PegInGraph::new_with_depositor_signatures(
            self.depositor_context.as_ref().unwrap().network,
            depositor_public_key,
            depositor_taproot_public_key,
            n_of_n_public_key,
            n_of_n_public_keys,
            n_of_n_taproot_public_key,
            depositor_evm_address,
            deposit_input,
            signatures,
        );

        let peg_in_graph_id = peg_in_generate_id(&peg_in_graph.peg_in_deposit_transaction);

        let graph = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_out_graph| peg_out_graph.id().eq(&peg_in_graph_id));
        if graph.is_some() {
            return Err("Peg in graph already exists".into());
        }

        self.data.peg_in_graphs.push(peg_in_graph.clone());

        match peg_in_graph.broadcast_deposit(&self.esplora).await {
            Ok(_) => Ok(json!({"graph_id": peg_in_graph_id})),
            Err(e) => Err(e),
        }
    }

    async fn retry_broadcast_peg_in_deposit(&self, peg_in_graph_id: &str) -> Result<Value, String> {
        let Some(peg_in_graph) = self
            .data
            .peg_in_graphs
            .iter()
            .find(|&peg_in_graph| peg_in_graph.id().eq(peg_in_graph_id))
        else {
            return Err("Peg in graph not found".into());
        };

        match peg_in_graph.broadcast_deposit(&self.esplora).await {
            Ok(_) => Ok(json!({"graph_id": peg_in_graph_id})),
            Err(e) => Err(e),
        }
    }
}
