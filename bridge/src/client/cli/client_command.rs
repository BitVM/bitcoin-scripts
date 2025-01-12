use super::key_command::KeysCommand;
use crate::client::client::BitVMClient;
use crate::constants::DestinationNetwork;
use crate::contexts::base::generate_keys_from_secret;
use crate::graphs::base::{VERIFIER_0_SECRET, VERIFIER_1_SECRET};
use crate::transactions::base::Input;
use bitcoin::PublicKey;
use bitcoin::{Network, OutPoint};
use clap::{arg, ArgMatches, Command};
use colored::Colorize;
use std::io::{self, Write};
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::sleep;

pub struct CommonArgs {
    pub key_dir: Option<String>,
    pub verifiers: Option<Vec<PublicKey>>,
    pub environment: Option<String>,
}

pub struct ClientCommand {
    client: BitVMClient,
}

impl ClientCommand {
    pub async fn new(common_args: CommonArgs) -> Self {
        let (source_network, destination_network) = match common_args.environment.as_deref() {
            Some("mainnet") => (Network::Bitcoin, DestinationNetwork::Ethereum),
            Some("testnet") => (Network::Testnet, DestinationNetwork::EthereumSepolia),
            _ => {
                eprintln!("Invalid environment. Use mainnet, testnet.");
                std::process::exit(1);
            }
        };

        let keys_command = KeysCommand::new(common_args.key_dir);
        let config = keys_command.read_config().expect("Failed to read config");

        let n_of_n_public_keys = common_args.verifiers.unwrap_or_else(|| {
            let (_, verifier_0_public_key) =
                generate_keys_from_secret(Network::Bitcoin, VERIFIER_0_SECRET);
            let (_, verifier_1_public_key) =
                generate_keys_from_secret(Network::Bitcoin, VERIFIER_1_SECRET);
            vec![verifier_0_public_key, verifier_1_public_key]
        });

        let bitvm_client = BitVMClient::new(
            source_network,
            destination_network,
            &n_of_n_public_keys,
            config.keys.depositor.as_deref(),
            config.keys.operator.as_deref(),
            config.keys.verifier.as_deref(),
            config.keys.withdrawer.as_deref(),
            None,
        )
        .await;

        Self {
            client: bitvm_client,
        }
    }

    pub fn get_depositor_address_command() -> Command {
        Command::new("get-depositor-address")
            .short_flag('d')
            .about("Get an address spendable by the registered depositor key")
            .after_help("Get an address spendable by the registered depositor key")
    }

    pub async fn handle_get_depositor_address(&mut self) -> io::Result<()> {
        let address = self.client.get_depositor_address().to_string();
        println!("{address}");
        Ok(())
    }

    pub fn get_depositor_utxos_command() -> Command {
        Command::new("get-depositor-utxos")
            .short_flag('u')
            .about("Get a list of the depositor's utxos")
            .after_help("Get a list of the depositor's utxos")
    }

    pub async fn handle_get_depositor_utxos(&mut self) -> io::Result<()> {
        for utxo in self.client.get_depositor_utxos().await {
            println!("{}:{} {}", utxo.txid, utxo.vout, utxo.value);
        }
        Ok(())
    }

    pub fn get_initiate_peg_in_command() -> Command {
        Command::new("initiate-peg-in")
        .short_flag('p')
        .about("Initiate a peg-in")
        .after_help("Initiate a peg-in by creating a peg-in graph")
        .arg(arg!(-u --utxo <UTXO> "Specify the uxo to spend from. Format: <TXID>:<VOUT>")
        .required(true))
        .arg(arg!(-d --destination_address <EVM_ADDRESS> "The evm-address to send the wrapped bitcoin to")
            .required(true))
    }

    pub async fn handle_initiate_peg_in_command(
        &mut self,
        sub_matches: &ArgMatches,
    ) -> io::Result<()> {
        let utxo = sub_matches.get_one::<String>("utxo").unwrap();
        let evm_address = sub_matches
            .get_one::<String>("destination_address")
            .unwrap();
        let outpoint = OutPoint::from_str(utxo).unwrap();

        let tx = self.client.esplora.get_tx(&outpoint.txid).await.unwrap();
        let tx = tx.unwrap();
        let input = Input {
            outpoint,
            amount: tx.output[outpoint.vout as usize].value,
        };
        let peg_in_id = self.client.create_peg_in_graph(input, evm_address).await;

        self.client.flush().await;

        println!("Created peg-in with ID {peg_in_id}. Broadcasting deposit...");

        let txid = self.client.broadcast_peg_in_deposit(&peg_in_id).await;

        println!("Broadcasted peg-in deposit with txid {txid}");

        Ok(())
    }

    pub fn get_automatic_command() -> Command {
        Command::new("automatic")
            .short_flag('a')
            .about("Automatic mode: Poll for status updates and sign or broadcast transactions")
    }

    pub async fn handle_automatic_command(&mut self) -> io::Result<()> {
        loop {
            self.client.sync().await;

            let old_data = self.client.get_data().clone();

            self.client.process_peg_ins().await;
            self.client.process_peg_outs().await;

            // A bit inefficient, but fine for now: only flush if data changed
            if self.client.get_data() != &old_data {
                self.client.flush().await;
            } else {
                sleep(Duration::from_millis(250)).await;
            }
        }
    }

    pub fn get_broadcast_command() -> Command {
        Command::new("broadcast")
            .short_flag('b')
            .about("Broadcast transactions")
            .after_help("Broadcast transactions.")
            .subcommand(
                Command::new("pegin")
                    .about("Broadcast peg-in transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-in graph ID").required(true))
                    .subcommand(Command::new("deposit").about("Broadcast peg-in deposit"))
                    .subcommand(Command::new("refund").about("Broadcast peg-in refund"))
                    .subcommand(Command::new("confirm").about("Broadcast peg-in confirm"))
                    .subcommand_required(true),
            )
            .subcommand(
                Command::new("tx")
                    .about("Broadcast transactions")
                    .arg(arg!(-g --graph_id <GRAPH_ID> "Peg-out graph ID").required(true))
                    .subcommand(Command::new("peg_out_confirm").about("Broadcast peg-out confirm"))
                    .subcommand(Command::new("kick_off_1").about("Broadcast kick off 1"))
                    .subcommand(Command::new("kick_off_2").about("Broadcast kick off 2"))
                    .subcommand(Command::new("start_time").about("Broadcast start time"))
                    .subcommand(Command::new("assert").about("Broadcast assert"))
                    .subcommand(Command::new("take_1").about("Broadcast take 1"))
                    .subcommand(Command::new("take_2").about("Broadcast take 2"))
                    .subcommand_required(true),
            )
            .subcommand_required(true)
    }

    pub async fn handle_broadcast_command(&mut self, sub_matches: &ArgMatches) -> io::Result<()> {
        let subcommand = sub_matches.subcommand();
        let graph_id = subcommand.unwrap().1.get_one::<String>("graph_id").unwrap();

        match subcommand.unwrap().1.subcommand() {
            Some(("deposit", _)) => {
                self.client.broadcast_peg_in_deposit(graph_id).await;
            }
            Some(("refund", _)) => {
                self.client.broadcast_peg_in_refund(graph_id).await;
            }
            Some(("confirm", _)) => {
                self.client.broadcast_peg_in_confirm(graph_id).await;
            }
            Some(("peg_out_confirm", _)) => self.client.broadcast_peg_out_confirm(graph_id).await,
            Some(("kick_off_1", _)) => self.client.broadcast_kick_off_1(graph_id).await,
            Some(("kick_off_2", _)) => self.client.broadcast_kick_off_2(graph_id).await,
            Some(("start_time", _)) => self.client.broadcast_start_time(graph_id).await,
            Some(("assert_initial", _)) => self.client.broadcast_assert_initial(graph_id).await,
            Some(("assert_final", _)) => self.client.broadcast_assert_final(graph_id).await,
            Some(("take_1", _)) => self.client.broadcast_take_1(graph_id).await,
            Some(("take_2", _)) => self.client.broadcast_take_2(graph_id).await,
            _ => unreachable!(),
        };

        Ok(())
    }

    pub fn get_status_command() -> Command {
        Command::new("status")
            .short_flag('s')
            .about("Show the status of the BitVM client")
            .after_help("Get the status of the BitVM client.")
    }

    pub async fn handle_status_command(&mut self) -> io::Result<()> {
        self.client.sync().await;
        self.client.status().await;
        Ok(())
    }

    pub fn get_interactive_command() -> Command {
        Command::new("interactive")
            .short_flag('i')
            .about("Interactive mode for manually issuing commands")
    }

    pub async fn handle_interactive_command(&mut self, main_command: &Command) -> io::Result<()> {
        println!(
            "{}",
            "Entering interactive mode. Type 'help' for a list of commands and 'exit' to quit."
                .green()
        );

        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        loop {
            print!("{}", "bitvm >> ".bold());
            io::stdout().flush().unwrap(); // Ensure the prompt is printed out immediately

            let mut line = String::new();
            stdin_reader.read_line(&mut line).await.unwrap();
            let input = line.trim();

            if input == "exit" {
                break;
            }

            let mut args = vec!["bitvm"];
            args.extend(input.split_whitespace());

            let matches = match main_command.clone().try_get_matches_from(args) {
                Ok(matches) => matches,
                Err(e) => {
                    if !e.to_string().to_lowercase().contains("error") {
                        println!("{}", format!("{}", e).green());
                    } else {
                        println!("{}", format!("{}", e).red());
                    }
                    continue;
                }
            };

            if let Some(sub_matches) = matches.subcommand_matches("keys") {
                let key_dir = matches.get_one::<String>("key-dir").cloned();
                let keys_command = KeysCommand::new(key_dir);
                keys_command.handle_command(sub_matches)?;
            } else if matches
                .subcommand_matches("get-depositor-address")
                .is_some()
            {
                self.handle_get_depositor_address().await?;
            } else if matches.subcommand_matches("get-depositor-utxos").is_some() {
                self.handle_get_depositor_utxos().await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("initiate-peg-in") {
                self.handle_initiate_peg_in_command(sub_matches).await?;
            } else if matches.subcommand_matches("status").is_some() {
                self.handle_status_command().await?;
            } else if let Some(sub_matches) = matches.subcommand_matches("broadcast") {
                self.handle_broadcast_command(sub_matches).await?;
            } else if matches.subcommand_matches("automatic").is_some() {
                self.handle_automatic_command().await?;
            } else if matches.subcommand_matches("interactive").is_some() {
                println!("{}", "Already in interactive mode.".yellow());
            } else {
                println!(
                    "{}",
                    "Unknown command. Type 'help' for a list of commands.".red()
                );
            }
        }

        println!("{}", "Exiting interactive mode.".green());
        Ok(())
    }
}
