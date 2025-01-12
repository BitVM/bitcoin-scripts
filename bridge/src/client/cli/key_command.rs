use bitcoin::{Network, PublicKey};
use clap::{arg, ArgGroup, ArgMatches, Command};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use toml;

use crate::contexts::base::generate_keys_from_secret;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub keys: Keys,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Keys {
    pub depositor: Option<String>,
    pub operator: Option<String>,
    pub verifier: Option<String>,
    pub withdrawer: Option<String>,
}

pub struct KeysCommand {
    pub config_path: PathBuf,
}

impl KeysCommand {
    pub fn new(key_dir: Option<String>) -> Self {
        let bitvm_dir = key_dir.map(PathBuf::from).unwrap_or_else(|| {
            let home_dir = env::var("HOME").expect("Could not find home directory");
            PathBuf::from(&home_dir).join(".bitvm")
        });

        let config_path = bitvm_dir.join("bitvm-cli-env.toml");

        // Create .bitvm directory if it doesn't exist
        if !bitvm_dir.exists() {
            fs::create_dir_all(&bitvm_dir).expect("Failed to create .bitvm directory");
        }

        KeysCommand { config_path }
    }

    pub fn get_command() -> Command {
        Command::new("keys")
            .short_flag('k')
            .about("Manage secret keys for different contexts")
            .after_help("The depositor, operator, verifier, and withdrawer contexts are optional and can be specified using the -d, -o, -v, and -w flags respectively. If a context is not specified, the default key for that context will be used.")
            .arg(arg!(-d --depositor <SECRET_KEY> "Secret key for depositor").required(false))
            .arg(arg!(-o --operator <SECRET_KEY> "Secret key for operator").required(false))
            .arg(arg!(-v --verifier <SECRET_KEY> "Secret key for verifier").required(false))
            .arg(arg!(-w --withdrawer <SECRET_KEY> "Secret key for withdrawer").required(false))
            .group(ArgGroup::new("context")
                .args(["depositor", "operator", "verifier", "withdrawer"])
                .required(true))
    }

    pub fn handle_command(&self, sub_matches: &ArgMatches) -> io::Result<()> {
        let mut config = self.read_config()?;

        if let Some(secret_key) = sub_matches.get_one::<String>("depositor") {
            if self.validate_key(secret_key) {
                config.keys.depositor = Some(secret_key.clone());
                println!(
                    "Secret key for depositor {} saved successfully!",
                    pubkey_of(secret_key)
                );
            } else {
                println!("error: Invalid depositor secret key.");
            }
        } else if let Some(secret_key) = sub_matches.get_one::<String>("operator") {
            if self.validate_key(secret_key) {
                config.keys.operator = Some(secret_key.clone());
                println!(
                    "Secret key for operator {} saved successfully!",
                    pubkey_of(secret_key)
                );
            } else {
                println!("error: Invalid operator secret key.");
            }
        } else if let Some(secret_key) = sub_matches.get_one::<String>("verifier") {
            if self.validate_key(secret_key) {
                config.keys.verifier = Some(secret_key.clone());
                println!(
                    "Secret key for verifier {} saved successfully!",
                    pubkey_of(secret_key)
                );
            } else {
                println!("error: Invalid verifier secret key.");
            }
        } else if let Some(secret_key) = sub_matches.get_one::<String>("withdrawer") {
            if self.validate_key(secret_key) {
                config.keys.withdrawer = Some(secret_key.clone());
                println!(
                    "Secret key for withdrawer {} saved successfully!",
                    pubkey_of(secret_key)
                );
            } else {
                eprintln!("error: Invalid withdrawer secret key.");
                std::process::exit(1);
            }
        } else {
            eprintln!("Invalid command. Use --help to see the valid commands.");
            std::process::exit(1);
        }

        self.write_config(&config)
    }

    pub fn read_config(&self) -> io::Result<Config> {
        if self.config_path.exists() {
            let mut file = OpenOptions::new().read(true).open(&self.config_path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            Ok(toml::from_str(&content).unwrap_or_default())
        } else {
            Ok(Config::default())
        }
    }

    pub fn write_config(&self, config: &Config) -> io::Result<()> {
        let toml_string = toml::to_string(config).expect("Failed to serialize config");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.config_path)?;
        file.write_all(toml_string.as_bytes())
    }

    fn validate_key(&self, key: &str) -> bool {
        key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
    }
}
fn pubkey_of(private_key: &str) -> PublicKey {
    generate_keys_from_secret(Network::Bitcoin, private_key).1
}
