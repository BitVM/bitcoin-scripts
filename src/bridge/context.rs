use bitcoin::{
    key::{Keypair, Secp256k1}, secp256k1::All, Network, PrivateKey, PublicKey, XOnlyPublicKey
};

use std::str::FromStr;

pub static UNSPENDABLE_PUBLIC_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct BridgeContext {
    pub secp: Secp256k1<All>,

    pub operator_public_key: Option<PublicKey>,
    pub operator_keypair: Option<Keypair>,
    pub operator_taproot_public_key: Option<XOnlyPublicKey>,

    pub n_of_n_public_key: Option<PublicKey>,
    pub n_of_n_keypair: Option<Keypair>,
    pub n_of_n_taproot_public_key: Option<XOnlyPublicKey>,

    pub depositor_public_key: Option<PublicKey>,
    pub depositor_keypair: Option<Keypair>,
    pub depositor_taproot_public_key: Option<XOnlyPublicKey>,
    
    pub withdrawer_public_key: Option<PublicKey>,
    pub withdrawer_keypair: Option<Keypair>,
    pub withdrawer_taproot_public_key: Option<XOnlyPublicKey>,

    pub unspendable_public_key: Option<PublicKey>,
    pub unspendable_taproot_public_key: Option<XOnlyPublicKey>,

    pub evm_address: Option<String>
    // TODO: current_height: Height,
    // TODO: participants secret for the n-of-n keypair
    // TODO: Store learned preimages here
}

impl Default for BridgeContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeContext {
    pub fn new() -> Self {
        BridgeContext {
            secp: Secp256k1::new(),

            operator_public_key: None,
            operator_keypair: None,
            operator_taproot_public_key: None,

            n_of_n_public_key: None,
            n_of_n_keypair: None,
            n_of_n_taproot_public_key: None,
        
            depositor_public_key: None,
            depositor_keypair: None,
            depositor_taproot_public_key: None,
            
            withdrawer_public_key: None,
            withdrawer_keypair: None,
            withdrawer_taproot_public_key: None,
        
            unspendable_public_key: None,
            unspendable_taproot_public_key: None,
            // unspendable_public_key: Some(PublicKey::from_str(UNSPENDABLE_PUBLIC_KEY).unwrap()),
            // unspendable_taproot_public_key: Some(XOnlyPublicKey::from_str(
            //     UNSPENDABLE_PUBLIC_KEY
            // ).unwrap()),

            evm_address: None
        }
    }

    pub fn initialize_evm_address(&mut self, evm_address: &str) {
        self.evm_address = Some(evm_address.to_string());
    }

    pub fn initialize_operator(&mut self, secret: &str) {
        self.operator_keypair = Some(Keypair::from_seckey_str(&self.secp, secret).unwrap());
        self.operator_taproot_public_key = Some(self.operator_keypair.unwrap().x_only_public_key().0);

        let operator_private_key = Some(PrivateKey::new(self.operator_keypair.unwrap().secret_key(), Network::Testnet));
        self.operator_public_key = Some(PublicKey::from_private_key(&self.secp, &operator_private_key.unwrap()));
    }

    pub fn initialize_n_of_n(&mut self, secret: &str) {
        self.n_of_n_keypair = Some(Keypair::from_seckey_str(&self.secp, secret).unwrap());
        self.n_of_n_taproot_public_key = Some(self.n_of_n_keypair.unwrap().x_only_public_key().0);

        let n_of_n_private_key = Some(PrivateKey::new(self.n_of_n_keypair.unwrap().secret_key(), Network::Testnet));
        self.n_of_n_public_key = Some(PublicKey::from_private_key(&self.secp, &n_of_n_private_key.unwrap()));
    }

    pub fn initialize_depositor(&mut self, secret: &str) {
        self.depositor_keypair = Some(Keypair::from_seckey_str(&self.secp, secret).unwrap());
        self.depositor_taproot_public_key = Some(self.depositor_keypair.unwrap().x_only_public_key().0);

        let depositor_private_key = Some(PrivateKey::new(self.depositor_keypair.unwrap().secret_key(), Network::Testnet));
        self.depositor_public_key = Some(PublicKey::from_private_key(&self.secp, &depositor_private_key.unwrap()));
    }

    pub fn initialize_withdrawer(&mut self, secret: &str) {
        self.withdrawer_keypair = Some(Keypair::from_seckey_str(&self.secp, secret).unwrap());
        self.withdrawer_taproot_public_key = Some(self.withdrawer_keypair.unwrap().x_only_public_key().0);

        let withdrawer_private_key = Some(PrivateKey::new(self.withdrawer_keypair.unwrap().secret_key(), Network::Testnet));
        self.withdrawer_public_key = Some(PublicKey::from_private_key(&self.secp, &withdrawer_private_key.unwrap()));
    }
}
