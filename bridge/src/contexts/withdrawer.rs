use bitcoin::{key::Keypair, Network, PublicKey, XOnlyPublicKey};

use super::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

pub struct WithdrawerContext {
    pub network: Network,

    pub withdrawer_keypair: Keypair,
    pub withdrawer_public_key: PublicKey,
    pub withdrawer_taproot_public_key: XOnlyPublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for WithdrawerContext {
    fn network(&self) -> Network { self.network }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> { &self.n_of_n_public_keys }
    fn n_of_n_public_key(&self) -> &PublicKey { &self.n_of_n_public_key }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey { &self.n_of_n_taproot_public_key }
}

impl WithdrawerContext {
    pub fn new(
        network: Network,
        withdrawer_secret: &str,
        n_of_n_public_keys: &[PublicKey],
    ) -> Self {
        let (keypair, public_key) = generate_keys_from_secret(network, withdrawer_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        WithdrawerContext {
            network,

            withdrawer_keypair: keypair,
            withdrawer_public_key: public_key,
            withdrawer_taproot_public_key: XOnlyPublicKey::from(public_key),

            n_of_n_public_keys: n_of_n_public_keys.to_owned(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
