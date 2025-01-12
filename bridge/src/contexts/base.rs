use bitcoin::{
    key::Keypair, secp256k1::PublicKey as Secp256k1PublicKey, Network, PrivateKey, PublicKey,
    XOnlyPublicKey,
};
use musig2::{secp::Point, KeyAggContext};
use secp256k1::SECP256K1;

pub trait BaseContext {
    fn network(&self) -> Network;
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey>;
    fn n_of_n_public_key(&self) -> &PublicKey;
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey;
}

pub fn generate_keys_from_secret(network: Network, secret: &str) -> (Keypair, PublicKey) {
    let keypair = Keypair::from_seckey_str(SECP256K1, secret).unwrap();
    let private_key = PrivateKey::new(keypair.secret_key(), network);
    let public_key = PublicKey::from_private_key(SECP256K1, &private_key);

    (keypair, public_key)
}

pub fn generate_n_of_n_public_key(n_of_n_public_keys: &[PublicKey]) -> (PublicKey, XOnlyPublicKey) {
    let public_keys: Vec<Point> = n_of_n_public_keys
        .iter()
        .map(|&public_key| public_key.inner.into())
        .collect();

    let key_agg_context = KeyAggContext::new(public_keys).unwrap();
    let aggregated_key: Secp256k1PublicKey = key_agg_context.aggregated_pubkey();

    let n_of_n_public_key = PublicKey::from(aggregated_key);
    let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);

    (n_of_n_public_key, n_of_n_taproot_public_key)
}
