use bitcoin_script::script;

use crate::chunk::primitives::pack_bytes_to_limbs;
use crate::pseudo::NMUL;
use crate::treepp::Script;
use crate::signatures::wots_api::{wots160, wots256};



pub(crate) fn checksig_verify_to_limbs(pub_key: &WOTSPubKey) -> Script {
    match pub_key {
        WOTSPubKey::P160(pb) => {
            let sc_nib = wots160::compact::checksig_verify(*pb);
            const N0: usize = 40;
            script!{
                {sc_nib}
                for _ in 0..(64-N0) { // padding
                    {0}
                }
                for i in 1..64 { // sig order reversal
                    {i} OP_ROLL
                }
                // w-window to byte array
                for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }
                for _ in 0..32 { OP_FROMALTSTACK }
                // byte array to limbs
                {pack_bytes_to_limbs()} // equivalent to CompressedStateObject::deserialize_from_byte_array
            }
        },
        WOTSPubKey::P256(pb) => {
            let sc_nib = wots256::compact::checksig_verify(*pb);
            script!{
                {sc_nib}
                for i in 1..64 {
                    {i} OP_ROLL
                }
                for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }
                for _ in 0..32 { OP_FROMALTSTACK }
                {pack_bytes_to_limbs()}
            }
        },
    }
}

#[cfg(test)]
fn byte_array_to_wots160_sig(secret: &str, msg_bytes: &[u8]) -> wots160::Signature {
    wots160::get_signature(secret, msg_bytes)
} 

#[cfg(test)]
fn byte_array_to_wots256_sig(secret: &str, msg_bytes: &[u8]) -> wots256::Signature {
    wots256::get_signature(secret, msg_bytes)
} 

pub(crate) fn wots256_sig_to_byte_array(sig: wots256::Signature) -> Vec<u8> {
    let nibs = sig.map(|(_, digit)| digit);
    // [MSB, LSB, MSB, LSB, ..., checksum]
    let mut nibs = nibs[0..64].to_vec(); // remove checksum
    // [MSB, LSB, MSB, LSB]
    nibs.reverse(); // sigs are obtained in reverse order so undo
    // [LSB, MSB, LSB, MSB,.., LSB]
    let nibs = nibs
        .chunks(2)
        .map(|bn| (bn[1] << 4) + bn[0]) // endian assumed by wots
        .collect::<Vec<u8>>();
    nibs
}

pub(crate) fn wots160_sig_to_byte_array(sig: wots160::Signature) -> Vec<u8> {
    let nibs = sig.map(|(_, digit)| digit);
    // [MSB, LSB, MSB, LSB, ..., checksum]
    let mut nibs = nibs[0..40].to_vec(); // remove checksum
    // [MSB, LSB, MSB, LSB]
    nibs.reverse(); // sigs are obtained in reverse order so undo
    // [LSB, MSB, LSB, MSB,.., LSB]
    let nibs = nibs
        .chunks(2)
        .map(|bn| (bn[1] << 4) + bn[0]) // endian assumed by wots
        .collect::<Vec<u8>>();
    nibs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WOTSPubKey {
    P160(wots160::PublicKey),
    P256(wots256::PublicKey)
}


#[cfg(test)]
mod test {
    use ark_ff::{Field, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use bitcoin_script::script;
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, chunk::{elements::CompressedStateObject, primitives::extern_hash_fps, wots::{byte_array_to_wots160_sig, byte_array_to_wots256_sig, checksig_verify_to_limbs, wots160_sig_to_byte_array, wots256_sig_to_byte_array, WOTSPubKey}}, execute_script, signatures::wots_api::{wots160, wots256, SignatureImpl}};

    #[test]
    fn test_wots256_sig_to_byte_array() {
        // wots sig to limbs
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let f = ark_bn254::Fq::rand(&mut prng);
        let a: ark_ff::BigInt<4> = f.into();
        let a = CompressedStateObject::U256(a);
        let a_bytes = a.clone().serialize_to_byte_array();

        let secret: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";
        let signature = byte_array_to_wots256_sig(secret, &a_bytes);

        let msg_bytes = wots256_sig_to_byte_array(signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes);
        assert_eq!(a, msg);

        let sig_witness = signature.to_compact_script();
        let pub_key = WOTSPubKey::P256(wots256::generate_public_key(secret));
        let scr = script!(
            {sig_witness}
            {checksig_verify_to_limbs(&pub_key)}
            {a.as_hint_type().push()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        );
        let tap_len = scr.len();
        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_wots160_sig_to_byte_array() {
        // wots sig to limbs
        let mut prng = ChaCha20Rng::seed_from_u64(97);
        let a = ark_bn254::Fq6::rand(&mut prng);
        let a = extern_hash_fps(a.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>());
        let a = CompressedStateObject::Hash(a);
        let a_bytes = a.clone().serialize_to_byte_array();

        let secret: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";

        let signature = byte_array_to_wots160_sig(secret, &a_bytes);
        let msg_bytes = wots160_sig_to_byte_array(signature);
        assert_eq!(msg_bytes, a_bytes);
        let msg = CompressedStateObject::deserialize_from_byte_array(msg_bytes);
        assert_eq!(a, msg);

        let sig_witness = signature.to_compact_script();
        let pub_key = WOTSPubKey::P160(wots160::generate_public_key(secret));
        let scr = script!(
            {sig_witness}
            {checksig_verify_to_limbs(&pub_key)}
            {a.as_hint_type().push()}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        );
        let tap_len = scr.len();
        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }
}