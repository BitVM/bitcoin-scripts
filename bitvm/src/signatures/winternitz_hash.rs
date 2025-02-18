use crate::treepp::*;
use super::winternitz::*;
use crate::hash::blake3::blake3_160_var_length;
use bitcoin::Witness;
use blake3::hash;

const MESSAGE_HASH_LEN: u32 = 20;
/// Winternitz parameters for the 20 byte blake3 variant with the block length 4
pub static WINTERNITZ_HASH_PARAMETERS: Parameters = Parameters::new_by_bit_length(MESSAGE_HASH_LEN * 8, 4);

/// Winternitz verifier for the 20 byte blake3 variant (can be used with other parameters), returns the message in bytes 
pub static WINTERNITZ_HASH_VERIFIER: Winternitz::<ListpickVerifier, ToBytesConverter> = Winternitz::new();

/// Winternitz verifier, returns the message in blocks
pub static WINTERNITZ_MESSAGE_VERIFIER: Winternitz::<ListpickVerifier, VoidConverter> = Winternitz::new();

/// Winternitz verifier, returns the message in in bytes
pub static WINTERNITZ_VARIABLE_VERIFIER: Winternitz::<ListpickVerifier, ToBytesConverter> = Winternitz::new();


/// Verify a Winternitz signature for the hash of the top `input_len` many bytes on the stack
/// The hash function is blake3 with a 20-byte digest size
/// Fails if the signature is invalid
pub fn check_hash_sig(public_key: &PublicKey, input_len: usize) -> Script {
    script! {
        { WINTERNITZ_HASH_VERIFIER.checksig_verify(&WINTERNITZ_HASH_PARAMETERS, public_key) }
        for _ in 0..MESSAGE_HASH_LEN {
            OP_TOALTSTACK
        }
        { blake3_160_var_length(input_len) }
        for _ in 0..MESSAGE_HASH_LEN / 4 {
            for j in 0..4 {
                { 3 - j }
                OP_ROLL
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
        }
    }
}

/// Create a Winternitz signature for the blake3 hash of a given message
pub fn sign_hash(sec_key: &Vec<u8>, message: &[u8]) -> Witness {
    let message_hash = hash(message);
    let message_hash_bytes = &message_hash.as_bytes()[0..20];
    WINTERNITZ_HASH_VERIFIER.sign(&WINTERNITZ_HASH_PARAMETERS, sec_key, &message_hash_bytes.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    const MY_SEC_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_check_hash_sig() {
        // My secret key 
        let secret_key = match hex::decode(MY_SEC_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let public_key = generate_public_key(&WINTERNITZ_HASH_PARAMETERS, &secret_key);
        let message = *b"This is an arbitrary length input intended for testing purposes....";
        let s = script! {
            for byte in message.iter().rev() {
                { *byte }
            }
            { sign_hash(&secret_key, &message) }
            { check_hash_sig(&public_key, message.len()) }
            OP_TRUE
        };
        run(s);
    }

}
