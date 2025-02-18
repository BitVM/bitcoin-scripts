use bitcoin::Witness;
use serde::{Deserialize, Serialize};

use crate::signatures::winternitz_hash::WINTERNITZ_VARIABLE_VERIFIER;
use crate::treepp::{script, Script};
use crate::{
    signatures::{
        winternitz::{generate_public_key, Parameters, PublicKey, SecretKey},
        winternitz_hash::{sign_hash, WINTERNITZ_MESSAGE_VERIFIER},
    },
    u32::u32_std::u32_compress,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret {
    secret_key: SecretKey,
    parameters: Parameters,
}

// Bits per digit (block)
pub const LOG_D: u32 = 4;

impl WinternitzSecret {
    /// Generate a random 160 bit number and return a hex encoded representation of it.
    pub fn new(message_size: usize) -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        // Best parameters depend on the stack depth, without that limitation best option is LOG_D = 4 and used Winternitz version here
        //let parameters = WINTERNITZ_HASH_PARAMETERS;
        let parameters = Parameters::new_by_bit_length(message_size as u32 * 8, LOG_D);
        WinternitzSecret {
            secret_key: hex::encode(buffer).into(),
            parameters,
        }
    }

    pub fn from_string(secret: &str, parameters: &Parameters) -> Self {
        WinternitzSecret {
            secret_key: hex::encode(secret.as_bytes()).into(),
            parameters: parameters.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzPublicKey {
    pub public_key: PublicKey,
    pub parameters: Parameters,
}

impl From<&WinternitzSecret> for WinternitzPublicKey {
    fn from(secret: &WinternitzSecret) -> Self {
        WinternitzPublicKey {
            public_key: generate_public_key(&secret.parameters, &secret.secret_key),
            parameters: secret.parameters.clone(),
        }
    }
}

pub struct WinternitzSigningInputs<'a, 'b> {
    pub message: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_checksig_leave_hash(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for i in 1..message_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_checksig_leave_variable(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    assert_eq!(message_size % 4, 0, "message should be u32s");
    let u32s_size = message_size / 4;
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for _ in 0..u32s_size {
            {u32_compress()}
            OP_TOALTSTACK
        }
        for _ in 0..u32s_size {
            OP_FROMALTSTACK
        }
        for i in 1..u32s_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_hash_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    sign_hash(
        &signing_inputs.signing_key.secret_key,
        signing_inputs.message,
    )
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    WINTERNITZ_MESSAGE_VERIFIER.sign(
        &signing_inputs.signing_key.parameters,
        &signing_inputs.signing_key.secret_key,
        &signing_inputs.message.to_vec(),
    )
}

pub fn winternitz_message_checksig(public_key: &WinternitzPublicKey) -> Script {
    WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)
}

pub fn winternitz_message_checksig_verify(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        { WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key) }
        // TODO(LucidLuckylee): Instead of using OP_DROP use a Winternitz Verifier that consumes
        // the message
        for _ in 0..message_size {
            OP_DROP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{WinternitzPublicKey, WinternitzSecret};
    use crate::chunker::common::{equalverify, extract_witness_from_stack, u32_witness_to_bytes};
    use crate::execute_script_with_inputs;
    use crate::{
        bn254::g1::G1Affine,
        chunker::common::BLAKE3_HASH_LENGTH,
        execute_script,
        signatures::{utils::digits_to_number, winternitz::generate_public_key},
    };
    use ark_ff::UniformRand as _;
    use ark_std::test_rng;
    use bitcoin_script::script;
    use rand::{RngCore as _, SeedableRng as _};

    #[test]
    fn test_signing_winternitz_with_message_success() {
        let secret = WinternitzSecret::new(4);
        let public_key = WinternitzPublicKey::from(&secret);
        let start_time_block_number = 860033_u32;

        let s = script! {
          { generate_winternitz_witness(
            &WinternitzSigningInputs {
              message: &start_time_block_number.to_le_bytes(),
              signing_key: &secret,
          },
          ).to_vec() }
          { winternitz_message_checksig(&public_key) }
          { digits_to_number::<{ 4 * 2}, { LOG_D as usize }>() }
          { start_time_block_number }
          OP_EQUAL
        };

        let result = execute_script(s);

        assert!(result.success);
    }

    #[test]
    fn test_generate_winternitz_secret_length() {
        // Uses an arbitrary message size of 1
        let secret = WinternitzSecret::new(1);
        assert_eq!(
            secret.secret_key.len(),
            40,
            "Secret: {0:?}",
            secret.secret_key
        );
    }

    #[test]
    fn test_winternitz_public_key_from_secret() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);
        let reference_public_key = generate_public_key(&secret.parameters, &secret.secret_key);

        for i in 0..secret.parameters.total_length() {
            assert_eq!(
                public_key.public_key[i as usize],
                reference_public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);

        assert_eq!(
            public_key.public_key.len(),
            public_key.parameters.total_length() as usize
        );
        for i in 0..public_key.parameters.total_length() {
            assert_eq!(
                public_key.public_key[i as usize].len(),
                20,
                "public_key[{}]: {:?}",
                i,
                public_key.public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_recover_g1_point_on_stack() {
        let g1_point_bytes_length = 9 * 4 * 2; // two fq element
        let secret = WinternitzSecret::new(g1_point_bytes_length);
        let public_key = WinternitzPublicKey::from(&secret);

        // random g1 point
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let random_g1_point = ark_bn254::G1Affine::rand(&mut rng);

        let res = execute_script(script! {
            {G1Affine::push(random_g1_point.clone())}
        });
        let g1_to_bytes = u32_witness_to_bytes(extract_witness_from_stack(res));
        println!("g1_to_bytes: {:?}", g1_to_bytes);

        let witness = generate_winternitz_witness(&WinternitzSigningInputs {
            message: &g1_to_bytes,
            signing_key: &secret,
        });

        let s = script! {
            { generate_winternitz_checksig_leave_variable(&public_key, g1_point_bytes_length) }
            {G1Affine::push(random_g1_point)}
            {equalverify(g1_point_bytes_length / 4)}
            OP_TRUE
        };

        let result = execute_script_with_inputs(s, witness.to_vec());

        println!("result: {:?}", result);
        assert!(result.success);
    }
}
