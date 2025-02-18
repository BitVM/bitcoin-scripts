use super::utils::*;
use crate::treepp::*;
use bitcoin::{hashes::{hash160, Hash}, Witness};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;

/// Contains the parameters to use with `Winternitz` struct
#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Parameters {
    /// Number of blocks of the actual message 
    message_length: u32,
    /// Number of bits in one block
    block_length: u32,
    /// Number of blocks of the checksum part 
    checksum_length: u32
}

impl Parameters {
    /// Creates parameters with given message length (number of blocks in the message) and block length (number of bits in one block, in the closed range 4, 8)
    pub const fn new(message_block_count: u32, block_length: u32) -> Self {
        assert!(
            4 <= block_length && block_length <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        Parameters {
            message_length: message_block_count,
            block_length: block_length,
            checksum_length: log_base_ceil(((1 << block_length) - 1) * message_block_count, 1 << block_length) + 1,
        }
    }

    /// Creates parameters with given message_length (number of bits in the message) and block length (number of bits in one block, in the closed range 4, 8)
    pub const fn new_by_bit_length(number_of_bits: u32, block_length: u32) -> Self {
        assert!(
            4 <= block_length && block_length <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        let message_block_count = (number_of_bits + block_length - 1) / block_length;
        Parameters {
            message_length: message_block_count,
            block_length: block_length,
            checksum_length: log_base_ceil(((1 << block_length) - 1) * message_block_count, 1 << block_length) + 1,
        }
    }

    /// Maximum value of a digit
    fn d(&self) -> u32 {
        (1 << self.block_length) - 1
    }

    /// Number of bytes that can be represented at maximum with the parameters
    fn byte_message_length(&self) -> u32 {
        (self.message_length * self.block_length + 7) / 8
    }

    /// Total number of blocks, i.e. sum of the number of blocks in the actual message and the checksum
    pub fn total_length(&self) -> u32 {
        self.message_length + self.checksum_length
    }
}


/// Returns the signature of a given digit (block), requires the digit index to modify the secret key for each digit 
pub fn digit_signature(secret_key: &SecretKey, digit_index: u32, message_digit: u32) -> HashOut {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hash160::Hash::hash(&secret_i);
    for _ in 0..message_digit {
        hash = hash160::Hash::hash(&hash[..]);
    }
    *hash.as_byte_array()
}

/// Returns the public key of a given digit (block), requires the digit index to modify the secret key for each digit 
fn public_key_for_digit(ps: &Parameters, secret_key: &SecretKey, digit_index: u32) -> HashOut {
    digit_signature(secret_key, digit_index, ps.d())
}

/// Returns the public key for the given secret key and the parameters
pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::with_capacity(ps.total_length() as usize);
    for i in 0..ps.total_length() {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

/// Checksum of the message (negated sum of the digits)
fn checksum(ps: &Parameters, digits: Vec<u32>) -> u32 {
    let mut sum = 0;
    for digit in digits {
        sum += digit;
    }
    ps.d() * ps.message_length - sum
}

/// Appends checksum to the given message (digits), and reverses the whole message (with checksum) for the ease of usage in the bitcoin script
fn add_message_checksum(ps: &Parameters, mut digits: Vec<u32>) -> Vec<u32> {
    let mut checksum_digits = to_digits(checksum(ps, digits.clone()), ps.d() + 1, ps.checksum_length as i32);
    checksum_digits.append(&mut digits);
    checksum_digits.reverse();
    checksum_digits
}

/// This trait covers 3 verifiers for the signing and verifying phase of the signatures: `ListpickVerifier`, `BruteforceVerifier`, `BinarysearchVerifier`
pub trait Verifier {
    /// Default digit signatures for `ListpickVerifier` and `BinarysearchVerifier`, in the format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, digits);
        let mut result = Witness::new();
        for i in 0..ps.total_length() {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            result.push(sig.to_vec());
            result.push(u32_to_le_bytes_minimal(digits[i as usize]));
        }
        result
    }
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script;
}

/// This trait covers 2 converters for converting the final message (which is left in the form of blocks): `VoidConverter`, `ToBytesConverter`
pub trait Converter {
    /// Wrapper for converter functions 
    fn get_script(ps: &Parameters) -> Script;
    /// Length of the final message
    fn length_of_final_message(ps: &Parameters) -> u32;
}
/// Winternitz struct to used for its operations \
/// Sample Usage:
/// - Pick the algorithms you want to use, i.e. `BinarysearchVerifier` and `ToBytesConverter`
/// - Construct your struct: `let o = Winternitz::<BinarysearchVerifier, ToBytesConverter>::new()`
/// - Identify your message parameters:` let p = Parameters::new(message_block_count, block_length)` or `let p = Parameters::new_by_bit_length(number_of_bits_of_the_message, block_length)`
/// - Use the methods for the necessary operations, for example: `o.sign(&p, ...)`, `o.checksig_verify(&p, ...)`, `o.checksig_verify_remove_message(&p, ...)`
pub struct Winternitz<VERIFIER: Verifier, CONVERTER: Converter> {
    phantom0: PhantomData<VERIFIER>, 
    phantom1: PhantomData<CONVERTER>,
}

impl<VERIFIER: Verifier, CONVERTER: Converter> Default for Winternitz<VERIFIER, CONVERTER> {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the default functions regardless of the algorithms that are chosen
impl<VERIFIER: Verifier, CONVERTER: Converter> Winternitz<VERIFIER, CONVERTER> {
    pub const fn new() -> Self {
        Winternitz {
            phantom0: PhantomData,
            phantom1: PhantomData,
        }
    }

    /// Wrapper to sign the digits
    pub fn sign_digits(&self, ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
        VERIFIER::sign_digits(ps, secret_key, digits)
    }

    /// Wrapper to sign the message in bytes (converts to digits inside)
    pub fn sign(&self, ps: &Parameters, secret_key: &SecretKey, message_bytes: &Vec<u8>) -> Witness {
        VERIFIER::sign_digits(
            ps,
            secret_key,
            bytes_to_u32s(ps.message_length, ps.block_length, message_bytes),
        )
    }

    /// Expects the signature in the format of the used verification algorithm, start of the message being on the top and checksum being at the bottom, and verifies if the given signature is accurate leaving digits of the message on the stack start of it being on top
    pub fn checksig_verify(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            { VERIFIER::verify_digits(ps, public_key) }
            { self.verify_checksum(ps) }
            { CONVERTER::get_script(ps) }
        }
    }

    /// Expects the signature in the format of the used verification algorithm, start of the message being on the top and checksum being at the bottom, and verifies if the given signature is accurate without leaving any trace on stack
    pub fn checksig_verify_and_clear_stack(&self, ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            { VERIFIER::verify_digits(ps, public_key) }
            { self.verify_checksum(ps) }
            { CONVERTER::get_script(ps) }
            for _ in 0..(CONVERTER::length_of_final_message(ps) / 2) {
                OP_2DROP
            }
            if CONVERTER::length_of_final_message(ps) % 2 == 1 {
                OP_DROP
            }
        }
    }

    /// Verifies the checksum after the whole message is verified, expects the digits of the whole message at the alt stack, the first element of the message being at the bottom. \
    /// Removes the checksum digits and leaves the actual message on stack
    fn verify_checksum(&self, ps: &Parameters) -> Script {
        script! {
            OP_FROMALTSTACK OP_DUP OP_NEGATE 
            for _ in 1..ps.message_length {
                OP_FROMALTSTACK OP_TUCK OP_SUB // sum the digits and tuck them before the sum so they are stored for later
            }
            { ps.d() * ps.message_length }
            OP_ADD
            OP_FROMALTSTACK
            for _ in 0..ps.checksum_length - 1 {
                for _ in 0..ps.block_length {
                    OP_DUP OP_ADD
                }
                OP_FROMALTSTACK
                OP_ADD
            }
            OP_EQUALVERIFY
        }
    }
}



/// - Verification Algorithm: Generates hashes for each possible value and then uses `OP_PICK` to get the corresponding one from the created list. \
///   As a small improvement, it also divides the length of the list by 2 in the start 
/// - Signature format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0 (With digits) 
/// - Approximate Max Stack Depth Used During Verification: 2 * `total_length()` + (2 ^ `block_length`)/2   
pub struct ListpickVerifier {}
impl Verifier for ListpickVerifier {
    /// Expects the signature in the verifier's format, checks and verifies if the given signature is accurate with the given public key, leaving the message (with checksum) on the stack in given order
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_length() {
                // See https://github.com/BitVM/BitVM/issues/35
                { ps.d() }
                OP_MIN
                OP_DUP
                OP_TOALTSTACK
                { (ps.d() + 1) / 2 }
                OP_2DUP
                OP_LESSTHAN
                OP_IF
                    OP_DROP
                    OP_TOALTSTACK
                    for _ in 0..(ps.d() + 1) / 2  {
                        OP_HASH160
                    }
                OP_ELSE
                    OP_SUB
                    OP_TOALTSTACK
                OP_ENDIF
                for _ in 0..ps.d()/2 {
                    OP_DUP OP_HASH160
                }
                OP_FROMALTSTACK
                OP_PICK
                { (public_key[ps.total_length() as usize - 1 - digit_index as usize]).to_vec() }
                OP_EQUALVERIFY
                for _ in 0..(ps.d() + 1) / 4 {
                    OP_2DROP
                }
            }
        }
    }
}
/// - Verification Algorithm: Tries each possible digit value
/// - Signature Format: hash_{n - 1}, hash_{n - 2} ... hash_0 (Without digits)
/// - Approximate Max Stack Depth Used During Verification: `total_length()`
pub struct BruteforceVerifier {}
impl Verifier for BruteforceVerifier {
    /// Signature in the verifier's format
    fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: Vec<u32>) -> Witness {
        let digits = add_message_checksum(ps, digits);
        let mut result = Witness::new();
        for i in 0..ps.total_length() {
            let sig = digit_signature(secret_key, i, digits[i as usize]);
            result.push(sig.to_vec());
        }
        result
    }
    /// Expects the signature in the verifier's format, checks and verifies if the given signature is accurate with the given public key, leaving the message (with checksum) on the stack in given order
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_length() {
                { public_key[(ps.total_length() - 1 - digit_index) as usize].to_vec() }
                OP_SWAP
                { -1 } OP_TOALTSTACK // To avoid illegal stack acces, same -1 is checked later 
                OP_2DUP
                OP_EQUAL
                OP_IF
                    {ps.d()}
                    OP_TOALTSTACK
                OP_ENDIF
                for i in 0..ps.d() {
                    OP_HASH160
                    OP_2DUP
                    OP_EQUAL
                    OP_IF
                        { ps.d() - i - 1 }
                        OP_TOALTSTACK
                    OP_ENDIF
                }
                OP_2DROP
                OP_FROMALTSTACK
                OP_DUP
                { -1 }
                OP_NUMNOTEQUAL OP_VERIFY
                OP_FROMALTSTACK OP_DROP
                OP_TOALTSTACK
            }
        }
    }
}


/// - Verification Algorithm: Simulates a for loop of hashing using binary search on the digit
/// - Signature Format: hash_{n - 1}, digit_{n - 1}, hash_{n - 2}, digit_{n - 2} ... hash_0, digit_0 (With digits)
/// - Approximate Max Stack Depth Used During Verification: 2 * `total_length()`
pub struct BinarysearchVerifier {}
impl Verifier for BinarysearchVerifier {
    /// Expects the signature in the verifier's format, checks and verifies if the given signature is accurate with the given public key, leaving the message (with checksum) on the stack in given order
    fn verify_digits(ps: &Parameters, public_key: &PublicKey) -> Script {
        script! {
            for digit_index in 0..ps.total_length() {
                //one can send digits out of the range, i.e. negative or bigger than D for it to act as in range, so inorder for checksum to not be decreased, a lower bound check is necessary and enough
                OP_0
                OP_MAX
                OP_DUP
                OP_TOALTSTACK
                { ps.d() } OP_SWAP OP_SUB
                for bit in (0..ps.block_length).rev() {
                    if bit != 0 {
                        {1 << bit}
                        OP_2DUP
                        OP_GREATERTHANOREQUAL
                        OP_IF
                            OP_SUB
                            OP_SWAP
                            for _ in 0..(1 << bit) {
                                OP_HASH160
                            }
                            OP_SWAP
                            OP_DUP
                        OP_ENDIF
                        OP_DROP
                    } else {
                        OP_IF
                            OP_HASH160
                        OP_ENDIF
                    }
                }
                { (public_key[(ps.total_length() - 1 - digit_index) as usize]).to_vec() }
                OP_EQUALVERIFY
            }
        }
    }
}

/// Does nothing, leaving each stack each element as a block from Winternitz
pub struct VoidConverter {}
impl Converter for VoidConverter {
    fn length_of_final_message(ps: &Parameters) -> u32 {
        return ps.message_length;
    }
    fn get_script(ps: &Parameters) -> Script {
        let _ = ps;
        script! {}
    }
}

/// Alters message (divides it into 8 bit pieces), leaving each stack each element as a byte
pub struct ToBytesConverter {}
impl Converter for ToBytesConverter {
    fn length_of_final_message(ps: &Parameters) -> u32 {
        return ps.byte_message_length();
    }
    fn get_script(ps: &Parameters) -> Script {
        let mut turning_into_bytes = script! {};
        if ps.block_length == 8 {
            //already bytes
            turning_into_bytes = script! {};
        } else if ps.block_length == 4 {
            turning_into_bytes = script! {
                for i in 0..ps.message_length / 2 {
                    OP_SWAP
                    for _ in 0..ps.block_length {
                        OP_DUP OP_ADD
                    }
                    OP_ADD
                    if i != (ps.message_length/2) - 1 {
                        OP_TOALTSTACK
                    }
                }
                if ps.message_length > 1 {
                    for _ in 0..ps.message_length / 2 - 1{
                        OP_FROMALTSTACK
                    }
                }
            };
        } else {
            let mut lens: Vec<u32> = vec![];
            let mut script_lines: Vec<Script> = vec![];
            for i in 0..ps.message_length {
                let start = i * ps.block_length;
                let next_stop = start + 8 - (start % 8);
                let split = next_stop - start;
                if split >= ps.block_length {
                    lens.push(ps.block_length);
                    script_lines.push(script! {
                        OP_TOALTSTACK
                    });
                } else {
                    lens.push(split);
                    lens.push(ps.block_length - split);
                    script_lines.push(script! {
                        OP_0
                        for j in (split..ps.block_length).rev() {
                            if j != ps.block_length - 1 {
                                OP_DUP OP_ADD
                            }
                            OP_SWAP
                            {1 << j}
                            OP_2DUP
                            OP_GREATERTHANOREQUAL
                            OP_IF
                                OP_SUB
                                OP_SWAP
                                OP_1ADD
                                OP_SWAP
                                OP_DUP
                            OP_ENDIF
                            OP_DROP
                            OP_SWAP
                        }
                        OP_SWAP
                        OP_TOALTSTACK
                        OP_TOALTSTACK
                    });
                }
            }
            lens.reverse();
            let mut last_bytes = (8 - (ps.message_length * ps.block_length % 8)) % 8;
            let mut is_last_zero = true;
            script_lines.push(script! {
                OP_0
            });
            for l in lens {
                if last_bytes >= 8 {
                    last_bytes = 0;
                    script_lines.push(script! {
                        OP_0
                    });
                    is_last_zero = true;
                }
                if !is_last_zero {
                    script_lines.push(script! {
                        for _ in 0..l {
                            OP_DUP OP_ADD
                        }
                    });
                }
                is_last_zero = false;
                script_lines.push(script! {
                    OP_FROMALTSTACK
                    OP_ADD
                });
                last_bytes += l;
            }

            for script_line in script_lines {
                turning_into_bytes = turning_into_bytes.push_script(script_line.compile());
            }
        }
        turning_into_bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::sync::{LazyLock, Mutex};
    static MALICIOUS_RNG: LazyLock<Mutex<ChaCha20Rng>> =
        LazyLock::new(|| Mutex::new(ChaCha20Rng::seed_from_u64(337)));

    const SAMPLE_SECRET_KEY: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";
    const TEST_COUNT: u32 = 20;

    fn get_type_name<T>() -> String {
        let full_type_name = std::any::type_name::<T>();
        let res = full_type_name.split("::").last().unwrap_or(full_type_name);
        res.to_string()
    }

    // This test is not extensive and definitely misses corner cases
    fn try_malicious(ps: &Parameters, _message: &Vec<u8>, verifier: &str) -> Script {
        let mut rng = MALICIOUS_RNG.lock().unwrap();
        let ind = rng.gen_range(0..ps.total_length());
        if verifier == get_type_name::<BruteforceVerifier>() {
            script! {
                for _ in 0..ind {
                    OP_TOALTSTACK
                }
                for _ in 0..(rng.gen_range(1..20)) {
                    OP_HASH160
                }                for _ in 0..ind {
                    OP_FROMALTSTACK
                }
            }
        } else {
            let type_of_action = rng.gen_range(0..2);
            script! {
                for _ in 0..ind {
                    OP_TOALTSTACK OP_TOALTSTACK
                }
                if type_of_action == 0 {
                    OP_DROP {-1}
                } else {
                    OP_TOALTSTACK
                    for _ in 0..(rng.gen_range(1..20)) {
                        OP_HASH160
                    }
                    OP_FROMALTSTACK
                }
                for _ in 0..ind {
                    OP_FROMALTSTACK OP_FROMALTSTACK
                }
            }
        }
    }

    macro_rules! test_script {
        ($ps:expr, $s:expr, $message_checker:expr, $desired_outcome:expr) => {
            println!(
                "Winternitz signature size:\n \t{:?} bytes / {:?} bits \n\t{:?} bytes / bit\n",
                $s.len(),
                $ps.message_length * $ps.block_length,
                $s.len() as f64 / ($ps.message_length * $ps.block_length) as f64
            );
            if $desired_outcome == true {
                assert!(
                    execute_script($s.push_script($message_checker.clone().compile())).success
                        == true
                );
            } else {
                assert!(
                    execute_script($s.clone()).success == false
                        || execute_script($s.push_script($message_checker.clone().compile()))
                            .success
                            == true
                );
            }
        };
    }
    macro_rules! generate_winternitz_tests {
        (
            $ps:expr, $secret_key:expr, $public_key:expr, $message:expr, $message_checker:expr, $desired_outcome:expr;
            $([$verifier:ty, $converter:ty]),*
        ) => {
            $(
                {
                    let o = Winternitz::<$verifier, $converter>::new();
                    let standard_script = script! {
                        { o.sign(&$ps, &$secret_key, &$message) }
                        if $desired_outcome == false {
                             { try_malicious(&$ps, &$message, &get_type_name::<$verifier>()) }
                        }
                        { o.checksig_verify(&$ps, &$public_key) }
                    };

                    println!("For message_length:{} and block_length:{}  {} with {} =>", $ps.message_length, $ps.block_length, get_type_name::<$verifier>(), get_type_name::<$converter>());
                    test_script!($ps, standard_script, $message_checker, $desired_outcome);
                    if $desired_outcome == true {
                        let message_remove_script = script! {
                            { o.sign(&$ps, &$secret_key, &$message) }
                            { o.checksig_verify_and_clear_stack(&$ps, &$public_key) }
                            OP_TRUE
                        };
                        assert!(execute_script(message_remove_script).success == true);                    
                    }
                }
            )*
        };
    }

    #[test]
    fn test_winternitz_with_actual_message_success() {
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let ps = Parameters::new_by_bit_length(32, 4);
        let public_key = generate_public_key(&ps, &secret_key);

        let message = 860033 as u32;
        let message_bytes = &message.to_le_bytes();

        let winternitz_verifier = Winternitz::<ListpickVerifier, VoidConverter>::new();

        let s = script! {
            // sign
            { winternitz_verifier.sign(&ps, &secret_key, &message_bytes.to_vec()) }

            // check signature
            { winternitz_verifier.checksig_verify(&ps, &public_key) }
            
            // convert to number
            { digits_to_number::<8, 4>() }
            
             { message }
            
            OP_EQUAL
            
        };
        run(s);
    }

    #[test]
    fn test_winternitz_success() {
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
            let message_byte_size = ps.message_length * ps.block_length / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, &secret_key);
            let message_checker = script! {
                for i in 0..ps.byte_message_length() {
                    {return_message[i as usize]}
                    if i == ps.byte_message_length() - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_winternitz_tests!(
                ps, secret_key, public_key, message, message_checker, true;
                [ListpickVerifier, ToBytesConverter],
                [BruteforceVerifier, ToBytesConverter],
                [BinarysearchVerifier, ToBytesConverter]
            );
            let message_digits = bytes_to_u32s(ps.message_length, ps.block_length, &message);
            let void_message_checker = script! {
                for i in 0..ps.message_length {
                    { message_digits[i as usize] }
                    if i == ps.message_length - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_winternitz_tests!(
                ps, secret_key, public_key, message, void_message_checker, true;
                [ListpickVerifier, VoidConverter],
                [BruteforceVerifier, VoidConverter],
                [BinarysearchVerifier, VoidConverter]
            );
        }
    }

    #[test]
    fn test_winternitz_fail() {
        let secret_key = match hex::decode(SAMPLE_SECRET_KEY) {
            Ok(bytes) => bytes,
            Err(_) => panic!("Invalid hex string"),
        };
        let mut prng = ChaCha20Rng::seed_from_u64(37);
        for _ in 0..TEST_COUNT {
            let ps = Parameters::new(prng.gen_range(1..200), prng.gen_range(4..=8));
            let message_byte_size = ps.message_length * ps.block_length / 8;
            let mut message = vec![0u8; message_byte_size as usize];
            let mut return_message = vec![0; ps.byte_message_length() as usize];
            for i in 0..message_byte_size {
                message[i as usize] = prng.gen_range(0u8..=255);
                return_message[i as usize] = message[i as usize];
            }
            let public_key = generate_public_key(&ps, &secret_key);
            let message_checker = script! {
                for i in 0..ps.byte_message_length() {
                    {return_message[i as usize]}
                    if i == ps.byte_message_length() - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_winternitz_tests!(
                ps, secret_key, public_key, message, message_checker, false;
                [ListpickVerifier, ToBytesConverter],
                [BruteforceVerifier, ToBytesConverter],
                [BinarysearchVerifier, ToBytesConverter]
            );
            let message_digits = bytes_to_u32s(ps.message_length, ps.block_length, &message);
            let void_message_checker = script! {
                for i in 0..ps.message_length {
                    { message_digits[i as usize] }
                    if i == ps.message_length - 1 {
                        OP_EQUAL
                    } else {
                        OP_EQUALVERIFY
                    }
                }
            };
            generate_winternitz_tests!(
                ps, secret_key, public_key, message, void_message_checker, false;
                [ListpickVerifier, VoidConverter],
                [BruteforceVerifier, VoidConverter],
                [BinarysearchVerifier, VoidConverter]
            );
        }
    }
}