#![allow(non_snake_case)]
use std::collections::HashMap;

use bitcoin::script;

use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};
use crate::u32::u32_std::{u32_equalverify, u32_roll, u32_uncompress};
use crate::u32::{
    u32_add::u32_add,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_push, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
    // unroll,
};

//
// Environment
//

// A pointer to address elements on the stack
#[derive(Eq, Hash, PartialEq, Debug, Clone, Copy)]
pub enum Ptr {
    State(u32),
    Message(u32),
}

pub fn S(i: u32) -> Ptr { Ptr::State(i) }

pub fn M(i: u32) -> Ptr { Ptr::Message(i) }

// An environment to track elements on the stack
pub type Env = HashMap<Ptr, u32>;

pub fn ptr_init() -> Env {
    // Initial positions for state and message
    let mut env: Env = Env::new();
    for i in 0..16 {
        env.insert(S(i), i);
        // The message's offset is the size of the state
        // plus the u32 size of our XOR table
        env.insert(M(i), i + 16 + 256 / 4);
    }
    env
}

pub fn ptr_init_160() -> Env {
    // Initial positions for state and message
    let mut env: Env = Env::new();
    for i in 0..16 {
        env.insert(S(i), i);
        // The message's offset is the size of the state
        // plus the u32 size of our XOR table
        let value: i32 = i as i32
            + 16
            + 256 / 4
            + match i < 10 {
                true => 6,
                false => -10,
            };
        env.insert(M(i), value as u32);
    }
    env
}

pub trait EnvTrait {
    // Get the position of `ptr`
    fn ptr(&mut self, ptr: Ptr) -> u32;

    /// Get the position of `ptr`, then delete it
    fn ptr_extract(&mut self, ptr: Ptr) -> u32;

    /// Set the position of `ptr` to the top stack ptr
    fn ptr_insert(&mut self, ptr: Ptr);
}

impl EnvTrait for Env {
    fn ptr_insert(&mut self, ptr: Ptr) {
        for (_, value) in self.iter_mut() {
            *value += 1;
        }
        self.insert(ptr, 0);
    }

    fn ptr_extract(&mut self, ptr: Ptr) -> u32 {
        match self.remove(&ptr) {
            Some(index) => {
                for (_, value) in self.iter_mut() {
                    if index < *value {
                        *value -= 1;
                    }
                }
                index
            }
            None => panic!("{:?}", ptr),
        }
    }

    fn ptr(&mut self, ptr: Ptr) -> u32 { *self.get(&ptr).unwrap() }
}

//
// Blake 3 Algorithm
//

pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [u32; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub fn initial_state(block_len: u32) -> Vec<Script> {
    let mut state = [
        IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3], 0, 0,
        block_len, 0b00001011,
    ];
    state.reverse();
    state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}

fn G(env: &mut Env, ap: u32, a: Ptr, b: Ptr, c: Ptr, d: Ptr, m0: Ptr, m1: Ptr) -> Script {
    let script = script! {
        // z = a+b+m0
        {u32_add(env.ptr(b), env.ptr_extract(a))}
        {u32_add(env.ptr(m0) + 1, 0)}
        // Stack:  m1 m0 d c b  |  z

        // y = (d^z) >>> 16
        {u32_xor(0, env.ptr_extract(d) + 1, ap + 1)}
        {u32_rrot(16)}
        // Stack:  m1 m0 c b  |  z y


        // x = y+c
        {u32_add(0, env.ptr_extract(c) + 2)}
        // Stack:  m1 m0 b  |  z y x

        // w = (b^x) >>> 12
        {u32_xor(0, env.ptr_extract(b) + 3, ap + 1)}
        {u32_rrot(12)}
        // Stack:  m1 m0 |  z y x w


        // v = z+w+m1
        {u32_add(0, 3)}
        {u32_add(env.ptr(m1) + 4, 0)}
        // Stack: m1 m0 |  y x w v

        // u = (y^v) >>> 8
        {u32_xor(0, 3, ap + 1)}
        {u32_rrot(8)}
        // Stack: m1 m0 |  x w v u

        // t = x+u
        {u32_add(0, 3)}
        // Stack: m1 m0 |  w v u t

        // s = (w^t) >>> 7
        {u32_xor(0, 3, ap + 1)}
        {u32_rrot(7)}
        // Stack: m1 m0 |  v u t s
    };

    env.ptr_insert(a);
    env.ptr_insert(d);
    env.ptr_insert(c);
    env.ptr_insert(b);
    script
}

pub fn round(env: &mut Env, ap: u32) -> Script {
    script! {
        { G(env, ap, S(0), S(4), S(8),  S(12), M(0),  M(1)) }
        { G(env, ap, S(1), S(5), S(9),  S(13), M(2),  M(3)) }
        { G(env, ap, S(2), S(6), S(10), S(14), M(4),  M(5)) }
        { G(env, ap, S(3), S(7), S(11), S(15), M(6),  M(7)) }

        { G(env, ap, S(0), S(5), S(10), S(15), M(8),  M(9)) }
        { G(env, ap, S(1), S(6), S(11), S(12), M(10), M(11)) }
        { G(env, ap, S(2), S(7), S(8),  S(13), M(12), M(13)) }
        { G(env, ap, S(3), S(4), S(9),  S(14), M(14), M(15)) }
    }
}

//Script added cause we are getting Non pushable error otherwise, not sure how to...
pub fn permute(env: &mut Env) -> Script {
    let mut prev_env = Vec::new();
    for i in 0..16 {
        prev_env.push(env.ptr(M(i)));
    }

    for i in 0..16 {
        env.insert(M(i as u32), prev_env[MSG_PERMUTATION[i] as usize]);
    }

    script! {}
}

pub fn compress(env: &mut Env, ap: u32) -> Script {
    script! {
        // Perform 7 rounds and permute after each round,
        // except for the last round
        {round(env, ap)}

        for _ in 0..6{
            {permute(env)}
            {round(env, ap)}
        }

        // XOR states [0..7] with states [8..15]
        for i in 0..8{
            {u32_xor(env.ptr(S(i)) + i, env.ptr_extract(S(i + 8)) + i, ap + 1)}
        }
    }
}

fn compress_160(env: &mut Env, ap: u32) -> Script {
    script! {
        // Perform 7 rounds and permute after each round,
        // except for the last round
        {round(env, ap)}
        for _ in 0..6 {
            {permute(env)}
            {round(env, ap)}
        }

        // XOR states [0..4] with states [8..12]
        for i in 0..5{
            {u32_xor(env.ptr(S(i)) + i, env.ptr_extract(S(i + 8)) + i, ap + 1)}
        }
    }
}

/// Blake3 taking a 64-byte message and returning a 32-byte digest
pub fn blake3() -> Script {
    let mut env = ptr_init();
    script! {
        // Initialize our lookup table
        // We have to do that only once per program
        u8_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(64)}

        // Perform a round of Blake3
        {compress(&mut env, 16)}

        // Save the hash
        for _ in 0..8{
            {u32_toaltstack()}
        }

        // Clean up the input data and the other half of the state
        for _ in 0..24 {
            {u32_drop()}
        }

        // Drop the lookup table
        u8_drop_xor_table

        // Load the hash
        for _ in 0..8{
            {u32_fromaltstack()}
        }
    }
}

pub fn blake3_var_length(num_u32: usize) -> Script {
    assert!(num_u32 <= 512,
            "This blake3 implementation does not support input larger than 512 bytes due to stack limit. \
            Please modify the hashing routine to avoid calling blake3 in this way.");

    // Compute how many padding elements are needed
    let num_bytes = num_u32 * 4;
    let num_blocks = (num_bytes + 64 - 1) / 64;
    let num_padding_bytes = num_blocks * 64 - num_bytes;
    let num_padding_u32 = num_blocks * 16 - num_u32;

    // Calculate the initial state
    let first_block_flag = if num_bytes <= 64 {
        0b00001011
    } else {
        0b00000001
    };
    let init_state = {
        let mut state = [
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            IV[4],
            IV[5],
            IV[6],
            IV[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            0,
            0,
            core::cmp::min(num_bytes as u32, 64),
            first_block_flag,
        ];
        state.reverse();
        state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
    };

    let mut env = ptr_init();

    // store the compression script for reuse
    let compression_script = script! {

        {compress(&mut env, 16)}

        { 321 }
        // Clean up the input data
        for _ in 0..63 {
            OP_DUP OP_ROLL OP_DROP
        }
        OP_1SUB OP_ROLL OP_DROP

        // Save the hash
        for _ in 0..8{
            {u32_toaltstack()}
        }

        // Clean up the other half of the state
        for _ in 0..8 {
            {u32_drop()}
        }

        u8_drop_xor_table
    };

    let script = script! {

        // Add the padding
        for _ in 0..num_padding_u32 {
            {0}
        }
        //{ push_to_stack(0, num_padding_bytes) }

        // If padded, move all the bytes down
        if num_padding_u32 != 0 {
            for _ in 0..num_u32 {
                { num_u32 + num_padding_u32 - 1 } OP_ROLL
            }
        }

        // the 1st block
        for _ in 0..15{
            OP_TOALTSTACK
        }
        { u32_uncompress() }

        for _ in 0..15 {
            OP_FROMALTSTACK
            { u32_uncompress() }
        }

        // Initialize the lookup table
        u8_push_xor_table

        // Push the initial Blake3 state onto the stack
        { init_state }

        // Call compression function initially
        { compression_script.clone() }

        // Variable script for the rest of the blocks
        // TODO: This is very ugly and can likely be improved by creating an iterator of num_bytes
        // beforehand and getting the next value (num_bytes - 64) from it.
        // By doing so we can get rid of the closure.
        { (| num_bytes | {
            let mut sub_script = script! {};
            let mut num_bytes = num_bytes;
            for i in 1..num_blocks {
                num_bytes -= 64;

                let block_flag = if i == num_blocks - 1 { 0b00001010 } else { 0 };

                let state_add = {
                    let mut state = [
                        IV[0],
                        IV[1],
                        IV[2],
                        IV[3],
                        0,
                        0,
                        core::cmp::min(num_bytes as u32, 64),
                        block_flag,
                    ];
                    state.reverse();
                    state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
                };

                sub_script = script! {
                    { sub_script }
                    { script! {

                            // the rest of blocks
                            for _ in 0..15{
                                OP_TOALTSTACK
                            }
                            { u32_uncompress() }

                            for _ in 0..15 {
                                OP_FROMALTSTACK
                                { u32_uncompress() }
                            }
                            u8_push_xor_table
                            { state_add }
                            for _ in 0..8 {
                                {u32_fromaltstack()}
                            }
                            for i in 1..8 {
                                {u32_roll(i)}
                            }
                            {compression_script.clone()}
                        }
                    }
                }
            }
            sub_script
            })(num_bytes)
        }

        //u8_drop_xor_table
        for _ in 0..8 {
            u32_fromaltstack
        }
    };

    script
}

/// Blake3 taking a 40-byte message and returning a 20-byte digest
pub fn blake3_160() -> Script {
    let mut env = ptr_init_160();
    script! {
        // Message zero-padding to 64-byte block
        // for _ in 0..6{
        //     {u32_push(0)}
        // }
        { push_to_stack(0,24) }

        // Initialize our lookup table
        // We have to do that only once per program
        u8_push_xor_table

        // Push the initial Blake state onto the stack
        {initial_state(40)}

        // Perform a round of Blake3
        {compress_160(&mut env, 16)}

        // Save the hash
        for _ in 0..5{
            {u32_toaltstack()}
        }

        // Clean up the input data and the other half of the state
        for _ in 0..27{
            {u32_drop()}
        }

        // Drop the lookup table
        u8_drop_xor_table

        // Load the hash
        for _ in 0..5{
            {u32_fromaltstack()}
        }
    }
}

pub fn blake3_160_var_length(num_bytes: usize) -> Script {
    script! {
        { blake3_var_length( num_bytes ) }
        // Reduce the digest's length to 20 bytes
        for _ in 0..12 {
            OP_DROP
        }
    }
}

pub fn push_bytes_hex(hex: &str) -> Script {
    let hex: String = hex
        .chars()
        .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
        .collect();

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();

    script! {
        for byte in bytes.iter().rev() {
            { *byte }
        }
    }
}

pub fn blake3_hash_equalverify() -> Script {
    script! {
        for _ in 0..28 {
            OP_TOALTSTACK
        }
        {u32_equalverify()}
        for _ in 0..7 {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            {u32_equalverify()}
        }
    }
}

pub fn blake3_160_hash_equalverify() -> Script {
    script! {
        for _ in 0..16 {
            OP_TOALTSTACK
        }
        {u32_equalverify()}
        for _ in 0..4 {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            {u32_equalverify()}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::blake3_u32_split::*;

    use crate::treepp::{execute_script, script};
    use crate::u32::u32_std::{u32_equalverify, u32_push, u32_uncompress};

    #[test]
    fn test_permute() {
        let mut env = ptr_init();
        // println!("Start env: {}", round(&mut env, 16).to_hex_string());
        permute(&mut env);
        // println!("Permuted env: {:?}", env);
        assert!(env.ptr(M(0)) == 82);
        assert!(env.ptr(M(1)) == 86);
        assert!(env.ptr(M(2)) == 83);
        assert!(env.ptr(M(3)) == 90);
        assert!(env.ptr(M(4)) == 87);
        assert!(env.ptr(M(5)) == 80);
        assert!(env.ptr(M(6)) == 84);
        assert!(env.ptr(M(7)) == 93);
        assert!(env.ptr(M(8)) == 81);
        assert!(env.ptr(M(9)) == 91);
        assert!(env.ptr(M(10)) == 92);
        assert!(env.ptr(M(11)) == 85);
        assert!(env.ptr(M(12)) == 89);
        assert!(env.ptr(M(13)) == 94);
        assert!(env.ptr(M(14)) == 95);
        assert!(env.ptr(M(15)) == 88);
    }

    #[test]
    fn test_initial_state() {
        let script = script! {
            {initial_state(64)}
        };
        let res = execute_script(script);
        assert!(res.final_stack.get(17)[0] == 79);
    }

    #[test]
    fn test_blake3() {
        let hex_out = "86ca95aefdee3d969af9bcc78b48a5c1115be5d66cafc2fc106bbd982d820e70";

        let script = script! {
            for _ in 0..16 {
                {u32_push(1)}
            }
            blake3
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let mut max_nb_stack_items = 0;

        if exec_result.stats.max_nb_stack_items > max_nb_stack_items {
            max_nb_stack_items = exec_result.stats.max_nb_stack_items;
        }
        println!("max_nb_stack_items = {max_nb_stack_items}");
    }

    #[test]
    fn test_blake3_var_length() {
        let hex_out = "cfe4e91ae2dd3223f02e8c33d4ee464734d1620b64ed1f08cac7e21f204851b7";

        let script = script! {
            for _ in 0..32 {
                //{u32_push(1)}
                { 1 }
            }
            { blake3_var_length(32) }
            {push_bytes_hex(hex_out)}
            {blake3_hash_equalverify()}
            OP_TRUE
        };
        println!("Blake3_var_length_60 size: {:?} \n", script.len());

        let exec_result = execute_script(script);
        assert!(exec_result.success);

        let mut max_nb_stack_items = 0;

        if exec_result.stats.max_nb_stack_items > max_nb_stack_items {
            max_nb_stack_items = exec_result.stats.max_nb_stack_items;
        }
        println!("max_nb_stack_items = {max_nb_stack_items}");
    }

    #[test]
    fn test_blake3_160_var_length() {
        let hex_out = "618f2b8aadb3339fa500848042f67323504128db";

        let script = script! {
            for _ in 0..256 {
                //{u32_push(1)}
                { 1 }
            }
            { blake3_160_var_length(256) }
            { push_bytes_hex(hex_out) }
            { blake3_160_hash_equalverify() }
            OP_TRUE
        };
        println!("Blake3_160_var_length_60 size: {:?} \n", script.len());

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_u32_uncompress() {
        let script = script! {

            { u32_push(1) }
            { 1 }
            { u32_uncompress() }
            { u32_equalverify() }

            OP_TRUE
        };
        println!("test_u32_uncompress size: {:?} \n", script.len());

        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_generate_blake3_exptect_output() {
        let mut input = vec![];

        for i in 0..32 {
            input.push(1);
            input.push(0);
            input.push(0);
            input.push(0);
        }

        let output = blake3::hash(&input);

        let expect_str = output.to_string();

        println!("output_str: {:?} \n", expect_str);

        let inputs = (0..32_u32)
            .into_iter()
            .flat_map(|i| 1_u32.to_le_bytes())
            .collect::<Vec<_>>();
        let output = blake3::hash(&inputs);

        let actual_str = output.to_string();
        // cfe4e91ae2dd3223f02e8c33d4ee464734d1620b64ed1f08cac7e21f204851b7
        println!("output_str: {:?} \n", actual_str);

        assert_eq!(expect_str, actual_str);
    }
}
