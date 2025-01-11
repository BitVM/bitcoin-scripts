use crate::{
    hash::blake3_u32_split::compress,
    treepp::{script, Script},
    u32::{
        u32_std::{u32_drop, u32_fromaltstack, u32_push, u32_roll, u32_toaltstack, u32_uncompress},
        u32_xor::{u8_drop_xor_table, u8_push_xor_table},
    },
};

use super::{ptr_init, Env, IV};

const CHUNK_LEN: u32 = 1024;
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;
const BLOCK_LEN: usize = 64;

// Each compress function could cost 64 bytes = 16 u32
// keep bytes_len <= 1 CHUNK SIZE
pub fn split_blake3(bytes_len: usize) -> Vec<Script> {
    assert!(bytes_len <= 1024);

    let bytes_len_remain = bytes_len;
    let block_len = ((bytes_len + 64 - 1) / 64) - 1;

    let mut env = ptr_init();

    let mut res_scripts = vec![];

    let t0 = 0;
    let t1 = 0;
    let b = BLOCK_LEN;
    let mut d = 0;

    if bytes_len_remain > BLOCK_LEN {
        d = d | CHUNK_START;
    } else {
        d = d | ROOT | CHUNK_END | CHUNK_START;
    }

    res_scripts.push(compression_script(&mut env, t0, t1, b as u32, d).clone());

    for i in 0..block_len {
        if i != (block_len - 1) {
            d = 0;
        } else {
            d = ROOT | CHUNK_END;
        }

        let mut env = ptr_init();

        res_scripts.push(compression_script(&mut env, t0, t1, b as u32, d).clone());
    }

    res_scripts
}

// [bytes, pre_hash]
fn compression_script(env: &mut Env, t0: u32, t1: u32, b: u32, d: u8) -> Script {
    script! {

        for _ in 0..8 {

            {u32_toaltstack()}

        }

        // Initialize the lookup table
        u8_push_xor_table

        { state_add(t0, t1, b, d as u32) }

        for _ in 0..8 {

            {u32_fromaltstack()}

        }

        {compress(env, 16)}

        // Save the hash
        for _ in 0..8{

            {u32_toaltstack()}

        }

        // Clean up the other half of the state
        for _ in 0..24 {

            {u32_drop()}

        }

        u8_drop_xor_table

        for _ in 0..8{

            {u32_fromaltstack()}

        }
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
// t0: low of chunk number
// t1: high of chunk number
// b: block input size
// d: domain flag
fn state_add(t0: u32, t1: u32, b: u32, d: u32) -> Vec<Script> {
    let mut state = [IV[0], IV[1], IV[2], IV[3], t0, t1, b, d];

    state.reverse();

    state.iter().map(|x| u32_push(*x)).collect::<Vec<_>>()
}

#[cfg(test)]
mod test {

    use ark_std::{end_timer, start_timer};
    use num_bigint::BigUint;

    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::hash::blake3::blake3_hash_equalverify;
    use crate::treepp::*;

    use crate::hash::blake3_u32_split::{blake3_native, blake3_script_split};

    #[test]
    fn test_Blake3_split() {
        let inputs = (0..48_u32)
            .into_iter()
            .flat_map(|i| i.to_le_bytes())
            .collect::<Vec<_>>();

        let sript_inputs = (0..48_u32)
            .into_iter()
            .rev()
            .flat_map(|i| i.to_be_bytes())
            .collect::<Vec<_>>();

        println!("inputs len = {:?}", inputs.len());

        let blake3_scripts = blake3_script_split::split_blake3(inputs.len());

        let (hash, ScriptContext) = blake3_native::blake3_1chunk(&inputs, &sript_inputs);

        let expect_hash = blake3::hash(&inputs);

        assert_eq!(expect_hash.to_string(), hash.to_string());

        assert_eq!(blake3_scripts.len(), ScriptContext.len());

        println!("test_Blake3_split len = {:?}", blake3_scripts.len());

        // execute for each script and witness
        for (i, (wit, scp)) in ScriptContext.iter().zip(blake3_scripts).enumerate() {
            let final_script = script! {
                for input in wit.inputs.iter() {
                    { Fq::push_u32_le(&BigUint::from(input.clone()).to_u32_digits()) }
                }
                for input in wit.auxiliary.iter() {
                    { *input }
                }
                { scp.clone() }
                for output in wit.outputs.iter().rev() {
                    { Fq::push_u32_le(&BigUint::from(output.clone()).to_u32_digits()) }
                    { Fq::equalverify(1,0) }
                }
                for output in wit.auxiliary_output.iter() {
                    { *output }
                }
                { blake3_hash_equalverify() }
                OP_TRUE
            };
            println!("test_Blake3_split.subscript[i] size: {} KBytes", final_script.len()/1024);

            let start = start_timer!(|| "test_Blake3_split");
            let exec_result = execute_script(final_script);
            assert!(exec_result.success);
            println!("subscript[{}] runs successfully!", i);
            end_timer!(start);
        }
    }
}
