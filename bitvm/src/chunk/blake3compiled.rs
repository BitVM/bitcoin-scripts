use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, hash::blake3_u4_compact::blake3_u4_compact, treepp::*};
use bitcoin_script_stack::stack::StackTracker;

use super::{elements::ElementType, primitives::{ hash_fp2, hash_fp6, new_hash_g2acc, new_hash_g2acc_with_hash_t, new_hash_g2acc_with_hashed_le}};


fn wrap_scr(scr: Script) -> Script {
    script! {
        { scr }
        for _ in 0..(64-40)/2 { OP_2DROP }
        for _ in 0..40 { OP_TOALTSTACK }
        for _ in 0..(64-40) { 0 }
        for _ in 0..40 { OP_FROMALTSTACK  }
    }
}

pub fn hash_64b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 64, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_128b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 128, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_192b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 192, true, true);
    wrap_scr(stack.get_script())
}

pub fn hash_448b() -> Script {
    let mut stack = StackTracker::new();
    blake3_u4_compact(&mut stack, 448, true, true);
    wrap_scr(stack.get_script())
}

/// This function is used to add hashing layer to the disprove script.
/// The additional logic here is due to a constraint in blake3_u4 
/// which requires the entire stack to only hold the message to be hashed.
/// Given an array of Elements of different ElementType, the function assumes the order [Input_A_Preimage, Input_B_Preimage, Output_Preimage] for main stack
/// and [Output_Hash, Input_B_Hash, Input_A_Hash] for altstack
pub fn hash_messages(elem_types: Vec<ElementType>) -> Script {
    // Altstack: [Hc, Hb, Ha]
    // Stack: [a, b, c]
    let elem_types: Vec<ElementType> = elem_types.into_iter().filter(|et| et.number_of_limbs_of_hashing_preimage() > 0).collect();
    let mut loop_script = script!();
    for msg_index in 0..elem_types.len() {
        // send other elems to altstack
        let mut remaining = elem_types[msg_index+1..].to_vec();
        let mut from_altstack = script!();
        for elem_type in &remaining {
            from_altstack = script!(
                {from_altstack}
                for _ in 0..elem_type.number_of_limbs_of_hashing_preimage() {
                    {Fq::fromaltstack()}
                }
            );
        }
        remaining.reverse();
        let mut to_altstack = script!();
        for elem_type in &remaining {
            to_altstack = script!(
                {to_altstack}
                for _ in 0..elem_type.number_of_limbs_of_hashing_preimage() {
                    {Fq::toaltstack()}
                }
            );
        }

        // hash remaining element
        let elem_type = elem_types[msg_index];
        let hash_scr = script!(
            if elem_type == ElementType::Fp6 {
                {hash_fp6()}
            } else if elem_type == ElementType::G1 {
                {hash_fp2()}
            } else if elem_type == ElementType::G2EvalPoint {
                {new_hash_g2acc_with_hashed_le()}
            } else if elem_type == ElementType::G2EvalMul {
                {new_hash_g2acc_with_hash_t()}
            } else if elem_type == ElementType::G2Eval {
                {new_hash_g2acc()}
            }
        );

        let verify_scr = script!(
            for _ in 0..Fq::N_LIMBS { 
                OP_DEPTH OP_1SUB OP_ROLL 
            }
            {Fq::fromaltstack()}
            {Fq::equal(1, 0)}
            if msg_index == elem_types.len()-1 {
                OP_NOT
            }
            OP_VERIFY
        );
        loop_script = script!(
            {loop_script}
            {to_altstack}
            {hash_scr}
            {from_altstack}
            {verify_scr}
        );
    }
    loop_script
}