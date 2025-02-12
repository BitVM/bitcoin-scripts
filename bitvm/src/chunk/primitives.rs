use std::collections::HashMap;

use ark_ff::{BigInt, BigInteger};

use crate::bigint::U256;
use crate::bn254::fq2::Fq2;
use crate::chunk::blake3compiled::{hash_128b, hash_192b, hash_448b, hash_64b};
use crate::signatures::wots_api::{wots160, wots256, SignatureImpl};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};

use super::wots::{checksig_verify_to_limbs, WOTSPubKey};

pub(crate) type HashBytes = [u8; 64];

pub type Link = (u32, bool);

#[derive(Debug, Clone)]
pub enum SigData {
    Sig256(wots256::Signature),
    Sig160(wots160::Signature),
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub(crate) cache: HashMap<u32, SigData>,
}

pub(crate) fn get_bitcom_signature_as_witness(sig: &mut Sig, tup: Vec<Link>) -> Script {
    let mut compact_bc_scripts = script!();
    if !sig.cache.is_empty() {
        for skey in tup {
            let bcelem = sig.cache.get(&skey.0).unwrap();
            let scr = match bcelem {
                SigData::Sig160(signature) => signature.to_compact_script(),
                SigData::Sig256(signature) => signature.to_compact_script(),
            };
            compact_bc_scripts = compact_bc_scripts.push_script(scr.compile());
        }        
    }
    compact_bc_scripts
}

pub(crate) fn wots_locking_script(link: Link, link_ids: &HashMap<u32, WOTSPubKey>) -> Script {
    checksig_verify_to_limbs(link_ids.get(&link.0).unwrap())
}

pub(crate) fn gen_bitcom(
    link_ids: &HashMap<u32, WOTSPubKey>,
    // sec_out: Option<Link>,
    sec: Vec<Link>,
) -> Script {
    let tot_script = script!(
        for sec_in in sec {
            {wots_locking_script(sec_in, link_ids)}  // hash_in
            {Fq::toaltstack()}
        }
    );
    tot_script
}

#[cfg(test)]
pub(crate) fn unpack_limbs_to_nibbles() -> Script {
    U256::transform_limbsize(29,4)
}

pub fn pack_nibbles_to_limbs() -> Script {
    U256::transform_limbsize(4,29)
}

pub fn pack_bytes_to_limbs() -> Script {
    U256::transform_limbsize(8,29)
}


pub(crate) fn hash_fp2() -> Script {
    script! {
        { hash_64b() }
        { pack_nibbles_to_limbs() }
    }
}

pub(crate) fn hash_fp4() -> Script {
    script! {
        // [a0b0, a0b1, a1b0, a1b1]
        {Fq2::roll(2)}
        { hash_128b() }
        { pack_nibbles_to_limbs() }
    }
}

pub(crate) fn extern_bigint_to_nibbles(msg: ark_ff::BigInt<4>) -> [u8; 64] {
    let v = fq_to_chunked_bits(msg, 4);
    let vu8: Vec<u8> = v.iter().map(|x| (*x) as u8).collect();
    vu8.try_into().unwrap()
}

fn fq_to_chunked_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).collect();
    assert!(bits.len() == 256);
    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
                let res = chunk.iter().rev().fold(0, |acc, &x| {
                    let r = acc + if x { factor } else { 0 };
                    factor *= 2;
                    r
                });
                res
        })
        .collect()
}

pub(crate) fn extern_nibbles_to_bigint(nibble_array: [u8; 64]) -> ark_ff::BigInt<4> {
    let bit_array: Vec<bool> = nibble_array
    .iter()
    .flat_map(|&nibble| (0..4).rev().map(move |i| (nibble >> i) & 1 != 0)) // Extract each bit
    .collect();

    let r: ark_ff::BigInt<4> = BigInt::from_bits_be(&bit_array);
    r
}

pub(crate) fn extern_nibbles_to_limbs(nibble_array: [u8; 64]) -> [u32; 9] {
    let bit_array: Vec<bool> = nibble_array
    .iter()
    .flat_map(|&nibble| (0..4).rev().map(move |i| (nibble >> i) & 1 != 0)) // Extract each bit
    .collect();

    let r: ark_ff::BigInt<4> = BigInt::from_bits_be(&bit_array);
    fn bigint_to_limbs(n: num_bigint::BigInt, n_bits: u32) -> Vec<u32> {
        const LIMB_SIZE: u64 = 29;
        let mut limbs = vec![];
        let mut limb: u32 = 0;
        for i in 0..n_bits as u64 {
            if i > 0 && i % LIMB_SIZE == 0 {
                limbs.push(limb);
                limb = 0;
            }
            if n.bit(i) {
                limb += 1 << (i % LIMB_SIZE);
            }
        }
        limbs.push(limb);
        limbs
    }

    let mut limbs = bigint_to_limbs(r.into(), 256);
    limbs.reverse();
    limbs.try_into().unwrap()
}


fn replace_first_n_with_zero(hex_string: &str, n: usize) -> String {
    let mut result = String::new();

    if hex_string.len() <= n {
        result.push_str(&"0".repeat(hex_string.len())); // If n >= string length, replace all
    } else {
        result.push_str(&"0".repeat(n)); // Replace first n characters
        result.push_str(&hex_string[0..(hex_string.len()-n)]); // Keep the rest of the string
    }
    result
}

pub(crate) fn extern_hash_fps(fqs: Vec<ark_bn254::Fq>) -> [u8; 64] {
    let mut msgs: Vec<[u8; 64]> = Vec::new();
    for fq in fqs {
        let v = fq_to_chunked_bits(fq.into(), 4);
        let nib_arr: Vec<u8> = v.into_iter().map(|x| x as u8).collect();
        msgs.push(nib_arr.try_into().unwrap());
    }
    extern_hash_nibbles(msgs)
}

pub(crate) fn extern_hash_nibbles(msgs: Vec<[u8; 64]>) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 14 || msgs.len() == 6 || msgs.len() == 8);

    fn hex_string_to_nibble_array(hex_string: &str) -> Vec<u8> {
        hex_string
            .chars()
            .map(|c| c.to_digit(16).expect("Invalid hex character") as u8) // Convert each char to a nibble
            .collect()
    }

    fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
        let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
    
        for nibble_pair in digits.chunks(2) {
            let byte = (nibble_pair[0] << 4) | (nibble_pair[1] & 0b00001111);
            msg_bytes.push(byte);
        }
    
        fn le_to_be_byte_array(byte_array: Vec<u8>) -> Vec<u8> {
            assert!(byte_array.len() % 4 == 0, "Byte array length must be a multiple of 4");
            byte_array
                .chunks(4) // Process each group of 4 bytes (one u32)
                .flat_map(|chunk| chunk.iter().rev().cloned()) // Reverse each chunk
                .collect()
        }
        le_to_be_byte_array(msg_bytes)
    }

    fn extern_hash_fp_var(fqs: Vec<[u8; 64]>) -> [u8;64] {
        let mut vs = Vec::new();
        for fq in fqs {
            let v = fq.to_vec();
            vs.extend_from_slice(&v);
        }
        let nib_arr: Vec<u8> = vs.clone().into_iter().collect();
        let p_bytes:Vec<u8> = nib_to_byte_array(&nib_arr);

        let hash_out = blake3::hash(&p_bytes).to_string();

        let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32-20)*2);
        let res = hex_string_to_nibble_array(&hash_out);
        res.try_into().unwrap()
    }

    extern_hash_fp_var(msgs)
}

pub(crate) fn new_hash_g2acc_with_hashed_le() -> Script {
    script! {
        //Stack: [tx, ty, hash_inaux]
        //T
        {Fq::toaltstack()} 
        {hash_fp4()} // HT

        {Fq::fromaltstack()}
        {hash_fp2()}
    }
}

pub(crate) fn new_hash_g2acc() -> Script {
    script!(
        // [t, le]
        for _ in 0..14 {
            {Fq::toaltstack()}
        }
        {hash_fp4()}
        for _ in 0..14 {
            {Fq::fromaltstack()}
        }
        {Fq::roll(14)} {Fq::toaltstack()}
        {hash_fp14()}
        {Fq::fromaltstack()}
        {Fq::roll(1)}
        {hash_fp2()}
    )
}

pub(crate) fn new_hash_g2acc_with_hash_t() -> Script {
    script!(
        // [le, ht]
        {Fq::toaltstack()}
        {hash_fp14()}
        {Fq::fromaltstack()}
        {Fq::roll(1)}
        {hash_fp2()}
    )
}


pub(crate) fn hash_fp6() -> Script {
    script! {
        {Fq2::roll(2)} {Fq2::roll(4)}
        {hash_192b()}
        {pack_nibbles_to_limbs()}

    }
}


pub(crate) fn hash_fp14() -> Script {
    script! {
        {Fq2::roll(2)} {Fq2::roll(4)} {Fq2::roll(6)} 
        {Fq2::roll(8)} {Fq2::roll(10)} {Fq2::roll(12)}
        {hash_448b()}
        {pack_nibbles_to_limbs()}

    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::{Field, PrimeField, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::execute_script;

    #[test]
    fn test_emulate_fq_to_nibbles() {
        let mut prng = ChaCha20Rng::seed_from_u64(1777);
        let p = ark_bn254::Fq::rand(&mut prng);
        pub(crate) fn emulate_fq_to_nibbles_scripted(msg: ark_bn254::Fq) -> [u8; 64] {
            let scr = script! {
                {Fq::push(msg)}
                {unpack_limbs_to_nibbles()}
            };
            let exec_result = execute_script(scr);
            let mut arr = [0u8; 64];
            for i in 0..exec_result.final_stack.len() {
                let v = exec_result.final_stack.get(i);
                if v.is_empty() {
                    arr[i] = 0;
                } else {
                    arr[i] = v[0];
                }
            }
            arr
        }
        let pb1 = extern_bigint_to_nibbles(p.into_bigint());
        let pb2 = emulate_fq_to_nibbles_scripted(p);
        assert_eq!(pb1, pb2);
    }

    #[test]
    fn test_emulate_external_hash() {
        fn emulate_extern_hash_fps_scripted(msgs: Vec<ark_bn254::Fq>) -> [u8; 64] {
            assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 14 || msgs.len() == 6 || msgs.len() == 8);

            let scr = script! {
                for i in 0..msgs.len() {
                    {Fq::push(msgs[i])}
                }
                if msgs.len() == 4 {
                    {hash_fp4()}
                } else if msgs.len() == 2 {
                    {hash_fp2()}
                } else if msgs.len() == 6 {
                    {hash_fp6()}
                } else if msgs.len() == 14 {
                    {hash_fp14()}
                }
                {unpack_limbs_to_nibbles()}
            };
            let exec_result = execute_script(scr.clone());
            let mut arr = [0u8; 64];
            for i in 0..exec_result.final_stack.len() {
                let v = exec_result.final_stack.get(i);
                if v.is_empty() {
                    arr[i] = 0;
                } else {
                    arr[i] = v[0];
                }
            }
            arr
        }
    
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let _f = ark_bn254::Fq12::rand(&mut prng);

        let ps = vec![ark_bn254::Fq::ONE + ark_bn254::Fq::ONE; 14];
        let res = emulate_extern_hash_fps_scripted(ps.clone());
        let res2 = extern_hash_fps(ps);
        assert_eq!(res, res2);
    }

}

