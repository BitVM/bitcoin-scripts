#![allow(non_snake_case)]

use crate::hash::sha256::u32_not;
use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};
use crate::u32::u32_add::u32_add_drop;
use crate::u32::u32_std::{u32_dup, u32_roll};
use crate::u32::{
    u32_and::u32_and,
    // u32_or::u32_or,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};

const K: [u32; 4] = [
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, 
];

const INITSTATE: [u32; 5] = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
];

pub fn sha1(num_bytes: usize) -> Script {
    let mut chunks_size: usize = num_bytes / 64 + 1;
    if (num_bytes % 64) > 55 {
        chunks_size += 1;
    }

    script! {
        {push_reverse_bytes_to_alt(num_bytes)}

        // top of stack: [ [n bytes input] ]
        {u8_push_xor_table()}
        {sha1_k()}
        // top of stack: [ [64 byte chunks]... ]
        {padding_add_roll(num_bytes)}
        {sha1_init()}
        // top of stack: [ [64 byte chunks]..., state[0-4]]
        for i in 0..chunks_size {
            {sha1_transform(5 + ((chunks_size as u32) - i as u32) *16 + 4 + 1, 5 + ((chunks_size as u32) - i as u32)  *16)}
        }

        {sha1_final()}
        for _ in 0..5 {  // SHA1 outputs 5 u32 values (160 bits, 20 bytes)
            {u32_toaltstack()}
        }
        for _ in 0..4 {
            {u32_drop()}
        }
        {u8_drop_xor_table()} 

        for _ in 0..5 {
            {u32_fromaltstack()}
        }
    }

}

/// reorder bytes for u32
pub fn padding_add_roll(num_bytes: usize) -> Script {
    assert!(num_bytes < 512); // The maximum input size of SHA1 is 512 bits (64 bytes)
    // Calculate the number of padding bytes
    let padding_num = if (num_bytes % 64) < 56 {
        55 - (num_bytes % 64)
    } else {
        64 + 55 - (num_bytes % 64)
    };
    // The number of u32 values after padding.
    let u32_num = (num_bytes + padding_num + 9) / 4; 
    script! {
        // Push the raw data from the ALT stack to the regular stack
        for _ in 0..num_bytes {
            OP_FROMALTSTACK
        }
        // Push the padding byte 0x80
        {0x80}
        // Push the required number of padding bytes
        {push_to_stack(0, padding_num)}
        // Push the 64-bit message length (in bits, num_bytes * 8)
        {u32_push(0)}
        {u32_push((num_bytes as u32) * 8)}
        for i in 1..u32_num {
            {u32_roll(i as u32)}
        }
    }
}

/// Change byte order, because SHA uses big endian.
pub fn sha1_final() -> Script {
    script! {
        for _ in 0..5 {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            {u32_toaltstack()}
        }
        for _ in 0..5 {
            {u32_fromaltstack()}
        }
    }
}

/// push all init state into stack
pub fn sha1_init() -> Vec<Script> {
    let mut state: [u32; 5] = INITSTATE;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// push other necessary state into stack
pub fn sha1_k() -> Vec<Script> {
    let mut state: [u32; 4] = K;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// sha1 transform
/// input: [m[15], m[14], ..., m[0], state[4], state[3], ..., state[0]]
/// output: [state[4], state[3], ..., state[0]]
pub fn sha1_transform(xor_depth: u32, k_depth: u32) -> Script {
    script! {
        // copy to alt stack
        for _ in 0..5 {
            {u32_pick(4)}
        }
        for _ in 0..10 {
            {u32_toaltstack()}
        }

        // reverse for 16 u32 data
        for i in 1..16 {
            {u32_roll(i)}
        }

        // reorg data
        // w[i] = (((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1) | ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31))
        for i in 16..80 {
            {u32_pick(2)}
            {u32_pick(8)}
            {u32_xor(0, 1, xor_depth - 3 + i-16)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_fromaltstack()}

            {u32_pick(14)}
            {u32_xor(0, 1, xor_depth - 3 + i-16)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_fromaltstack()}

            {u32_pick(16)}
            {u32_xor(0, 1, xor_depth - 3 + i-16)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_fromaltstack()}

            {u32_lrot(1)}
        }

        for _ in 0..5{
            {u32_fromaltstack()}
        }   // [w[79], w[78], w[77], w[76], w[75], ..., w[0], e, d, c, b, a]
        // Round 1
        for i in 0..20 {
            {R(F0, k_depth + 64, 79 - i, xor_depth + 64)}
        }
        // Round 2 
        for i in 20..40 {
            {R(F1, k_depth + 64 + 1, 79 - i, xor_depth + 64)}
        }
        // Round 3
        for i in 40..60 {
            {R(F2, k_depth + 64 + 2, 79 - i, xor_depth + 64)}
        }
        // Round 4
        for i in 60..80 {
            {R(F1, k_depth + 64 + 3, 79 - i, xor_depth + 64)}
        }
        for _ in 0..5{
            {u32_fromaltstack()}
        }   // [e1, d1, c1, b1, a1, e, d, c, b, a]
        
        // state[4] = (e + e1)
        {u32_add_from_two(4, 9)}
        // state[3] = (d + d1)
        {u32_add_from_two(3 + 1, 8 + 1)}
        // state[2] = (c + c1)
        {u32_add_from_two(2 + 2, 7 + 2)}
        // state[1] = (b + b1)
        {u32_add_from_two(1 + 3, 6 + 3)}
        // state[0] = (a + a1)
        {u32_add_from_two(0 + 4, 5 + 4)}
        

        for _ in 0..5 {
            {u32_toaltstack()}
        }
        for _ in 0..10 {
            {u32_drop()}
        }
        for _ in 0..80 {
            {u32_drop()}
        }
        for _ in 0..5 {
            {u32_fromaltstack()}
        }
        
    }
}

pub fn u32_add_from_two(x: u32, y: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_add_drop(0, 1)}
    }
}

/// Push reversed bytes to the alt stack.
pub fn push_reverse_bytes_to_alt(num_bytes: usize) -> Script {
    script! {
        for i in 1..=num_bytes {
            {num_bytes-i} OP_ROLL
            OP_TOALTSTACK
        }
    }
}

/// Rotate left n bits for a 32-bit value x. ((x << n) & 0xffffffff) | (x >> (32 - n))
pub fn u32_lrot(n: usize) -> Script {
    script! {
        {u32_rrot((32 - n) % 32)}
    }
}

/// F0(x, y, z) = (x & y) ^ (~x & z)
pub fn F0(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_and(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(x+1)}
        {u32_not()}
        {u32_pick(z+2)}
        {u32_and(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_xor(0, 1, stack_depth + 2)} // (x & y) ^ (~x & z)
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// F1(x, y, z) = x ^ y ^ z
pub fn F1(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_xor(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(z+1)}
        {u32_xor(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// F2(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
pub fn F2(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_and(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(x+1)}
        {u32_pick(z+2)}
        {u32_and(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(y+2)}
        {u32_pick(z+3)}
        {u32_and(0, 1, stack_depth+4)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_xor(0, 1, stack_depth + 3)}
        {u32_xor(0, 2, stack_depth + 3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// top of stack: [X[15], X[14], ..., X[0], e, d, c, b, a]
/// a = LROT(5, a) + Fj(b, c, d) + X[rj] + K[kj] + e
/// c = LROT(30, c)
/// and rotate c by 10 positions
pub fn R(Fj: fn(u32, u32, u32, u32) -> Script, kj: u32, rj: u32, xor_depth: u32) -> Script {
    script! {
        {u32_dup()} // [e, d, c, b, a, a]
        {u32_lrot(5)} // [e, d, c, b, a, tmp_t1]
        {Fj(2, 3, 4, xor_depth + 1)}    // [e, d, c, b, a, tmp_t1, tmp_t2]
        {u32_add_drop(0, 1)} // LROT(5, a) + Fj(b, c, d)
        // [e, d, c, b, a, tmp_t1]
        {u32_pick(rj + 6)} // [e, d, c, b, a, tmp_t1, X[rj]]
        {u32_pick(kj+2)} // [e, d, c, b, a, tmp_t1, X[rj], K[kj]]
        {u32_add_drop(0, 1)}
        {u32_add_drop(0, 1)} // [e, d, c, b, a, tmp_t1]
        [u32_roll(5)] // [d, c, b, a, tmp_t1, e]
        {u32_add_drop(0, 1)} // [d, c, b, a, t1]
        {u32_toaltstack()}
        {u32_toaltstack()}
        {u32_lrot(30)} // [d, c, LROT(b, 30)]
        {u32_fromaltstack()}
        {u32_fromaltstack()} // [d, c, LROT(b, 30), a, t1]
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::blake3::push_bytes_hex;
    use crate::hash::sha1::*;
    use crate::treepp::{execute_script, script};
    use crate::u32::u32_std::{u32_equal, u32_equalverify};
    use sha1::{Sha1, Digest};

    #[test]
    fn test_sha1() {
        println!(
            "sha1 chunk: {} bytes",
            sha1_transform(5 + 16 + 4 + 1, 5 + 16).len()
        );
        let hex_in = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
        
        let mut hasher = Sha1::new();
        
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        
        let result = hasher.finalize();
        
        let res = hex::encode(result);
        println!("res: {}", res);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {sha1(hex_in.len()/2)}
            {push_bytes_hex(res.as_str())}
            for _ in 0..20 { 
                OP_TOALTSTACK
            }

            for i in 1..20 {
                {i}
                OP_ROLL
            }

            for _ in 0..20 {
                OP_FROMALTSTACK
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        
        let res = execute_script(script);
        assert!(res.success);
    }


    #[test]
    fn test_lrot() {
        let x: u32 = 1234;
        let n: usize = 7;
        let result: u32 = ((x << n) & 0xffffffff) | (x >> (32 - n)); 
        let script = script! {
            {u32_push(x)}
            {u32_lrot(n)} 

            {u32_push(result)}
            {u32_equal()} 
        };
        let res = execute_script(script);
        // println!("res: {:?}", res);
        assert!(res.success);
    }

    #[test]
    fn test_F0() {
        let x: u32 = 1461618803;
        let y: u32 = 3271303715;
        let z: u32 = 3095366052;
        let result: u32 = (x & y) ^ (!x & z);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {F0(0, 1, 2, 4)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }


    #[test]
    fn test_F1() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = x ^ y ^ z;
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {F1(0, 1, 2, 4)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()} 
        };
        let res = execute_script(script);
        assert!(res.success);
    }
    #[test]
    fn test_F2() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = (x & y) ^ (x & z) ^ (y & z);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {F2(0, 1, 2, 4)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u8_drop_xor_table()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_transform_data() {
        let input: [u32; 16] = [
            1633837924, 1701209960, 1768581996, 1835954032, 1903326068, 1970698104, 2038071296, 0, 0, 0, 0, 0, 0, 0, 0, 208,
        ];

        let output: [u32; 5] = [
            852561019, 2365154672, 3389312567, 4070677892, 604846729,
        ];
        let k_depth: u32 = 5 + 16;
        let xor_depth: u32 = 5 + 16 + 4 + 1;

        let script = script! {
            // push xor table
            {u8_push_xor_table()}

            // push k
            // for i in 0..10 {
            //     {u32_push(K[9-i])}
            // }
            {sha1_k()}

            for i in 0..16 {
                {u32_push(input[15-i])}
            }
            // for i in 0..5 {
            //     {u32_push(INITSTATE[4-i])}
            // }
            {sha1_init()}

            {sha1_transform(xor_depth, k_depth)}

            for i in 0..5 {
                {u32_push(output[i])}
                {u32_equalverify()} // panic if verify fail
            }

            for _ in 0..4 {
                {u32_drop()}
            }

            {u8_drop_xor_table()}

        };

        let res = execute_script(script);
        // println!("res:{:?}", res);
        assert_eq!(res.final_stack.len(), 0);

    }

    #[test]
    fn test_R() {
        let input: [u32; 16] = [
            1633837924, 1701209960, 1768581996, 1835954032, 1903326068, 1970698104, 2038071296, 0, 0, 0, 0, 0, 0, 0, 0, 208,
        ];

        let output: [u32; 5] = [
            852561019, 2365154672, 3389312567, 4070677892, 604846729,
        ];
        let k_depth: u32 = 5 + 16;
        let xor_depth: u32 = 5 + 16 + 4 + 1;

        let script = script! {

            // push xor table
            {u8_push_xor_table()}

            // push k
            for i in 0..4 {
                {u32_push(K[3-i])}
            }

            for i in 0..16 {
                {u32_push(input[15-i])}
            }
            for i in 0..5 {
                {u32_push(INITSTATE[4-i])}
            }
            // copy to alt stack
            for _ in 0..5 {
                {u32_pick(4)}
            }
            for _ in 0..10 {
                {u32_toaltstack()}
            }

            // reverse for 16 u32 data
            for i in 1..16 {
                {u32_roll(i)}
            }

            // reorg data
            // w[i] = (((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1) | ((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31))
            for i in 16..80 {
                {u32_pick(2)}
                {u32_pick(8)}
                {u32_xor(0, 1, xor_depth - 3 + i-16)}
                {u32_toaltstack()}
                {u32_drop()}
                {u32_fromaltstack()}

                {u32_pick(14)}
                {u32_xor(0, 1, xor_depth - 3 + i-16)}
                {u32_toaltstack()}
                {u32_drop()}
                {u32_fromaltstack()}

                {u32_pick(16)}
                {u32_xor(0, 1, xor_depth - 3 + i-16)}
                {u32_toaltstack()}
                {u32_drop()}
                {u32_fromaltstack()}

                {u32_lrot(1)}
            }

            for _ in 0..5{
                {u32_fromaltstack()}
            }   // [w[79], w[78], w[77], w[76], w[75], ..., w[0], e, d, c, b, a]
            // Round 1
            for i in 0..20 {
                {R(F0, k_depth + 64, 79 - i, xor_depth + 64)}
            }
            // Round 2 
            for i in 20..40 {
                {R(F1, k_depth + 64 + 1, 79 - i, xor_depth + 64)}
            }
            // Round 3
            for i in 40..60 {
                {R(F2, k_depth + 64 + 2, 79 - i, xor_depth + 64)}
            }
            // Round 4
            for i in 60..80 {
                {R(F1, k_depth + 64 + 3, 79 - i, xor_depth + 64)}
            }
            for _ in 0..5{
                {u32_fromaltstack()}
            }   // [e1, d1, c1, b1, a1, e, d, c, b, a]
            
            // state[4] = (e + e1)
            {u32_add_from_two(4, 9)}
            // state[3] = (d + d1)
            {u32_add_from_two(3 + 1, 8 + 1)}
            // state[2] = (c + c1)
            {u32_add_from_two(2 + 2, 7 + 2)}
            // state[1] = (b + b1)
            {u32_add_from_two(1 + 3, 6 + 3)}
            // state[0] = (a + a1)
            {u32_add_from_two(0 + 4, 5 + 4)}

            for i in 0..5 {
                {u32_push(output[i])}
                {u32_equalverify()} // panic if verify fail
            }

            // for _ in 0..5 {
            //     {u32_toaltstack()}
            // }

            for _ in 0..10 {
                {u32_drop()}
            }
            for _ in 0..80 {
                {u32_drop()}
            }
            for _ in 0..4 {
                {u32_drop()}
            }
            {u8_drop_xor_table()}

            // for _ in 0..5 {
            //     {u32_fromaltstack()}
            // }
        };

        let res = execute_script(script);
        println!("res:{:100}", res);
        assert_eq!(res.final_stack.len(), 0);
    }

    #[test]
    fn test_u32_add_from_two() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let m: u32 = 23;
        let result: u32 = x + y;
        let script = script! {
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {u32_push(m)}
            {u32_add_from_two(1, 2)}
            {u32_toaltstack()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u32_drop()}
            {u32_fromaltstack()}

            {u32_push(result)}
            {u32_equal()}
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_padding_add_roll() {
        let hex_in = "6162636465666768696a6b6c6d6e6f707172737475767778797a";

        let stack_out: [u32; 16] = [
            1633837924, 1701209960, 1768581996, 1835954032, 1903326068, 1970698104, 2038071296, 0, 0, 0, 0, 0, 0, 0, 0, 208,
        ];

        let script = script! {
            {push_bytes_hex(hex_in)}
            {push_reverse_bytes_to_alt(hex_in.len()/2)}
            // {u8_push_xor_table()}
            // {sha1_k()}
            {padding_add_roll(hex_in.len()/2)}
            for i in 0..16 {
                {u32_push(stack_out[i])}
                {u32_equalverify()} //
            }
            // for _ in 0..10 {
            //     {u32_drop()}
            // }

            // {u8_drop_xor_table()}
        };
        let res = execute_script(script);
        // assert!(res.success);
        // println!("result {:100}", res);
        assert_eq!(res.final_stack.len(), 0);
    }

}
