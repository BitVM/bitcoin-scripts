#![allow(non_snake_case)]

use crate::hash::sha256::u32_not;
use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};
use crate::u32::u32_add::u32_add_drop;
use crate::u32::u32_std::{u32_dup, u32_roll};
use crate::u32::{
    u32_and::u32_and,
    u32_or::u32_or,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};

const K: [u32; 10] = [
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E, 
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
];

const INITSTATE: [u32; 5] = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
];
const S_ROUND_LEFT: [usize; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const S_ROUND_RIGHT: [usize; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

const I_ROUND_LEFT: [u32; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const I_ROUND_RIGHT: [u32; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];


pub fn ripemd160(num_bytes: usize) -> Script {
    let mut chunks_size: usize = num_bytes / 64 + 1;
    if (num_bytes % 64) > 55 {
        chunks_size += 1;
    }

    script! {
        {push_reverse_bytes_to_alt(num_bytes)}

        // top of stack: [ [n bytes input] ]
        {u8_push_xor_table()}
        {ripemd160_k()}
        // top of stack: [ [64 byte chunks]... ]
        {padding_add_roll(num_bytes)}
        {ripemd160_init()}
        // top of stack: [ [64 byte chunks]..., state[0-4]]
        for i in 0..chunks_size {
            {ripemd160_transform(5 + ((chunks_size as u32) - i as u32) *16 + 10 + 1, 5 + ((chunks_size as u32) - i as u32)  *16)}
        }
        for _ in 0..5 {  // RIPEMD-160 outputs 5 u32 values (160 bits, 20 bytes)
            {u32_toaltstack()}
        }
        for _ in 0..10 {
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
    assert!(num_bytes < 512); // The maximum input size of RIPEMD-160 is 512 bits (64 bytes)
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
        // Change byte order, because RIPEMD-160 uses little endian.
        for _ in 1..=(padding_num+num_bytes+1)/4 {
            {padding_num+num_bytes+1-4} OP_ROLL
            {padding_num+num_bytes+1-3} OP_ROLL
            {padding_num+num_bytes+1-2} OP_ROLL
            {padding_num+num_bytes+1-1} OP_ROLL
        }
        // Push the 64-bit message length (in bits, num_bytes * 8)
        {u32_push((num_bytes as u32) * 8)}
        {u32_push(0)}
        for i in 1..u32_num {
            {u32_roll(i as u32)}
        }
    }
}


/// push all init state into stack
pub fn ripemd160_init() -> Vec<Script> {
    let mut state: [u32; 5] = INITSTATE;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// push other necessary state into stack
pub fn ripemd160_k() -> Vec<Script> {
    let mut state: [u32; 10] = K;
    state.reverse();
    state.iter().map(|x: &u32| u32_push(*x)).collect::<Vec<_>>()
}

/// ripemd160 transform
/// input: [m[15], m[14], ..., m[0], state[4], state[3], ..., state[0]]
/// output: [state[4], state[3], ..., state[0]]
pub fn ripemd160_transform(xor_depth: u32, k_depth: u32) -> Script {
    script! {
        // copy two copies to alt stack
        for _ in 0..10 {
            {u32_pick(4)}
        }
        for _ in 0..10 {
            {u32_toaltstack()}
        }

        // Round 1 left
        for i in 0..16 {
            {R(F0, k_depth, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
        }
        // Round 2 left
        for i in 16..32 {
            {R(F1, k_depth+1, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
        }
        // Round 3 left
        for i in 32..48 {
            {R(F2, k_depth+2, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
        }
        // Round 4 left
        for i in 48..64 {
            {R(F3, k_depth+3, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
        }
        // Round 5 left
        for i in 64..80 {
            {R(F4, k_depth+4, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
        }   // [e1, d1, c1, b1, a1]

        for _ in 0..5{
            {u32_fromaltstack()}
        }   // [e1, d1, c1, b1, a1, e, d, c, b, a]
        for _ in 0..5{
            {u32_roll(9)}
        }   // [e, d, c, b, a, e1, d1, c1, b1, a1]
        for _ in 0..5{
            {u32_toaltstack()}
        }

        // Round 1 right
        for i in 0..16 {
            {R(F4, k_depth+5, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
        }
        // Round 2 right
        for i in 16..32 {
            {R(F3, k_depth+6, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
        }
        // Round 3 right
        for i in 32..48 {
            {R(F2, k_depth+7, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
        }
        // Round 4 right
        for i in 48..64 {
            {R(F1, k_depth+8, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
        }
        // Round 5 right
        for i in 64..80 {
            {R(F0, k_depth+9, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
        }   // [e2, d2, c2, b2, a2]

        for _ in 0..10{
            {u32_fromaltstack()}
        }   // [e2, d2, c2, b2, a2, e1, d1, c1, b1, a1, e, d, c, b, a]

        // state[4] = (a + b1 + c2)
        {u32_add_from_three(0, 6, 12)}
        // state[3] = (e + a1 + b2)
        {u32_add_from_three(4 + 1, 5 + 1, 11 + 1)}
        // state[2] = (d + e1 + a2)
        {u32_add_from_three(3 + 2, 9 + 2, 10 + 2)}
        // state[1] = (c + d1 + e2)
        {u32_add_from_three(2 + 3, 8 + 3, 14 + 3)}
        // state[0] = (b + c1 + d2)
        {u32_add_from_three(1 + 4, 7 + 4, 13 + 4)}

        for _ in 0..5 {
            {u32_toaltstack()}
        }
        for _ in 0..15 {
            {u32_drop()}
        }
        for _ in 0..16 {
            {u32_drop()}
        }
        for _ in 0..5 {
            {u32_fromaltstack()}
        }
        
    }
}

pub fn u32_add_from_three(x: u32, y: u32, z: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_add_drop(0, 1)}
        {u32_pick(z+1)}
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

/// F0(x, y, z) = x ^ y ^ z
pub fn F0(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
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

/// F1(x, y, z) = (x & y) | (~x & z)
pub fn F1(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
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

        {u32_or(0, 1, stack_depth + 2)} // (x & y) | (~x & z)
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// F2(x, y, z) = (x | (~y)) ^ z
pub fn F2(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_not()}
        {u32_or(0, 1, stack_depth+2)}
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

/// F3(x, y, z) = (x & z) | ((~z) & y)
pub fn F3(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(z+1)}
        {u32_and(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_pick(y+1)}
        {u32_pick(z+2)}
        {u32_not()}
        {u32_and(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_or(0, 1, stack_depth + 2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// F4(x, y, z) = x ^ (y | (~z))
pub fn F4(x: u32, y: u32, z: u32, stack_depth: u32) -> Script {
    script! {
        {u32_pick(x)}
        {u32_pick(y+1)}
        {u32_pick(z+2)}
        {u32_not()}
        {u32_or(0, 1, stack_depth+3)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}

        {u32_xor(0, 1, stack_depth+2)}
        {u32_toaltstack()}
        {u32_drop()}
        {u32_fromaltstack()}
    }
}

/// top of stack: [X[15], X[14], ..., X[0], e, d, c, b, a]
/// a = (LROT(sj, (a + Fj(b, c, d) + X[rj] + K[kj]) % 0x100000000) + e) % 0x100000000
/// c = LROT(10, c)
/// and rotate c by 10 positions
pub fn R(Fj: fn(u32, u32, u32, u32) -> Script, kj: u32, sj: usize, rj: u32, xor_depth: u32) -> Script {
    script! {
        {Fj(1, 2, 3, xor_depth)}    // [e, d, c, b, a, tmp_t1]
        {u32_add_drop(0, 1)} // a + Fj(b, c, d)
        // [e, d, c, b, tmp_t1]
        {u32_pick(rj + 5)} // [e, d, c, b, tmp_t1, X[rj]]
        {u32_pick(kj+1)} // [e, d, c, b, tmp_t1, X[rj], K[kj]]
        {u32_add_drop(0, 1)}
        {u32_add_drop(0, 1)} // [e, d, c, b, tmp_t1]
        {u32_lrot(sj)} // [e, d, c, b, tmp_t1]
        [u32_roll(4)] // [d, c, b, tmp_t1, e]
        {u32_dup()} // [d, c, b, tmp_t1, e, e]
        {u32_toaltstack()} // [d, c, b, tmp_t1, e]
        {u32_add_drop(0, 1)} // [d, c, b, t1]
        {u32_toaltstack()}
        {u32_toaltstack()}
        {u32_lrot(10)} // [d, LROT(c, 10)]
        {u32_fromaltstack()}
        {u32_fromaltstack()}
        {u32_fromaltstack()} // [d, LROT(c, 10), b, t1, e]
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::blake3::push_bytes_hex;
    use crate::hash::ripemd160::*;
    use crate::treepp::{execute_script, script};
    use crate::u32::u32_std::{u32_equal, u32_equalverify};
    use ripemd::{Ripemd160, Digest};


    #[test]
    fn test_ripemd160() {
        println!(
            "ripemd160 chunk: {} bytes",
            ripemd160_transform(5 + 16 + 10 + 1, 5 + 16).len()
        );
        let hex_in = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
        
        let mut hasher = Ripemd160::new();
        
        let data = hex::decode(hex_in).unwrap();
        hasher.update(&data);
        
        let result = hasher.finalize();
        
        let res = hex::encode(result);
        // println!("res: {}", res);

        let script = script! {
            {push_bytes_hex(hex_in)}
            {ripemd160(hex_in.len()/2)}
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
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = x ^ y ^ z;
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
        let x: u32 = 1461618803;
        let y: u32 = 3271303715;
        let z: u32 = 3095366052;
        let result: u32 = (x & y) | ((!x) & z);
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
        let result: u32 = (x | (!y)) ^ z;
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
    fn test_F3() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = (x & z) | ((!z) & y);
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {F3(0, 1, 2, 4)}
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
    fn test_F4() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let result: u32 = x ^ (y | (!z));
        let script = script! {
            {u8_push_xor_table()}
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {F4(0, 1, 2, 4)}
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
            1684234849, 1751606885, 1818978921, 1886350957, 1953722993, 2021095029, 8419961, 0, 0, 0, 0, 0, 0, 0, 208, 0,
        ];

        let output: [u32; 5] = [
            270998775, 455895452, 3957111638, 1697160539, 3163386035,
        ];
        let k_depth: u32 = 5 + 16;
        let xor_depth: u32 = 5 + 16 + 10 + 1;

        let script = script! {
            // push xor table
            {u8_push_xor_table()}

            // push k
            // for i in 0..10 {
            //     {u32_push(K[9-i])}
            // }
            {ripemd160_k()}

            for i in 0..16 {
                {u32_push(input[15-i])}
            }
            // for i in 0..5 {
            //     {u32_push(INITSTATE[4-i])}
            // }
            {ripemd160_init()}

            {ripemd160_transform(xor_depth, k_depth)}

            for i in 0..5 {
                {u32_push(output[i])}
                {u32_equalverify()} // panic if verify fail
            }

            for _ in 0..15 {
                {u32_drop()}
            }

            for _ in 0..16 {
                {u32_drop()}
            }
            for _ in 0..10 {
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
            1684234849, 1751606885, 1818978921, 1886350957, 1953722993, 2021095029, 8419961, 0, 0, 0, 0, 0, 0, 0, 208, 0,
        ];

        let output: [u32; 5] = [
            270998775, 455895452, 3957111638, 1697160539, 3163386035,
        ];
        let k_depth: u32 = 5 + 16;
        let xor_depth: u32 = 5 + 16 + 10 + 1;

        let script = script! {

            // push xor table
            {u8_push_xor_table()}

            // push k
            for i in 0..10 {
                {u32_push(K[9-i])}
            }

            for i in 0..16 {
                {u32_push(input[15-i])}
            }
            for i in 0..5 {
                {u32_push(INITSTATE[4-i])}
            }
            // copy two copies to alt stack
            for _ in 0..10 {
                {u32_pick(4)}
            }
            for _ in 0..10 {
                {u32_toaltstack()}
            }

            // {R(F0, 5 + 16, S_ROUND_LEFT[0], I_ROUND_LEFT[0], 5 + 16 + 10 + 1)}
            // Round 1 left
            for i in 0..16 {
                {R(F0, k_depth, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
            }
            // {R(F1, k_depth+1, S_ROUND_LEFT[16], I_ROUND_LEFT[16], xor_depth)}
            // Round 2 left
            for i in 16..32 {
                {R(F1, k_depth+1, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
            }
            // Round 3 left
            for i in 32..48 {
                {R(F2, k_depth+2, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
            }
            // Round 4 left
            for i in 48..64 {
                {R(F3, k_depth+3, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
            }
            // Round 5 left
            for i in 64..80 {
                {R(F4, k_depth+4, S_ROUND_LEFT[i], I_ROUND_LEFT[i], xor_depth)}
            }   // [e1, d1, c1, b1, a1]

            for _ in 0..5{
                {u32_fromaltstack()}
            }   // [e1, d1, c1, b1, a1, e, d, c, b, a]
            for _ in 0..5{
                {u32_roll(9)}
            }   // [e, d, c, b, a, e1, d1, c1, b1, a1]
            for _ in 0..5{
                {u32_toaltstack()}
            }

            // Round 1 right
            for i in 0..16 {
                {R(F4, k_depth+5, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
            }
            // Round 2 right
            for i in 16..32 {
                {R(F3, k_depth+6, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
            }
            // Round 3 right
            for i in 32..48 {
                {R(F2, k_depth+7, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
            }
            // Round 4 right
            for i in 48..64 {
                {R(F1, k_depth+8, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
            }
            // Round 5 right
            for i in 64..80 {
                {R(F0, k_depth+9, S_ROUND_RIGHT[i], I_ROUND_RIGHT[i], xor_depth)}
            }   // [e2, d2, c2, b2, a2]
            for _ in 0..10{
                {u32_fromaltstack()}
            }   // [e2, d2, c2, b2, a2, e1, d1, c1, b1, a1, e, d, c, b, a]
    
            // state[4] = (a + b1 + c2)
            {u32_add_from_three(0, 6, 12)}
            // state[3] = (e + a1 + b2)
            {u32_add_from_three(4 + 1, 5 + 1, 11 + 1)}
            // state[2] = (d + e1 + a2)
            {u32_add_from_three(3 + 2, 9 + 2, 10 + 2)}
            // state[1] = (c + d1 + e2)
            {u32_add_from_three(2 + 3, 8 + 3, 14 + 3)}
            // state[0] = (b + c1 + d2)
            {u32_add_from_three(1 + 4, 7 + 4, 13 + 4)}

            for i in 0..5 {
                {u32_push(output[i])}
                {u32_equalverify()} // panic if verify fail
            }

            for _ in 0..15 {
                {u32_drop()}
            }

            for _ in 0..16 {
                {u32_drop()}
            }
            for _ in 0..10 {
                {u32_drop()}
            }

            {u8_drop_xor_table()}
        };

        let res = execute_script(script);
        // println!("res:{:?}", res);
        assert_eq!(res.final_stack.len(), 0);
    }

    #[test]
    fn test_u32_add_from_three() {
        let x: u32 = 12;
        let y: u32 = 38;
        let z: u32 = 97;
        let m: u32 = 23;
        let result: u32 = x + y + z;
        let script = script! {
            {u32_push(z)}
            {u32_push(y)}
            {u32_push(x)}
            {u32_push(m)}
            {u32_add_from_three(3, 1, 2)}
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
            1684234849, 1751606885, 1818978921, 1886350957, 1953722993, 2021095029, 8419961, 0, 0, 0, 0, 0, 0, 0, 208, 0,
        ];

        let script = script! {
            {push_bytes_hex(hex_in)}
            {push_reverse_bytes_to_alt(hex_in.len()/2)}
            // {u8_push_xor_table()}
            // {ripemd160_k()}
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
