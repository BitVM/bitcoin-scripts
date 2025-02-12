use crate::bigint::BigIntImpl;
use crate::bigint::U256;
use crate::bn254::fq::bigint_to_u32_limbs;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::*;
use ark_ff::BigInt;

#[derive(Debug, Clone)]
pub enum Hint {
    U32(u32),
    Fq(ark_bn254::Fq),
    Fr(ark_bn254::Fr),
    Hash([u32; 9]),
    U256(num_bigint::BigInt),
    BigIntegerTmulLC1(num_bigint::BigInt),
    BigIntegerTmulLC2(num_bigint::BigInt),
    BigIntegerTmulLC4(num_bigint::BigInt),
}

impl Hint {
    pub fn push(&self) -> Script {
        const K1: (u32, u32) = Fq::bigint_tmul_lc_1();
        const K2: (u32, u32) = Fq::bigint_tmul_lc_2();
        const K4: (u32, u32) = Fq::bigint_tmul_lc_4();
        pub type T1 = BigIntImpl<{ K1.0 }, { K1.1 }>;
        pub type T2 = BigIntImpl<{ K2.0 }, { K2.1 }>;
        pub type T4 = BigIntImpl<{ K4.0 }, { K4.1 }>;
        match self {
            Hint::U32(f)  => script!{
                {*f}
            },
            Hint::Fq(fq) => script! {
                { Fq::push(*fq) }
            },
            Hint::Fr(fr) => script! {
                { Fr::push(*fr) }
            },
            Hint::Hash(hash) => script! {
                for h in hash {
                    {*h}
                }
            },
            Hint::U256(num) => script! {
                { U256::push_u32_le(&bigint_to_u32_limbs(num.clone(), 256)) }
            },
            Hint::BigIntegerTmulLC1(a) => script! {
                { T1::push_u32_le(&bigint_to_u32_limbs(a.clone(), T1::N_BITS)) }
            },
            Hint::BigIntegerTmulLC2(a) => script! {
                { T2::push_u32_le(&bigint_to_u32_limbs(a.clone(), T2::N_BITS)) }
            },
            Hint::BigIntegerTmulLC4(a) => script! {
                { T2::push_u32_le(&bigint_to_u32_limbs(a.clone(), T4::N_BITS)) }
            },
        }
    }
}

pub fn fq_to_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let mut bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).skip(2).collect();
    bits.reverse();

    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
            let res = chunk.iter().fold(0, |acc, &x| {
                let r = acc + if x { factor } else { 0 };
                factor *= 2;
                r
            });
            res
        })
        .collect()
}
