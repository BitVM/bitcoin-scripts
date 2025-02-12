use crate::bigint::add::limb_add_carry;
use crate::bigint::sub::limb_sub_borrow;
use crate::bigint::U254;
use crate::bn254::fq::Fq;
use crate::bn254::utils::Hint;
use crate::treepp::*;
use ark_ff::PrimeField;
use bitcoin_script::script;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use std::str::FromStr;
use std::sync::OnceLock;

#[allow(clippy::declare_interior_mutable_const)]
pub trait Fp254Impl {
    const N_LIMBS: u32 = U254::N_LIMBS;
    const N_BITS: u32 = U254::N_BITS;

    const MODULUS: &'static str;
    const MODULUS_LIMBS: [u32; U254::N_LIMBS as usize];

    const P_PLUS_ONE_DIV2: &'static str;
    const TWO_P_PLUS_ONE_DIV3: &'static str;
    const P_PLUS_TWO_DIV3: &'static str;

    const ADD_ONCELOCK: OnceLock<Script> = OnceLock::new();
    const SUB_ONCELOCK: OnceLock<Script> = OnceLock::new();

    type ConstantType: PrimeField;

    #[inline]
    fn copy(a: u32) -> Script {
        U254::copy(a)
    }

    #[inline]
    fn roll(a: u32) -> Script {
        U254::roll(a)
    }

    #[inline]
    fn drop() -> Script {
        U254::drop()
    }

    #[inline]
    fn toaltstack() -> Script {
        U254::toaltstack()
    }

    #[inline]
    fn fromaltstack() -> Script {
        U254::fromaltstack()
    }

    #[inline]
    fn zip(a: u32, b: u32) -> Script {
        U254::zip(a, b)
    }

    #[inline]
    fn push_modulus() -> Script {
        U254::push_hex(Self::MODULUS)
    }

    #[inline]
    fn push_zero() -> Script {
        U254::push_zero()
    }

    #[inline]
    fn push_one() -> Script {
        U254::push_one()
    }

    #[inline]
    fn push_u32_le(v: &[u32]) -> Script {
        script! {
            { U254::push_u32_le(&BigUint::from_slice(v).to_u32_digits()) }
        }
    }

    #[inline]
    fn read_u32_le(witness: Vec<Vec<u8>>) -> Vec<u32> {
        U254::read_u32_le(witness)
    }

    #[inline]
    fn push_dec(dec_string: &str) -> Script {
        let v = BigUint::from_str_radix(dec_string, 10).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn push_hex(hex_string: &str) -> Script {
        let v = BigUint::from_str_radix(hex_string, 16).unwrap();
        script! {
            { U254::push_u32_le(&v.to_u32_digits()) }
        }
    }

    #[inline]
    fn equal(a: u32, b: u32) -> Script {
        U254::equal(a, b)
    }

    #[inline]
    fn equalverify(a: u32, b: u32) -> Script {
        U254::equalverify(a, b)
    }

    fn is_zero(a: u32) -> Script {
        U254::is_zero(a)
    }

    fn is_zero_keep_element(a: u32) -> Script {
        U254::is_zero_keep_element(a)
    }

    fn is_one() -> Script {
        script! {
            { Self::push_one() }
            { Self::equal(1, 0) }
        }
    }

    fn is_one_keep_element(a: u32) -> Script {
        script! {
            { Self::copy(a) }
            { Self::is_one() }
        }
    }

    fn is_field() -> Script {
        script! {
            // Each limb must not be negative
            for i in 0..Self::N_LIMBS - 1 {
                { i } OP_PICK
                0 OP_GREATERTHANOREQUAL OP_TOALTSTACK
            }
            { Self::N_LIMBS - 1 } OP_PICK
            0 OP_GREATERTHANOREQUAL
            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK OP_BOOLAND
            }
            OP_TOALTSTACK

            { Self::push_modulus() }
            { U254::lessthan(1, 0) }

            OP_FROMALTSTACK OP_BOOLAND
        }
    }

    #[inline]
    fn convert_to_le_bits_toaltstack() -> Script {
        U254::convert_to_le_bits_toaltstack()
    }

    // A + B mod M
    // Ci⁺ overflow carry bit (A+B)
    // Ci⁻ overflow carry bit (A-B)
    fn add(a: u32, b: u32) -> Script {
        let binding = Self::ADD_ONCELOCK;
        let add_script = binding.get_or_init(|| {
            script! {
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀
                { 0x20000000 }
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀ 2²⁹

                // A₀ + B₀
                limb_add_carry
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁺ A₀+B₀
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁺ A₀+B₀ | A₀+B₀
                OP_ROT
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ 2²⁹
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ A₀+B₀ M₀ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁺ 2²⁹ C₀⁻ | (A₀+B₀)-M₀

                // from     A₁      + B₁        + carry_0
                //   to     A{N-2}  + B{N-2}    + carry_{N-3}
                for i in 1..Self::N_LIMBS-1 {
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁻ B₁ C₀⁺
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁻ B₁+C₀⁺
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ B₁+C₀⁺ A₁ 2²⁹
                    limb_add_carry
                    OP_DUP
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁻ 2²⁹ C₁⁺ (B₁+C₀)+A₁ | (B₁+C₀)+A₁
                    OP_2SWAP
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻
                    { Self::MODULUS_LIMBS[i as usize] }
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻ M₁
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ 2²⁹ C₀⁻+M₁
                    OP_ROT
                    OP_SWAP
                    OP_ROT
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ (B₁+C₀)+A₁ C₀⁻+M₁ 2²⁹
                    limb_sub_borrow
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁺ 2²⁹ C₁⁻ | ((B₁+C₀)+A₁)-(C₀⁻+M₁)
                }
                // ⋯ A₈ B₈ C₇⁺ 2²⁹ C₇⁻
                OP_2SWAP
                OP_ADD
                // ⋯ A₈ 2²⁹ C₇⁻ B₈+C₇⁺
                OP_2SWAP
                OP_ROT
                OP_ROT
                // ⋯ C₇⁻ 2²⁹ B₈+C₇⁺ A₈
                OP_ADD
                // ⋯ C₇⁻ 2²⁹ (B₈+C₇⁺)+A₈
                OP_DUP
                OP_TOALTSTACK
                OP_ROT
                // ⋯ 2²⁹ (B₈+C₇⁺)+A₈ C₇⁻
                { *Self::MODULUS_LIMBS.last().unwrap() }
                // ⋯ 2²⁹ (B₈+C₇⁺)+A₈ C₇⁻ M₈
                OP_ADD
                OP_ROT
                // ⋯ (B₈+C₇⁺)+A₈ C₇⁻+M₈ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ 2²⁹ C₈⁻ | ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈)
                OP_NIP
                OP_DUP

                // ⋯ C₈⁻ C₈⁻
                OP_IF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF

                OP_FROMALTSTACK
                // ⋯ (B₈+C₇⁺)+A₈ C₈⁻ | ((B₇+C₆⁺)+A₇)-(C₆⁻+M₇)
                // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) C₈⁻ | (B₈+C₇⁺)+A₈
                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK  OP_DROP
                    OP_FROMALTSTACK
                }
                // ⋯ (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₂+C₁⁺)+A₂ (B₁+C₀⁺)+A₁ A₀+B₀ C₈⁻
                // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀ C₈⁻ | A₀+B₀
                { Self::N_LIMBS }
                OP_ROLL
                OP_NOTIF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF
                // ⋯ (B₈+C₇⁺)+A₈ (B₇+C₆⁺)+A₇ ... (B₁+C₀⁺)+A₁ A₀+B₀
                // ⋯ ((B₈+C₇⁺)+A₈)-(C₇⁻+M₈) ... (A₀+B₀)-M₀
            }
        });
        script! {
            { Self::zip(a, b) }
            { add_script.clone() }
        }
    }

    fn neg(a: u32) -> Script {
        script! {
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ ⋯
            { Self::roll(a) }
            { Self::is_zero_keep_element(0) }
            OP_NOTIF
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀
                { Self::MODULUS_LIMBS[0] } OP_SWAP { 0x20000000 }
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁻ | M₀-A₀ ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ 2²⁹ C₀⁻+A₁
                { Self::MODULUS_LIMBS[1] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ 2²⁹ C₁⁻ | M₁-(C₀⁻+A₁) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ 2²⁹ C₁⁻+A₂
                { Self::MODULUS_LIMBS[2] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ 2²⁹ C₂⁻ | M₂-(C₁⁻+A₂) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ 2²⁹ C₂⁻+A₃
                { Self::MODULUS_LIMBS[3] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ 2²⁹ C₃⁻ | M₃-(C₂⁻+A₃) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ 2²⁹ C₃⁻+A₄
                { Self::MODULUS_LIMBS[4] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ 2²⁹ C₄⁻ | M₄-(C₃⁻+A₄) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ A₆ 2²⁹ C₄⁻+A₅
                { Self::MODULUS_LIMBS[5] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ 2²⁹ C₅⁻ | M₅-(C₄⁻+A₅) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ A₇ 2²⁹ C₅⁻+A₆
                { Self::MODULUS_LIMBS[6] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ A₇ 2²⁹ C₆⁻ | M₆-(C₅⁻+A₆) ⋯
                OP_ROT OP_ADD
                // ⋯ A₈ 2²⁹ C₆⁻+A₇
                { Self::MODULUS_LIMBS[7] } OP_SWAP OP_ROT
                limb_sub_borrow OP_TOALTSTACK
                // ⋯ A₈ 2²⁹ C₇⁻ | M₇-(C₆⁻+A₇) ⋯
                OP_NIP OP_ADD
                // ⋯ C₇⁻+A₈
                { Self::MODULUS_LIMBS[8] } OP_SWAP OP_SUB
                // ⋯ M₈-(C₇⁻+A₈)
                OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
                OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            OP_ENDIF
        }
    }

    // A - B mod M
    // Ci⁻ overflow carry bit (A-B)
    // Ci⁺ overflow carry bit (A+B)
    fn sub(a: u32, b: u32) -> Script {
        let binding = Self::SUB_ONCELOCK;
        let sub_script = binding.get_or_init(|| {
            script! {
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀
                { 0x20000000 }
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ A₀ B₀ 2²⁹

                // A₀ - B₀
                limb_sub_borrow
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁻ A₀-B₀
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ 2²⁹ C₀⁻ A₀-B₀ | A₀-B₀
                OP_ROT
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ A₀-B₀ 2²⁹
                { Self::MODULUS_LIMBS[0] }
                OP_SWAP
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ A₀-B₀ M₀ 2²⁹
                limb_add_carry
                OP_TOALTSTACK
                // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ 2²⁹ C₀⁺ | (A₀-B₀)+M₀

                // from     A₁      - B₁        - carry_0
                //   to     A{N-2}  - B{N-2}    - carry_{N-3}
                for i in 1..Self::N_LIMBS-1 {
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ B₁ C₀⁻ 2²⁹ C₀⁺
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁺ B₁ C₀⁻
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ A₁ 2²⁹ C₀⁺ B₁+C₀⁻
                    OP_2SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁺ B₁+C₀⁻ A₁ 2²⁹
                    OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
                    limb_sub_borrow
                    OP_DUP
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₀⁺ 2²⁹ C₁⁻ A₁-(B₁+C₀) | A₁-(B₁+C₀)
                    OP_2SWAP
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺
                    { Self::MODULUS_LIMBS[i as usize] }
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺ M₁
                    OP_ADD
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) 2²⁹ C₀⁺+M₁
                    OP_SWAP
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ A₁-(B₁+C₀) C₀⁺+M₁ 2²⁹
                    limb_add_carry
                    OP_TOALTSTACK
                    // ⋯ A₈ B₈ A₇ B₇ A₆ B₆ A₅ B₅ A₄ B₄ A₃ B₃ A₂ B₂ C₁⁻ 2²⁹ C₁⁺ | (A₁-(B₁+C₀))+(C₀⁺+M₁)
                }
                // ⋯ A₈ B₈ C₇⁻ 2²⁹ C₇⁺
                OP_2SWAP
                OP_ADD
                // ⋯ A₈ 2²⁹ C₇⁺ B₈+C₇⁻
                OP_2SWAP
                // ⋯ C₇⁺ B₈+C₇⁻ A₈ 2²⁹
                OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
                // ⋯ C₇⁺ A₈ B₈+C₇⁻ 2²⁹
                limb_sub_borrow
                // ⋯ C₇⁺ 2²⁹ C₈⁻ A₈-(B₈+C₇⁻)
                OP_DUP
                OP_TOALTSTACK
                // ⋯ C₇⁺ 2²⁹ C₈⁻ A₈-(B₈+C₇⁻) | A₈-(B₈+C₇⁻)
                OP_ROT OP_TOALTSTACK
                // ⋯ C₇⁺ C₈⁻ A₈-(B₈+C₇⁻) | 2²⁹ A₈-(B₈+C₇⁻)
                OP_ROT { *Self::MODULUS_LIMBS.last().unwrap() }
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻)) C₇⁺ M₈
                OP_ADD OP_ADD
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈)
                OP_FROMALTSTACK OP_2DUP OP_GREATERTHANOREQUAL
                OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
                OP_TOALTSTACK
                // ⋯ C₈⁻ | (A₈-(B₈+C₇⁻))+(C₇⁺+M)₈ A₈-(B₈+C₇⁻)
                OP_DUP
                // ⋯ C₈⁻ C₈⁻
                OP_NOTIF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF

                OP_FROMALTSTACK
                // ⋯ C₈⁻ A₈-(B₈+C₇⁻) | (A₇-(B₇+C₆⁻))+(C₆⁺+M₇)
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) | (B₈+C₇⁻)+A₈
                for _ in 0..Self::N_LIMBS-1 {
                    OP_FROMALTSTACK  OP_DROP
                    OP_FROMALTSTACK
                }
                // ⋯ C₈⁻ A₈-(B₈+C₇⁻) A₇-(B₇+C₆⁻) ... A₂-(B₂+C₁⁻) A₁-(B₁+C₀⁻) A₀+B₀
                // ⋯ C₈⁻ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) ... (A₀+B₀)-M₀ | A₀+B₀
                { Self::N_LIMBS }
                OP_ROLL
                OP_IF
                    OP_FROMALTSTACK
                    OP_DROP
                OP_ENDIF
                // ⋯ A₈-(B₈+C₇⁻) A₇-(B₇+C₆⁻) ... A₁-(B₁+C₀⁻) A₀+B₀
                // ⋯ (A₈-(B₈+C₇⁻))+(C₇⁺+M₈) ... (A₀-B₀)+M₀
            }
        });
        script! {
            { Self::zip(a, b) }
            { sub_script.clone() }
        }
    }

    fn double(a: u32) -> Script {
        script! {
            { Self::roll(a) }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀
            OP_DUP
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ A₀
            { 0x20000000 }
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ A₀ A₀ 2²⁹

            // A₀ + A₀
            limb_add_carry
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁺ 2⋅A₀
            OP_DUP
            OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ 2²⁹ C₀⁺ 2⋅A₀ | 2⋅A₀
            OP_ROT
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2⋅A₀ 2²⁹
            { Self::MODULUS_LIMBS[0] }
            OP_SWAP
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2⋅A₀ M₀ 2²⁹
            limb_sub_borrow
            OP_TOALTSTACK
            // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2²⁹ C₀⁻ | 2⋅A₀-M₀

            // from     A₁      + A₁        + carry_0
            //   to     A{N-2}  + A{N-2}    + carry_{N-3}
            for i in 1..Self::N_LIMBS-1 {
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ A₁ C₀⁺ 2²⁹ C₀⁻
                OP_SWAP OP_2SWAP
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ A₁ C₀⁺
                OP_OVER OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ A₁ A₁+C₀⁺
                OP_ROT
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ A₁ A₁+C₀⁺ 2²⁹
                limb_add_carry
                OP_DUP
                OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₀⁻ 2²⁹ C₁⁺ 2⋅A₁+C₀⁺ | 2⋅A₁+C₀⁺
                OP_ROT OP_TOALTSTACK OP_ROT
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻ | 2²⁹
                { Self::MODULUS_LIMBS[i as usize] }
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻ M₁
                OP_ADD
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻+M₁
                OP_FROMALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2⋅A₁+C₀⁺ C₀⁻+M₁ 2²⁹
                limb_sub_borrow
                OP_TOALTSTACK
                // ⋯ A₈ A₇ A₆ A₅ A₄ A₃ A₂ C₁⁺ 2²⁹ C₁⁻ | (2⋅A₁+C₀⁺)-(C₀⁻+M₁)
            }
            // ⋯ A₈ C₇⁺ 2²⁹ C₇⁻
            OP_2SWAP
            // ⋯ 2²⁹ C₇⁻ A₈ C₇⁺
            OP_OVER OP_ADD
            // ⋯ 2²⁹ C₇⁻ A₈ A₈+C₇⁺
            OP_ADD
            // ⋯ 2²⁹ C₇⁻ 2⋅A₈+C₇⁺
            OP_DUP OP_TOALTSTACK
            // ⋯ 2²⁹ C₇⁻ 2⋅A₈+C₇⁺ | 2⋅A₈+C₇⁺
            OP_SWAP
            // ⋯ 2²⁹ 2⋅A₈+C₇⁺ C₇⁻
            { *Self::MODULUS_LIMBS.last().unwrap() }
            // ⋯ 2²⁹ 2⋅A₈+C₇⁺ C₇⁻ M₈
            OP_ADD
            OP_ROT
            // ⋯ 2⋅A₈+C₇⁺ C₇⁻+M₈ 2²⁹
            limb_sub_borrow
            OP_TOALTSTACK
            // ⋯ 2²⁹ C₈⁻ | (2⋅A₈+C₇⁺)-(C₇⁻+M₈)
            OP_NIP
            OP_DUP
            // ⋯ C₈⁻ C₈⁻
            OP_IF
                OP_FROMALTSTACK
                OP_DROP
            OP_ENDIF

            OP_FROMALTSTACK
            // ⋯ 2⋅A₈+C₇⁺ C₈⁻ | (2⋅A₇+C₆⁺)-(C₆⁻+M₇)
            // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) C₈⁻ | 2⋅A₈+C₇⁺
            for _ in 0..Self::N_LIMBS-1 {
                OP_FROMALTSTACK  OP_DROP
                OP_FROMALTSTACK
            }
            // ⋯ 2⋅A₈+C₇⁺ 2⋅A₇+C₆⁺ ... 2⋅A₂+C₁⁺ 2⋅A₁+C₀⁺ 2⋅A₀ C₈⁻
            // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) ... 2⋅A₀-M₀ C₈⁻ | 2⋅A₀
            { Self::N_LIMBS }
            OP_ROLL
            OP_NOTIF
                OP_FROMALTSTACK
                OP_DROP
            OP_ENDIF
            // ⋯ 2⋅A₈+C₇⁺ 2⋅A₇+C₆⁺ ... 2⋅A₁+C₀⁺ 2⋅A₀
            // ⋯ (2⋅A₈+C₇⁺)-(C₇⁻+M₈) ... 2⋅A₀-M₀
        }
    }

    fn div2() -> Script {
        script! {
            { U254::div2rem() }
            OP_IF
                { U254::push_hex(Self::P_PLUS_ONE_DIV2) }
                { Self::add(1, 0) }
            OP_ENDIF
        }
    }

    fn div3() -> Script {
        script! {
            { U254::div3rem() }
            OP_DUP
            0 OP_GREATERTHAN
            OP_IF
                OP_1SUB
                OP_IF
                    { U254::push_hex(Self::P_PLUS_TWO_DIV3) }
                    { Self::add(1, 0) }
                OP_ELSE
                    { U254::push_hex(Self::TWO_P_PLUS_ONE_DIV3) }
                    { Self::add(1, 0) }
                OP_ENDIF
            OP_ELSE
                OP_DROP
            OP_ENDIF
        }
    }

    fn hinted_mul(
        mut a_depth: u32,
        mut a: ark_bn254::Fq,
        mut b_depth: u32,
        mut b: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        assert_ne!(a_depth, b_depth);
        if a_depth > b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }

        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(a_depth + 1) }
            { Fq::roll(b_depth + 1) }
            { Fq::tmul() }
        };
        hints.push(Hint::BigIntegerTmulLC1(q));

        (script, hints)
    }

    // TODO: Optimize by using the constant feature
    fn hinted_mul_by_constant(a: ark_bn254::Fq, constant: &ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&constant.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(1) }
            { Fq::push(*constant) }
            { Fq::tmul() }
        };
        hints.push(Hint::BigIntegerTmulLC1(q));

        (script, hints)
    }

    fn hinted_mul_keep_element(
        mut a_depth: u32,
        mut a: ark_bn254::Fq,
        mut b_depth: u32,
        mut b: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        assert_ne!(a_depth, b_depth);
        if a_depth > b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }

        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::copy(a_depth + 1) }
            { Fq::copy(b_depth + 2) }
            { Fq::tmul() }
        };
        hints.push(Hint::BigIntegerTmulLC1(q));

        (script, hints)
    }

    #[allow(clippy::too_many_arguments)]
    fn hinted_mul_lc2(
        a_depth: u32,
        a: ark_bn254::Fq,
        b_depth: u32,
        b: ark_bn254::Fq,
        c_depth: u32,
        c: ark_bn254::Fq,
        d_depth: u32,
        d: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        assert!(a_depth > b_depth && b_depth > c_depth && c_depth > d_depth);

        let mut hints = Vec::new();

        let modulus = &Fq::modulus_as_bigint();

        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let z = BigInt::from_str(&c.to_string()).unwrap();
        let w = BigInt::from_str(&d.to_string()).unwrap();

        let q = (x * z + y * w) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(a_depth + 1) }
            { Fq::roll(b_depth + 2) }
            { Fq::roll(c_depth + 3) }
            { Fq::roll(d_depth + 4) }
            { Fq::tmul_lc2() }
        };
        hints.push(Hint::BigIntegerTmulLC2(q));

        (script, hints)
    }

    #[allow(clippy::too_many_arguments)]
    fn hinted_mul_lc4(
        a_depth: u32,
        a: ark_bn254::Fq,
        b_depth: u32,
        b: ark_bn254::Fq,
        c_depth: u32,
        c: ark_bn254::Fq,
        d_depth: u32,
        d: ark_bn254::Fq,

        e_depth: u32,
        e: ark_bn254::Fq,
        f_depth: u32,
        f: ark_bn254::Fq,
        g_depth: u32,
        g: ark_bn254::Fq,
        h_depth: u32,
        h: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        assert!(a_depth > b_depth && b_depth > c_depth && c_depth > d_depth && d_depth > e_depth && e_depth > f_depth && f_depth > g_depth && g_depth > h_depth);

        let mut hints = Vec::new();

        let modulus = &Fq::modulus_as_bigint();

        let x1 = BigInt::from_str(&a.to_string()).unwrap();
        let y1 = BigInt::from_str(&b.to_string()).unwrap();
        let z1 = BigInt::from_str(&c.to_string()).unwrap();
        let w1 = BigInt::from_str(&d.to_string()).unwrap();

        let x2 = BigInt::from_str(&e.to_string()).unwrap();
        let y2 = BigInt::from_str(&f.to_string()).unwrap();
        let z2 = BigInt::from_str(&g.to_string()).unwrap();
        let w2 = BigInt::from_str(&h.to_string()).unwrap();

        let q = (x1 * x2 + y1 * y2 + z1 * z2 + w1 * w2) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { fq_push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(a_depth + 1) }
            { Fq::roll(b_depth + 2) }
            { Fq::roll(c_depth + 3) }
            { Fq::roll(d_depth + 4) }
            { Fq::roll(e_depth + 5) }
            { Fq::roll(f_depth + 6) }
            { Fq::roll(g_depth + 7) }
            { Fq::roll(h_depth + 8) }
            { Fq::tmul_lc4() }
        };
        hints.push(Hint::BigIntegerTmulLC4(q));

        (script, hints)
    }
    
    #[allow(clippy::too_many_arguments)]
    fn hinted_mul_lc2_keep_elements(
        a_depth: u32,
        a: ark_bn254::Fq,
        b_depth: u32,
        b: ark_bn254::Fq,
        c_depth: u32,
        c: ark_bn254::Fq,
        d_depth: u32,
        d: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        assert!(a_depth > b_depth && b_depth > c_depth && c_depth > d_depth);

        let mut hints = Vec::new();

        let modulus = &Fq::modulus_as_bigint();

        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&b.to_string()).unwrap();
        let z = BigInt::from_str(&c.to_string()).unwrap();
        let w = BigInt::from_str(&d.to_string()).unwrap();

        let q = (x * z + y * w) / modulus;

        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::copy(a_depth + 1) }
            { Fq::copy(b_depth + 2) }
            { Fq::copy(c_depth + 3) }
            { Fq::copy(d_depth + 4) }
            { Fq::tmul_lc2() }
        };
        hints.push(Hint::BigIntegerTmulLC2(q));

        (script, hints)
    }

    // TODO: Optimize using the sqaure feature
    fn hinted_square(a: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = &BigInt::from_str(&a.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let q = (x * x) / modulus;
        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            { Fq::roll(1) }
            { Fq::copy(0) }
            { Fq::tmul() }
        };
        hints.push(Hint::BigIntegerTmulLC1(q));

        (script, hints)
    }

    fn hinted_inv(a: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = &BigInt::from_str(&a.to_string()).unwrap();
        let modulus = &Fq::modulus_as_bigint();
        let y = &x.modinv(modulus).unwrap();
        let q = (x * y) / modulus;
        let script = script! {
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            for _ in 0..Self::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            // { Fq::push(ark_bn254::Fq::from_str(&y.to_string()).unwrap()) }
            // { Fq::push(ark_bn254::Fq::from_str(&q.to_string()).unwrap()) }
            // x, y, q
            { Fq::roll(2) }
            { Fq::copy(2) }
            // y, q, x, y
            { Fq::tmul() }
            // y, 1
            { Fq::push_one() }
            { Fq::equalverify(1, 0) }
        };
        hints.push(Hint::Fq(ark_bn254::Fq::from_str(&y.to_string()).unwrap()));
        hints.push(Hint::BigIntegerTmulLC1(q));

        (script, hints)
    }
}
