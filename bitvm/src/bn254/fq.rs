#![allow(clippy::reversed_empty_ranges)]
use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, Num, ToPrimitive};

use crate::bigint::BigIntImpl;
use crate::bn254::fp254impl::Fp254Impl;
use crate::pseudo::NMUL;
use crate::treepp::*;

pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    // p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    const MODULUS_LIMBS: [u32; Self::N_LIMBS as usize] = [
        0x187cfd47, 0x10460b6, 0x1c72a34f, 0x2d522d0, 0x1585d978, 0x2db40c0, 0xa6e141, 0xe5c2634,
        0x30644e,
    ];

    const P_PLUS_ONE_DIV2: &'static str =
        "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4";

    const TWO_P_PLUS_ONE_DIV3: &'static str =
        "2042def740cbc01bd03583cf0100e593ba56470b9af68708d2c05d6490535385";

    const P_PLUS_TWO_DIV3: &'static str =
        "10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9c3";
    type ConstantType = ark_bn254::Fq;
}

impl Fq {
    pub fn modulus_as_bigint() -> BigInt {
        BigInt::from_str_radix(Self::MODULUS, 16).unwrap()
    }

    pub fn tmul() -> Script {
        script! {
            { <Fq as Fp254Mul>::tmul() }
        }
    }

    pub fn tmul_lc2() -> Script {
        script! {
            { <Fq as Fp254Mul2LC>::tmul() }
        }
    }

    pub const fn bigint_tmul_lc_1() -> (u32, u32) {
        const X: u32 = <Fq as Fp254Mul>::T::N_BITS;
        const Y: u32 = <Fq as Fp254Mul>::LIMB_SIZE;
        (X, Y)
    }

    pub const fn bigint_tmul_lc_2() -> (u32, u32) {
        const X: u32 = <Fq as Fp254Mul2LC>::T::N_BITS;
        const Y: u32 = <Fq as Fp254Mul2LC>::LIMB_SIZE;
        (X, Y)
    }
    
    #[inline]
    pub fn push(a: ark_bn254::Fq) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
        }
    }
}

pub fn bigint_to_u32_limbs(n: BigInt, n_bits: u32) -> Vec<u32> {
    const LIMB_SIZE: u64 = 32;
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

macro_rules! fp_lc_mul {
    ($NAME:ident, $MOD_WIDTH:literal, $VAR_WIDTH:literal, $LCS:expr) => {
        paste::paste! {
            trait [<Fp254 $NAME>] {
                const LIMB_SIZE: u32 = 29;
                const LCS: [bool; $LCS.len()] = $LCS;
                const LC_BITS: u32 = usize::BITS - $LCS.len().leading_zeros() - 1;
                type U;
                type T;
                fn tmul() -> Script;
            }

            impl [<Fp254 $NAME>] for Fq {

                type U = BigIntImpl<{ Self::N_BITS }, { <Self as [<Fp254 $NAME>]>::LIMB_SIZE }>;
                type T = BigIntImpl<{ Self::N_BITS + $VAR_WIDTH + <Self as [<Fp254 $NAME>]>::LC_BITS + 1 }, { <Self as [<Fp254 $NAME>]>::LIMB_SIZE }>;

                fn tmul() -> Script {
                    const N_BITS: u32 = Fq::N_BITS;
                    const LIMB_SIZE: u32 = <Fq as [<Fp254 $NAME>]>::LIMB_SIZE;
                    const N_LC: u32 = <Fq as [<Fp254 $NAME>]>::LCS.len() as u32;
                    const MOD_WIDTH: u32 = $MOD_WIDTH;
                    const VAR_WIDTH: u32 = $VAR_WIDTH;

                    assert_eq!(MOD_WIDTH, VAR_WIDTH);

                    let lc_signs = <Fq as [<Fp254 $NAME>]>::LCS;

                    type U = <Fq as [<Fp254 $NAME>]>::U;
                    type T = <Fq as [<Fp254 $NAME>]>::T;

                    // N_BITS for the extended number used during intermediate computation
                    const MAIN_LOOP_END: u32 = {
                        let n_bits_mod_width = N_BITS.div_ceil(MOD_WIDTH) * MOD_WIDTH;
                        let n_bits_var_width = N_BITS.div_ceil(VAR_WIDTH) * VAR_WIDTH;
                        let mut u = n_bits_mod_width;
                        if n_bits_var_width > u {
                            u = n_bits_var_width;
                        }
                        while !(u % MOD_WIDTH == 0 && u % VAR_WIDTH == 0) {
                            u += 1;
                        }
                        u
                    };

                    // Pre-computed lookup table allows us to skip initial few doublings
                    const MAIN_LOOP_START: u32 = {
                        if MOD_WIDTH < VAR_WIDTH {
                            MOD_WIDTH
                        } else {
                            VAR_WIDTH
                        }
                    };

                    const N_VAR_WINDOW: u32 = MAIN_LOOP_END / VAR_WIDTH;
                    const N_MOD_WINDOW: u32 = MAIN_LOOP_END / MOD_WIDTH;

                    // Pre-computed lookup table's size
                    fn size_table(window: u32) -> u32 { (1 << window) - 1 }

                    // Initialize the lookup table
                    fn init_table(window: u32) -> Script {
                        assert!(
                            (1..=6).contains(&window),
                            "expected 1<=window<=6; got window={}",
                            window
                        );
                        script! {
                            for i in 2..=window {
                                for j in 1 << (i - 1)..1 << i {
                                    if j % 2 == 0 {
                                        { T::double_allow_overflow_keep_element( (j/2 - 1) * T::N_LIMBS ) }
                                    } else {
                                        { T::add_ref_with_top(j - 2) }
                                    }
                                }
                            }
                        }
                    }

                    // Drop the lookup table
                    fn drop_table(window: u32) -> Script {
                        script! {
                            for _ in 1..1<<window {
                                { T::drop() }
                            }
                        }
                    }

                    // Get modulus window at given index
                    fn mod_window(index: u32) -> u32 {
                        let shift_by = MOD_WIDTH * (N_MOD_WINDOW - index - 1);
                        let bit_mask = BigInt::from_i32((1 << MOD_WIDTH) - 1).unwrap() << shift_by;
                        ((Fq::modulus_as_bigint() & bit_mask) >> shift_by).to_u32().unwrap()
                    }

                    // Get var windows at given index
                    fn var_windows_script(index: u32) -> Script {
                        let stack_top = T::N_LIMBS;
                        let iter = N_VAR_WINDOW - index;

                        let s_bit = iter * VAR_WIDTH - 1; // start bit
                        let e_bit = (iter - 1) * VAR_WIDTH; // end bit

                        let s_limb = s_bit / LIMB_SIZE; // start bit limb
                        let e_limb = e_bit / LIMB_SIZE; // end bit limb

                        let mut st = 0;
                        if (e_bit % LIMB_SIZE == 0) || (s_limb > e_limb) {
                            st = (s_bit % LIMB_SIZE) + 1;
                        }

                        script! {
                            for j in 0..N_LC {
                                if iter == N_VAR_WINDOW { // initialize accumulator to track reduced limb
                                    { stack_top + T::N_LIMBS * j + s_limb } OP_PICK

                                } else if (s_bit + 1) % LIMB_SIZE == 0  { // drop current and initialize next accumulator
                                    OP_FROMALTSTACK OP_DROP
                                    { stack_top + T::N_LIMBS * j   + s_limb } OP_PICK

                                } else {
                                    OP_FROMALTSTACK // load accumulator from altstack
                                }

                                if (e_bit % LIMB_SIZE == 0) || (s_limb > e_limb) {
                                    if s_limb > e_limb {
                                        { NMUL(2) }
                                    } else {
                                        0
                                    }
                                }
                                for i in st..VAR_WIDTH {
                                    if s_limb > e_limb {
                                        if i % LIMB_SIZE == (s_bit % LIMB_SIZE) + 1 {
                                            // window is split between multiple limbs
                                            { stack_top + T::N_LIMBS * j + e_limb + 1 } OP_PICK
                                        }
                                    }
                                    if ( i == 0){
                                        { 1 << ((s_bit - i) % LIMB_SIZE) }
                                        OP_2DUP
                                        OP_GREATERTHANOREQUAL
                                        OP_IF
                                            OP_SUB
                                            2
                                        OP_ELSE
                                            OP_DROP
                                            0
                                        OP_ENDIF
                                        OP_SWAP
                                    } else{
                                        if (s_bit - i) % LIMB_SIZE > 7 {
                                            { 1 << ((s_bit - i) % LIMB_SIZE) }
                                            OP_2DUP
                                            OP_GREATERTHANOREQUAL
                                            OP_IF
                                                OP_SUB
                                                OP_SWAP OP_1ADD
                                            OP_ELSE
                                                OP_DROP
                                                OP_SWAP
                                            OP_ENDIF
                                            if i < VAR_WIDTH - 1 { { NMUL(2) } }
                                            OP_SWAP
                                        } else {
                                            OP_TUCK
                                            { (1 << ((s_bit - i) % LIMB_SIZE)) - 1 }
                                            OP_GREATERTHAN
                                            OP_TUCK
                                            OP_ADD
                                            if i < VAR_WIDTH - 1 { { NMUL(2) } }
                                            OP_ROT OP_ROT
                                            OP_IF
                                                { 1 << ((s_bit - i) % LIMB_SIZE) }
                                                OP_SUB
                                            OP_ENDIF
                                        }
                                    }
                                }

                                if j+1 < N_LC {
                                    if iter == N_VAR_WINDOW {
                                        OP_TOALTSTACK
                                        OP_TOALTSTACK
                                    } else {
                                        for _ in j+1..N_LC {
                                            OP_FROMALTSTACK
                                        }
                                        { N_LC - j - 1 } OP_ROLL OP_TOALTSTACK // acc
                                        { N_LC - j - 1 } OP_ROLL OP_TOALTSTACK // res
                                        for _ in j+1..N_LC {
                                            OP_TOALTSTACK
                                        }
                                    }
                                }
                            }
                            for _ in 0..N_LC-1 {
                                OP_FROMALTSTACK
                                OP_FROMALTSTACK
                            }
                            for j in (0..N_LC).rev() {
                                if j != 0 { { 2*j } OP_ROLL }
                                if iter == 1 { OP_DROP } else { OP_TOALTSTACK }
                            }
                        }
                    }

                    script! {
                        // stack: {q} {x0} {x1} {y0} {y1}
                        for _ in 0..2*N_LC {
                            // Range check: U < MODULUS
                            { U::copy(0) }                                                 // {q} {x0} {x1} {y0} {y1} {y1}
                            { U::push_u32_le(&Fq::modulus_as_bigint().to_u32_digits().1) } // {q} {x0} {x1} {y0} {y1} {y1} {MODULUS}
                            { U::lessthan(1, 0) } OP_VERIFY                                // {q} {x0} {x1} {y0} {y1}
                            { U::toaltstack() }                                            // {q} {x0} {x1} {y0} -> {y1}
                        }                                                                  // {q} -> {x0} {x1} {y0} {y1}
                        // Pre-compute lookup tables
                        { T::push_zero() }                   // {q} {0} -> {x0} {x1} {y0} {y1}
                        { T::sub(0, 1) }                     // {-q} -> {x0} {x1} {y0} {y1}
                        { init_table(MOD_WIDTH) }            // {-q_table} -> {x0} {x1} {y0} {y1}
                        for i in 0..N_LC {
                            { U::fromaltstack() }            // {-q_table} {x0} -> {x1} {y0} {y1}
                            { U::resize::<{ T::N_BITS }>() } // {-q_table} {x0} -> {x1} {y0} {y1}
                            if !lc_signs[i as usize] {
                                { T::push_zero() }           // {-q_table} {x0} {0} -> {x1} {y0} {y1}
                                { T::sub(0, 1) }             // {-q_table} {-x0} -> {x1} {y0} {y1}
                            }
                            { init_table(VAR_WIDTH) }        // {-q_table} {x0_table} -> {x1} {y0} {y1}
                        }                                    // {-q_table} {x0_table} {x1_table} -> {y0} {y1}
                        for _ in 0..N_LC {
                            { U::fromaltstack() }            // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
                            { U::resize::<{ T::N_BITS }>() } // {-q_table} {x0_table} {x1_table} {y0} -> {y1}
                        }                                    // {-q_table} {x0_table} {x1_table} {y0} {y1}
                        { T::push_zero() }                   // {-q_table} {x0_table} {x1_table} {y0} {y1} {0}

                        // Main loop
                        for i in MAIN_LOOP_START..=MAIN_LOOP_END {
                            // z += x*y[i]
                            if i % VAR_WIDTH == 0 {
                                { var_windows_script(i/VAR_WIDTH - 1) }
                                for _ in 1..N_LC { OP_TOALTSTACK }
                                for j in 0..N_LC {
                                    if j != 0 { OP_FROMALTSTACK }
                                    OP_DUP OP_NOT
                                    OP_IF
                                        OP_DROP
                                    OP_ELSE
                                        { 1 + N_LC + (N_LC - j) * size_table(VAR_WIDTH)  }
                                        OP_SWAP
                                        OP_SUB
                                        if i + j == MAIN_LOOP_START && j == 0 {
                                            for _ in 0..Self::N_LIMBS {
                                                OP_NIP
                                            }
                                            { NMUL(Self::N_LIMBS) }
                                            OP_DUP OP_PICK
                                            for _ in 0..Self::N_LIMBS-1 {
                                                OP_SWAP
                                                OP_DUP OP_PICK
                                            }
                                            OP_NIP
                                        } else {
                                            { T::add_ref_stack() }
                                        }
                                    OP_ENDIF
                                }
                            }
                            // z -= q*p[i]
                            if i % MOD_WIDTH == 0 && mod_window(i/MOD_WIDTH - 1) != 0  {
                                { T::add_ref(1 + N_LC + size_table(MOD_WIDTH) +
                                    N_LC * size_table(VAR_WIDTH) - mod_window(i/MOD_WIDTH - 1)) }
                            }
                            if i < MAIN_LOOP_END {
                                if MOD_WIDTH == VAR_WIDTH {
                                    if i % VAR_WIDTH == 0 {
                                        { T::lshift_prevent_overflow(VAR_WIDTH) }
                                    }
                                } else {
                                    { T::double_prevent_overflow() }
                                }
                            }
                        }

                        { T::is_positive(size_table(MOD_WIDTH) +                 // q was negative
                            N_LC * size_table(VAR_WIDTH) + N_LC) } OP_TOALTSTACK // {-q_table} {x0_table} {x1_table} {y0} {y1} {r} -> {0/1}
                        { T::toaltstack() }                                      // {-q_table} {x0_table} {x1_table} {y0} {y1} -> {r} {0/1}

                        // Cleanup
                        for _ in 0..N_LC { { T::drop() } }             // {-q_table} {x0_table} {x1_table} -> {r} {0/1}
                        for _ in 0..N_LC { { drop_table(VAR_WIDTH) } } // {-q_table} -> {r} {0/1}
                        { drop_table(MOD_WIDTH) }                      // -> {r} {0/1}

                        // Correction/validation
                        // r = if q < 0 { r + p } else { r }; assert(r < p)
                        { T::push_u32_le(&Fq::modulus_as_bigint().to_u32_digits().1) } // {MODULUS} -> {r} {0/1}
                        { T::fromaltstack() } OP_FROMALTSTACK // {MODULUS} {r} {0/1}
                        OP_IF { T::add_ref(1) } OP_ENDIF      // {MODULUS} {-r/r}
                        { T::copy(0) }                        // {MODULUS} {-r/r} {-r/r}
                        { T::lessthan(0, 2) } OP_VERIFY       // {-r/r}

                        // Resize res back to N_BITS
                        { T::resize::<N_BITS>() } // {r}
                    }
                }
            }
        }
    };
}

fp_lc_mul!(Mul, 4, 4, [true]);
fp_lc_mul!(Mul2LC, 3, 3, [true, true]);

#[cfg(test)]
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::treepp::*;
    use crate::chunker::common::extract_witness_from_stack;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use ark_ff::AdditiveGroup;
    use core::ops::{Add, Mul, Rem, Sub};
    use num_bigint::{BigInt, BigUint, RandBigInt, RandomBits};
    use num_traits::{Num, Signed};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn test_read_from_stack() {
        let _m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a: BigUint = prng.sample(RandomBits::new(254));

        let script = script! {
            { Fq::push_u32_le(&a.to_u32_digits()) }
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);

        let u32s = Fq::read_u32_le(witness);
        let read_a = BigUint::from_slice(&u32s);
        assert_eq!(read_a, a);
    }

    #[test]
    fn test_add() {
        println!("Fq.add: {} bytes", Fq::add(0, 1).len());

        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::push_u32_le(&b.to_u32_digits()) }
                { Fq::add(1, 0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_sub() {
        println!("Fq.sub: {} bytes", Fq::sub(0, 1).len());

        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));

            let a = a.rem(&m);
            let b = b.rem(&m);
            let c: BigUint = a.clone().add(&m).sub(b.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::push_u32_le(&b.to_u32_digits()) }
                { Fq::sub(1, 0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_double() {
        println!("Fq.double: {} bytes", Fq::double(0).len());
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        for _ in 0..100 {
            let a: BigUint = m.clone().sub(BigUint::new(vec![1]));

            let a = a.rem(&m);
            let c: BigUint = a.clone().add(a.clone()).rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::double(0) }
                { Fq::push_u32_le(&c.to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_neg() {
        println!("Fq.neg: {} bytes", Fq::neg(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::copy(0) }
                { Fq::neg(0) }
                { Fq::add(0, 1) }
                { Fq::push_zero() }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_div2() {
        println!("Fq.div2: {} bytes", Fq::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fq::div2() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_div3() {
        println!("Fq.div3: {} bytes", Fq::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = a.clone().double();
            let c = a.add(b);

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
                { Fq::div3() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_is_zero() {
        println!("Fq.is_zero: {} bytes", Fq::is_zero(0).len());
        println!(
            "Fq.is_zero_keep_element: {} bytes",
            Fq::is_zero_keep_element(0).len()
        );
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..10 {
            let a = ark_bn254::Fq::rand(&mut prng);

            let script = script! {
                // Push three Fq elements
                { Fq::push_zero() }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }

                // The first element should not be zero
                { Fq::is_zero_keep_element(0) }
                OP_NOT
                OP_TOALTSTACK

                // The third element should be zero
                { Fq::is_zero_keep_element(2) }
                OP_TOALTSTACK

                // Drop all three elements
                { Fq::drop() }
                { Fq::drop() }
                { Fq::drop() }

                // Both results should be true
                OP_FROMALTSTACK
                OP_FROMALTSTACK
                OP_BOOLAND
                { Fq::push_zero() }
                { Fq::is_zero(0) }
                OP_BOOLAND
            };
            run(script);
        }
    }

    #[test]
    fn test_is_field() {
        let m = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        println!("Fq.is_field: {} bytes", Fq::is_field().len());

        for _ in 0..10 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let a = a.rem(&m);

            let script = script! {
                { Fq::push_u32_le(&a.to_u32_digits()) }
                { Fq::is_field() }
            };
            run(script);
        }

        let script = script! {
            { Fq::push_modulus() } OP_1 OP_ADD
            { Fq::is_field() }
            OP_NOT
        };
        run(script);

        let script = script! {
            { Fq::push_modulus() } OP_1 OP_SUB
            OP_NEGATE
            { Fq::is_field() }
            OP_NOT
        };
        run(script);
    }

    #[allow(unused)]
    fn rand_bools<const SIZE: usize>(seed: u64) -> [bool; SIZE] {
        let mut bools = [true; SIZE];
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(seed);
        for i in 0..SIZE {
            bools[i] = prng.gen_bool(0.5);
        }
        bools
    }

    #[test]
    fn test_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq::hinted_mul(1, a, 0, b);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { Fq::push(b) }
                { hinted_mul.clone() }
                { Fq::push(c) }
                { Fq::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq::hinted_mul: {} @ {} stack", hinted_mul.len(), max_stack);
        }
    }

    #[test]
    fn test_hinted_mul_keep_element() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq::hinted_mul_keep_element(1, a, 0, b);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { Fq::push(b) }
                { hinted_mul.clone() }
                { Fq::push(c) }
                { Fq::equal(0, 1) }
                OP_TOALTSTACK
                { Fq::drop() }
                { Fq::drop() }
                OP_FROMALTSTACK
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq::hinted_mul_keep_element: {} @ {} stack",
                hinted_mul.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_hinted_mul_by_constant() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq::hinted_mul_by_constant(a, &b);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { hinted_mul.clone() }
                { Fq::push(c) }
                { Fq::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq::hinted_mul_by_constant: {} @ {} stack",
                hinted_mul.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_hinted_mul_lc2() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let c = ark_bn254::Fq::rand(&mut prng);
            let d = ark_bn254::Fq::rand(&mut prng);
            let e = a.mul(&c).add(b.mul(&d));

            let (hinted_mul_lc2, hints) = Fq::hinted_mul_lc2(3, a, 2, b, 1, c, 0, d);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { Fq::push(b) }
                { Fq::push(c) }
                { Fq::push(d) }
                { hinted_mul_lc2.clone() }
                { Fq::push(e) }
                { Fq::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq::hinted_mul_lc2: {} @ {} stack",
                hinted_mul_lc2.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_hinted_mul_lc2_keep_elements() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let b = ark_bn254::Fq::rand(&mut prng);
            let c = ark_bn254::Fq::rand(&mut prng);
            let d = ark_bn254::Fq::rand(&mut prng);
            let e = a.mul(&c).add(b.mul(&d));

            let (hinted_mul_lc2, hints) = Fq::hinted_mul_lc2_keep_elements(3, a, 2, b, 1, c, 0, d);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { Fq::push(b) }
                { Fq::push(c) }
                { Fq::push(d) }
                { hinted_mul_lc2.clone() }
                { Fq::push(e) }
                { Fq::equal(0, 1) }
                OP_TOALTSTACK
                { Fq::drop() }
                { Fq::drop() }
                { Fq::drop() }
                { Fq::drop() }
                OP_FROMALTSTACK
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq::hinted_mul_lc2: {} @ {} stack",
                hinted_mul_lc2.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_hinted_square() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq::rand(&mut prng);
            let c = a.mul(&a);

            let (hinted_square, hints) = Fq::hinted_square(a);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(a) }
                { hinted_square.clone() }
                { Fq::push(c) }
                { Fq::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq::hinted_square: {} @ {} stack",
                hinted_square.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a = ark_bn254::Fq::rand(&mut prng);
        let c = a.inverse().unwrap();

        let (hinted_inv, hints) = Fq::hinted_inv(a);
        println!("Fq::hinted_inv: {} bytes", hinted_inv.len());

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push_u32_le(&BigUint::from(a).to_u32_digits()) }
            { hinted_inv }
            { Fq::push_u32_le(&BigUint::from(c).to_u32_digits()) }
            { Fq::equalverify(1, 0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_windowed_mul() {
        type U = <Fq as Fp254Mul>::U;
        type T = <Fq as Fp254Mul>::T;

        let zero = &BigInt::ZERO;
        let modulus = &Fq::modulus_as_bigint();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let x = &prng.gen_bigint_range(zero, modulus);
            let y = &prng.gen_bigint_range(zero, modulus);
            let r = (x * y) % modulus;

            // correct quotient
            let q = (x * y) / modulus;
            let script = script! {
                { T::push_u32_le(&bigint_to_u32_limbs(q, T::N_BITS)) }
                { U::push_u32_le(&x.to_u32_digits().1) }
                { U::push_u32_le(&y.to_u32_digits().1) }
                { <Fq as Fp254Mul>::tmul() }
                { U::push_u32_le(&r.to_u32_digits().1) }
                { U::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);

            // incorrect quotient
            let q = (x * y) / modulus;
            let q = loop {
                let rnd = prng.gen_bigint_range(zero, modulus);
                if rnd != q {
                    break rnd;
                }
            };
            let script = script! {
                { T::push_u32_le(&bigint_to_u32_limbs(q, T::N_BITS)) }
                { U::push_u32_le(&x.to_u32_digits().1) }
                { U::push_u32_le(&y.to_u32_digits().1) }
                { <Fq as Fp254Mul>::tmul() }
                { U::push_u32_le(&r.to_u32_digits().1) }
                { U::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(!res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
        }

        println!(
            "<Fq as Fp254Mul>::tmul: {} @ {} stack",
            <Fq as Fp254Mul>::tmul().len(),
            max_stack
        );
    }

    #[test]
    fn test_windowed_mul_2lc() {
        type U = <Fq as Fp254Mul2LC>::U;
        type T = <Fq as Fp254Mul2LC>::T;

        let lcs = <Fq as Fp254Mul2LC>::LCS;

        let zero = &BigInt::ZERO;
        let modulus = &Fq::modulus_as_bigint();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let xs = lcs.map(|_| prng.gen_bigint_range(zero, modulus));
            let ys = lcs.map(|_| prng.gen_bigint_range(zero, modulus));
            let mut qs = vec![];
            let mut rs = vec![];

            let mut c = zero.clone();
            for i in 0..lcs.len() {
                let xy = &xs[i] * &ys[i];
                qs.push(&xy / modulus);
                rs.push(&xy % modulus);
                c += if lcs[i] { xy } else { -xy };
            }
            let r = &c % modulus;
            let r = &(if r.is_negative() { modulus + r } else { r });

            // correct quotient
            let q = &(&c / modulus);
            let script = script! {
                { T::push_u32_le(&bigint_to_u32_limbs(q.clone(), T::N_BITS)) }
                for i in 0..lcs.len() {
                    { U::push_u32_le(&xs[i].to_u32_digits().1) }
                }
                for i in 0..lcs.len() {
                    { U::push_u32_le(&ys[i].to_u32_digits().1) }
                }
                { <Fq as Fp254Mul2LC>::tmul() }
                { U::push_u32_le(&r.to_u32_digits().1) }
                { U::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);

            // incorrect quotient
            let q = loop {
                let rnd = prng.gen_bigint_range(zero, modulus);
                if rnd != *q {
                    break rnd;
                }
            };
            let script = script! {
                { T::push_u32_le(&bigint_to_u32_limbs(q.clone(), T::N_BITS)) }
                for i in 0..lcs.len() {
                    { U::push_u32_le(&xs[i].to_u32_digits().1) }
                }
                for i in 0..lcs.len() {
                    { U::push_u32_le(&ys[i].to_u32_digits().1) }
                }
                { <Fq as Fp254Mul>::tmul() }
                { U::push_u32_le(&r.to_u32_digits().1) }
                { U::equal(0, 1) }
            };
            let res = execute_script(script);
            assert!(!res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
        }

        println!(
            "<Fq as Fp254Mul2LC>::tmul: {} @ {} stack",
            <Fq as Fp254Mul2LC>::tmul().len(),
            max_stack
        );
    }
}
