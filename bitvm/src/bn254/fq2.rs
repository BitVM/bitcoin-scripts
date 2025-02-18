use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::treepp::{script, Script};
use crate::bn254::utils::Hint;
use ark_ff::Fp2Config;
use num_bigint::BigUint;

pub struct Fq2;

impl Fq2 {
    pub fn copy(a: u32) -> Script {
        script! {
            { Fq::copy(a + 1) }
            { Fq::copy(a + 1) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq::roll(a + 1) }
            { Fq::roll(a + 1) }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq::drop() }
            { Fq::drop() }
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq::toaltstack() }
            { Fq::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq::fromaltstack() }
            { Fq::fromaltstack() }
        }
    }

    pub fn push(a: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(a.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(a.c1).to_u32_digits()) }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn push_one() -> Script {
        script! {
            { Fq::push_one() }
            { Fq::push_zero() }
        }
    }

    pub fn read_from_stack(witness: Vec<Vec<u8>>) -> ark_bn254::Fq2 {
        assert_eq!(witness.len() as u32, Fq::N_LIMBS * 2);
        let c0 = Fq::read_u32_le(witness[0..Fq::N_LIMBS as usize].to_vec());
        let c1 = Fq::read_u32_le(
            witness[Fq::N_LIMBS as usize..2 * Fq::N_LIMBS as usize].to_vec(),
        );
        ark_bn254::Fq2 {
            c0: BigUint::from_slice(&c0).into(),
            c1: BigUint::from_slice(&c1).into(),
        }
    }

    pub fn equalverify() -> Script {
        script! {
            { Fq::equalverify(3, 1) }
            { Fq::equalverify(1, 0) }
        }
    }

    pub fn equal() -> Script {
        script! {
            { Fq::equal(3, 1) }
            OP_TOALTSTACK
            { Fq::equal(1, 0) }
            OP_FROMALTSTACK
            OP_BOOLAND
        }
    }
    
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }

        script! {
            { Fq::add(a + 1, b + 1) }
            { Fq::add(a, b + 1) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq::sub(a + 1, b + 1) }
                { Fq::sub(a, b + 1) }
            }
        } else {
            script! {
                { Fq::sub(a + 1, b + 1) }
                { Fq::sub(a + 1, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq::double(a + 1) }
            { Fq::double(a + 1) }
        }
    }

    pub fn triple(a: u32) -> Script {
        script! {
            { Fq2::copy(a) }
            { Fq2::double(a + 2) }
            { Fq2::add(2, 0) }
        }
    }

    pub fn div2() -> Script {
        script! {
            { Fq::roll(1) }
            { Fq::div2() }
            { Fq::roll(1) }
            { Fq::div2() }
        }
    }

    pub fn div3() -> Script {
        script! {
            { Fq::roll(1) }
            { Fq::div3() }
            { Fq::roll(1) }
            { Fq::div3() }
        }
    }

    pub fn neg(a: u32) -> Script {
        script! {
            { Fq::neg(a + 1) }
            { Fq::neg(a + 1) }
        }
    }

    pub fn hinted_mul(mut a_depth: u32, mut a: ark_bn254::Fq2, mut b_depth: u32, mut b: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        if a_depth < b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }
        assert_ne!(a_depth, b_depth);

        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq::hinted_mul_lc2_keep_elements(3, a.c0, 2, a.c1, 1, b.c1, 0, b.c0);
        let (hinted_script2, hint2) = Fq::hinted_mul_lc2(3, a.c0, 2, a.c1, 1, b.c0, 0, -b.c1);

        let script = script! {
            { Fq2::roll(a_depth) }
            { Fq2::roll(b_depth + 2) }                       // a.c0 a.c1 b.c0 b.c1
            { Fq::roll(1) }                                  // a.c0 a.c1 b.c1 b.c0
            { hinted_script1 }                               // a.c0 a.c1 b.c1 b.c0 a.c0*b.c1+a.c1*b.c0
            { Fq::toaltstack() }                             // a.c0 a.c1 b.c1 b.c0 | a.c0*b.c1+a.c1*b.c0
            { Fq::roll(1) }                                  // a.c0 a.c1 b.c0 b.c1 | a.c0*b.c1+a.c1*b.c0
            { Fq::neg(0) }                                   // a.c0 a.c1 b.c0 -b.c1 | a.c0*b.c1+a.c1*b.c0
            { hinted_script2 }                               // a.c0*b.c0-a.c1*b.c1 | a.c0*b.c1+a.c1*b.c0
            { Fq::fromaltstack() }                           // a.c0*b.c0-a.c1*b.c1 a.c0*b.c1+a.c1*b.c0
        };

        hints.extend(hint1);
        hints.extend(hint2);

        (script, hints)
    }

    pub fn hinted_mul_by_constant(a: ark_bn254::Fq2, constant: &ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq::hinted_mul_by_constant(a.c0, &constant.c0);
        let (hinted_script2, hint2) = Fq::hinted_mul_by_constant(a.c1, &constant.c1);
        let (hinted_script3, hint3) = Fq::hinted_mul_by_constant(a.c0+a.c1, &(constant.c0+constant.c1));

        let script = script! {
            { Fq::copy(1) }
            { hinted_script1 }
            { Fq::copy(1) }
            { hinted_script2 }
            { Fq::add(3, 2) }
            { hinted_script3 }
            { Fq::copy(2) }
            { Fq::copy(2) }
            { Fq::add(1, 0) }
            { Fq::sub(1, 0) }
            { Fq::sub(2, 1) }
            { Fq::roll(1) }
        };

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    pub fn hinted_mul_lc4_keep_elements(
        a: ark_bn254::Fq2, b:ark_bn254::Fq2, c:ark_bn254::Fq2, d:ark_bn254::Fq2
    ) -> (Script, Vec<Hint>) {

        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq::hinted_mul_lc4(7, a.c0, 6, -a.c1, 5, c.c0, 4, -c.c1, 3, b.c0, 2, b.c1, 1, d.c0, 0, d.c1);
        let (hinted_script2, hint2) = Fq::hinted_mul_lc4(7, a.c0, 6, a.c1, 5, c.c0, 4, c.c1, 3, b.c1, 2, b.c0, 1, d.c1, 0, d.c0);

        let script = script! {
            // [a, b, c, d] 
            {Fq2::copy(6)}
            {Fq::neg(0)}
            // [a, b, c, d, -a]
            {Fq2::copy(4)}
            {Fq::neg(0)}
            // [a, b, c, d, -a, -c]
            {Fq2::copy(8)}
            // [a, b, c, d, -a, -c, b]
            {Fq2::copy(6)}
            // [a, b, c, d, -a, -c, b, d]
            {hinted_script1}
            {Fq::toaltstack()}
            // [a, b, c, d]
            {Fq2::copy(6)} {Fq2::copy(6)} {Fq2::copy(6)} {Fq2::copy(6)} 
            // [a, b, c, d, a, b, c, d]
            {Fq2::toaltstack()} {Fq2::roll(2)} 
            // [a, c, b, d]
            {Fq::roll(1)}
            {Fq2::fromaltstack()}
            {Fq::roll(1)}
            // [a, c, b', d']
            {hinted_script2}
            {Fq::fromaltstack()}
            {Fq::roll(1)}
        };

        hints.extend(hint1);
        hints.extend(hint2);

        (script, hints)
    }

    
    /// Square the top Fq2 element
    pub fn hinted_square(a: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let (hinted_script1, hint1) = Fq::hinted_mul_keep_element(1, a.c0, 0, a.c1);
        let (hinted_script2, hint2) = Fq::hinted_mul(1, a.c0 - a.c1, 0, a.c0 + a.c1);

        let script = script! {
            // a0, a1
            { Fq::copy(1) }
            { Fq::copy(1) }
            // a0, a1, a0, a1
            { hinted_script1 }
            // a0, a1, a0, a1, a0*a1
            { Fq::double(0) }
            // a0, a1, a0, a1, 2*a0*a1
            { Fq::sub(2, 1) }
            { Fq::add(3, 2) }
            // 2*a0*a1, a0-a1, a0+a1
            { hinted_script2 }
            // 2*a0*a1, a0^2-a1^2
            { Fq::roll(1) }
            // a0^2-a1^2, 2*a0*a1
        };

        hints.extend(hint1);
        hints.extend(hint2);
        (script, hints)
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        Fq::hinted_mul_by_constant(a.c1, &ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1[i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()])
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq2::Fq2;
    use crate::treepp::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::{Add, Mul};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_bn254_fq2_add() {
        println!("Fq2.add: {} bytes", Fq2::add(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a + b;

            let script = script! {
                { Fq2::push(a) }
                { Fq2::push(b) }
                { Fq2::add(2, 0) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);

            let script = script! {
                { Fq2::push(a) }
                { Fq2::push(b) }
                { Fq2::add(0, 2) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_sub() {
        println!("Fq2.sub: {} bytes", Fq2::sub(2, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a - b;

            let script = script! {
                { Fq2::push(a) }
                { Fq2::push(b) }
                { Fq2::sub(2, 0) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);

            let script = script! {
                { Fq2::push(b) }
                { Fq2::push(a) }
                { Fq2::sub(0, 2) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_double() {
        println!("Fq2.double: {} bytes", Fq2::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fq2::push(a) }
                { Fq2::double(0) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_triple() {
        println!("Fq2.triple: {} bytes", Fq2::triple(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();
            let c = a.add(b);

            let script = script! {
                { Fq2::push(a) }
                { Fq2::triple(0) }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_div2() {
        println!("Fq2.div2: {} bytes", Fq2::div2().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();

            let script = script! {
                { Fq2::push(b) }
                { Fq2::div2() }
                { Fq2::push(a) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_div3() {
        println!("Fq2.div3: {} bytes", Fq2::div3().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.double();
            let c = a.add(b);

            let script = script! {
                { Fq2::push(c) }
                { Fq2::div3() }
                { Fq2::push(a) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq2_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq2::hinted_mul(2, a, 0, b);
            println!("Fq2::hinted_mul: {} bytes", hinted_mul.len());

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { Fq2::push(b) }
                { hinted_mul.clone() }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }

    }

    #[test]
    fn test_bn254_fq2_hinted_mul_by_constant() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul_by_constant, hints) = Fq2::hinted_mul_by_constant(a, &b);
            println!("Fq2::hinted_mul_by_constant: {} bytes", hinted_mul_by_constant.len());

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { hinted_mul_by_constant.clone() }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }

    }

    #[test]
    fn test_bn254_fq2_hinted_square() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&a);

            let (hinted_square, hints) = Fq2::hinted_square(a);
            println!("Fq2::hinted_square: {} bytes", hinted_square.len());

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { hinted_square.clone() }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }

    }

    #[test]
    fn test_bn254_fq2_hinted_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = a.frobenius_map(0);

            let (hinted_frobenius_map_0, hints) = Fq2::hinted_frobenius_map(0, a);
            println!("Fq2.hinted_frobenius_map(0): {} bytes", hinted_frobenius_map_0.len());

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { hinted_frobenius_map_0 }
                { Fq2::push(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);

            let b = a.frobenius_map(1);

            let (hinted_frobenius_map_1, hints) = Fq2::hinted_frobenius_map(1, a);
            println!("Fq2.hinted_frobenius_map(1): {} bytes", hinted_frobenius_map_1.len());

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { hinted_frobenius_map_1 }
                { Fq2::push(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }
}
