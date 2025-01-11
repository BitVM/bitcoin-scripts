use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::utils::Hint;
use crate::treepp::{script, Script};
use ark_ff::{Field, Fp2Config};
use num_bigint::BigUint;

pub struct Fq2;

impl Fq2 {
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

    /// Square the top Fq2 element
    pub fn hinted_square(a: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let (hinted_script1, hint1) = Fq::hinted_mul_keep_element(1, a.c0, 0, a.c1);
        let (hinted_script2, hint2) = Fq::hinted_mul(1, a.c0 - a.c1, 0, a.c0 + a.c1);

        let mut script = script! {};
        let script_lines = [
            // a0, a1
            Fq::copy(1),
            Fq::copy(1),
            // a0, a1, a0, a1
            hinted_script1,
            // a0, a1, a0, a1, a0*a1
            Fq::double(0),
            // a0, a1, a0, a1, 2*a0*a1
            Fq::sub(2, 1),
            Fq::add(3, 2),
            // 2*a0*a1, a0-a1, a0+a1
            hinted_script2,
            // 2*a0*a1, a0^2-a1^2
            Fq::roll(1),
            // a0^2-a1^2, 2*a0*a1
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        (script, hints)
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq::copy(a + 1) }
            { Fq::copy(a + 1) }
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
    pub fn roll(a: u32) -> Script {
        script! {
            { Fq::roll(a + 1) }
            { Fq::roll(a + 1) }
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

    pub fn push_one() -> Script {
        script! {
            { Fq::push_one() }
            { Fq::push_zero() }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }
    
    pub fn push(a: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(a.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(a.c1).to_u32_digits()) }
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

    pub fn neg(a: u32) -> Script {
        script! {
            { Fq::neg(a + 1) }
            { Fq::neg(a + 1) }
        }
    }

    pub fn hinted_inv(a: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let (a0_sq, a0_sq_hint) = Fq::hinted_square(a.c0);
        let (a1_sq, a1_sq_hint) = Fq::hinted_square(a.c1);
        let t0 = a.c0 * a.c0 + a.c1 * a.c1;
        let t1 = t0.inverse().unwrap();
        let (idmul, idmul_hint) = Fq::hinted_mul(0, t1, 1, t0);
        let (t1a0, t1a0_hint) = Fq::hinted_mul(0, a.c0, 1, t1);
        let (t1a1, t1a1_hint) = Fq::hinted_mul(0, t1, 1, a.c1);
        // [t0inv, a0, a1]
        let scr = script! {
            // copy c1
            { Fq::copy(0) }

            // compute v1 = c1^2
            { a1_sq }
            // [t0inv, a0, a1, a1_sq]
            // copy c0
            { Fq::copy(2) }

            // compute v0 = c0^2 + v1
            { a0_sq }
            // [t0inv, a0, a1, a1_sq, a0_sq]
            { Fq::add(1, 0) } // t0 = a0^2 + a1^2
            // [t0inv, a0, a1, t0]
            {Fq::copy(3)}
            // [t0inv, a0, a1, t0, t0inv]
            // compute inv v0
            { idmul} // t1 <- t0.inv
            { Fq::push(ark_bn254::Fq::ONE)}
            { Fq::equalverify(1, 0)}
            {Fq::roll(2)}
            // [a0, a1, t1]
            // dup inv v0 // c0 <- a0. t1
            { Fq::copy(0) }
            // [a0, a1, t1, t1]

            // compute c0
            { Fq::roll(3) }
            // [a1, t1, t1, a0]
            { t1a0 }
            // [a1, t1, a0.t1]
            // compute c1 // c1<-[-a1, t1]
            { Fq::roll(2) }
            { Fq::roll(2) }
            // [a0.t1, a1, t1]
            { t1a1 }
            { Fq::neg(0) }
            //[a0.t1, -a1.t1]
        };

        let mut all_hints = vec![];
        for h in [a1_sq_hint, a0_sq_hint, idmul_hint, t1a0_hint, t1a1_hint].iter() {
            all_hints.extend_from_slice(h);
        }
        return (scr, all_hints);
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

    pub fn triple(a: u32) -> Script {
        script! {
            { Fq2::copy(a) }
            { Fq2::double(a + 2) }
            { Fq2::add(2, 0) }
        }
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        Fq::hinted_mul_by_constant(a.c1, &ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1[i % ark_bn254::Fq2Config::FROBENIUS_COEFF_FP2_C1.len()])
    }

    pub fn hinted_mul_by_constant(a: ark_bn254::Fq2, constant: &ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq::hinted_mul_by_constant(a.c0, &constant.c0);
        let (hinted_script2, hint2) = Fq::hinted_mul_by_constant(a.c1, &constant.c1);
        let (hinted_script3, hint3) = Fq::hinted_mul_by_constant(a.c0+a.c1, &(constant.c0+constant.c1));

        let mut script = script! {};
        let script_lines = [
            Fq::copy(1),
            hinted_script1,
            Fq::copy(1),
            hinted_script2,
            Fq::add(3, 2),
            hinted_script3,
            Fq::copy(2),
            Fq::copy(2),
            Fq::add(1, 0),
            Fq::sub(1, 0),
            Fq::sub(2, 1),
            Fq::roll(1),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
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

    pub fn drop() -> Script {
        script! {
            { Fq::drop() }
            { Fq::drop() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
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
    fn test_bn254_fq2_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq2::hinted_mul(2, a, 0, b);

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
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq2::hinted_mul: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_fq2_hinted_mul_by_constant() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let b = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq2::hinted_mul_by_constant(a, &b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(a) }
                { hinted_mul.clone() }
                { Fq2::push(c) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq2::hinted_mul_by_constant: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_hinted_fq2_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);


            let a = ark_bn254::Fq2::rand(&mut prng);
            assert_ne!(a, ark_bn254::Fq2::ZERO);

            let b = a.inverse().unwrap();

            let (invs, hints) = Fq2::hinted_inv(a);
            let t0 = a.c0 * a.c0 + a.c1 * a.c1;
            // if a is not zero, t0 is never zero
            let t1 = t0.inverse().unwrap();

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq::push(t1)}
                { Fq2::push(a) }
                { invs }
                { Fq2::push(b) }
                { Fq2::equalverify() }
                OP_TRUE
            };
            let len = script.len();
            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("fq2 inv len {}", len);
    }

    #[test]
    fn test_bn254_fq2_hinted_square() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq2::rand(&mut prng);
            let c = a.mul(&a);

            let (hinted_square, hints) = Fq2::hinted_square(a);

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
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq2::hinted_square: {} @ {} stack", hinted_square.len(), max_stack);
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
            let exec_result = execute_script(script);
            assert!(exec_result.success);

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
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
