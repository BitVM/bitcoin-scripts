use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use std::str::FromStr;
use crate::treepp::{script, Script};
use ark_ff::{Field, Fp12Config};
use num_bigint::BigUint;

use super::utils::Hint;

pub struct Fq12;

impl Fq12 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq6::add(a + 6, b + 6) }
            { Fq6::add(a, b + 6) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a, b + 6) }
            }
        } else {
            script! {
                { Fq6::sub(a + 6, b + 6) }
                { Fq6::sub(a + 6, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq6::double(a + 6) }
            { Fq6::double(a + 6) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..12 {
                { Fq::equalverify(23 - i * 2, 11 - i) }
            }
        }
    }

    pub fn mul_fq6_by_nonresidue() -> Script {
        script! {
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::roll(4) }
            { Fq2::roll(4) }
        }
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq6::push_zero() }
            { Fq6::push_zero() }
        }
    }
    
    pub fn push(a: ark_bn254::Fq12) -> Script {
        script! {
            for elem in a.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    pub fn hinted_mul(
        mut a_depth: u32,
        mut a: ark_bn254::Fq12,
        mut b_depth: u32,
        mut b: ark_bn254::Fq12,
    ) -> (Script, Vec<Hint>) {
        if a_depth < b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }
        assert_ne!(a_depth, b_depth);
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul(6, a.c0, 0, b.c0);
        let (hinted_script2, hint2) = Fq6::hinted_mul(6, a.c1, 0, b.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul(6, a.c0 + a.c1, 0, b.c0 + b.c1);

        let mut script = script! {};
        let script_lines = [
            Fq6::copy(a_depth + 6),
            Fq6::copy(b_depth + 12),
            hinted_script1,
            Fq6::copy(a_depth + 6),
            Fq6::copy(b_depth + 12),
            hinted_script2,
            Fq6::add(a_depth + 12, a_depth + 18),
            Fq6::add(b_depth + 18, b_depth + 24),
            hinted_script3,
            Fq6::copy(12),
            Fq6::copy(12),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::add(6, 0),
            Fq6::add(18, 12),
            Fq6::sub(12, 0),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    // input:
    //   p   (12 elements)
    //   c3  (2 elements)
    //   c4  (2 elements)
    // where c0 is a trival value ONE, so we can ignore it
    pub fn hinted_mul_by_34(
        p: ark_bn254::Fq12,
        c3: ark_bn254::Fq2,
        c4: ark_bn254::Fq2,
    ) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_mul_by_01(p.c1, c3, c4);
        let (hinted_script2, hint2) =
            Fq6::hinted_mul_by_01(p.c0 + p.c1, c3 + ark_bn254::Fq2::ONE, c4);

        let mut script = script! {};

        let script_lines = [
            // copy p.c1, c3, c4
            Fq6::copy(4),
            Fq2::copy(8),
            Fq2::copy(8),
            // [p, c3, c4, p.c1, c3, c4]

            // compute b = p.c1 * (c3, c4)
            hinted_script1,
            // [p, c3, c4, b]

            // a = p.c0 * c0, where c0 = 1
            Fq6::copy(16),
            // [p, c3, c4, b, a]

            // compute beta * b
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            // [p, c3, c4, b, a, beta * b]

            // compute final c0 = a + beta * b
            Fq6::copy(6),
            Fq6::add(6, 0),
            // [p, c3, c4, b, a, c0]

            // compute e = p.c0 + p.c1
            Fq6::add(28, 22),
            // [c3, c4, b, a, c0, e]

            // compute c0 + c3, where c0 = 1
            Fq2::roll(26),
            Fq2::push_one(),
            Fq2::add(2, 0),
            // [c4, b, a, c0, e, 1 + c3]

            // update e = e * (c0 + c3, c4), where c0 = 1
            Fq2::roll(26),
            hinted_script2,
            // [b, a, c0, e]

            // sum a and b
            Fq6::add(18, 12),
            // [c0, e, a + b]

            // compute final c1 = e - (a + b)
            Fq6::sub(6, 0),
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
            { Fq6::copy(a + 6) }
            { Fq6::copy(a + 6) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq6::roll(a + 6) }
            { Fq6::roll(a + 6) }
        }
    }

    pub fn hinted_square(a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hints1) = Fq6::hinted_mul(12, a.c1, 18, a.c0);
        let mut beta_ac1 = a.c1;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut beta_ac1);
        let (hinted_script2, hints2) = Fq6::hinted_mul(12, a.c0 + a.c1, 6, a.c0 + beta_ac1);

        let mut script = script! {};

        let script_lines = [
            // v0 = c0 + c1
            Fq6::copy(6),
            Fq6::copy(6),
            Fq6::add(6, 0),
            // v3 = c0 + beta * c1
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::copy(18),
            Fq6::add(0, 6),
            // v2 = c0 * c1
            hinted_script1,
            // v0 = v0 * v3
            hinted_script2,
            // final c0 = v0 - (beta + 1) * v2
            Fq6::copy(6),
            Fq12::mul_fq6_by_nonresidue(),
            Fq6::copy(12),
            Fq6::add(6, 0),
            Fq6::sub(6, 0),
            // final c1 = 2 * v2
            Fq6::double(6),
        ];

        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hints1);
        hints.extend(hints2);

        (script, hints)
    }

    pub fn cyclotomic_inverse() -> Script {
        script! {
            { Fq6::neg(0) }
        }
    }

    fn mul_fp6_by_nonresidue_in_place(fe: ark_bn254::Fq6) -> ark_bn254::Fq6 {
        let mut fe = fe.clone();
        let nine = ark_bn254::Fq::from_str("9").unwrap();
        let nonresidue: ark_bn254::Fq2 = ark_bn254::Fq2::new(nine, ark_bn254::Fq::ONE);
        let old_c1 = fe.c1;
        fe.c1 = fe.c0;
        fe.c0 = fe.c2 * nonresidue;
        fe.c2 = old_c1;
        fe
    }

    pub fn aux_hints_for_fp12_inv(a: ark_bn254::Fq12) -> ark_bn254::Fq {
        let t1 = a.c1 * a.c1;
        let t0 = a.c0 * a.c0;
        let yt1 = Self::mul_fp6_by_nonresidue_in_place(t1);
        let t0 = t0-yt1;
        let aux = Fq6::aux_hints_for_fp6_inv(t0);
        aux
    }

    fn hinted_inv0(a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {

        let (s_t1, h_t1) = Fq6::hinted_square(a.c1);
        let (s_t0, h_t0) = Fq6::hinted_square(a.c0);

        let mut hints: Vec<Hint> = vec![];
        for hint in vec![h_t1, h_t0] {
            hints.extend_from_slice(&hint);
        }

        let scr = script!{
            // compute beta * v1 = beta * c1^2
            { s_t1 }
            { Fq12::mul_fq6_by_nonresidue() }
            // [c0,, beta * c1^2]

            // copy c0
            { Fq6::roll(6) }

            // compute v0 = c0^2 + beta * v1
            { s_t0 }
            // [yt1, t0]
            { Fq6::sub(0, 6) }
            // [t0]
        };

        (scr, hints)
    }

    fn hinted_inv1(t0: ark_bn254::Fq6) -> (Script, Vec<Hint>) {
        let (scr, hts) = Fq6::hinted_inv(t0);
        (scr, hts)
    }

    fn hinted_inv2(a: ark_bn254::Fq12, t1: ark_bn254::Fq6) -> (Script, Vec<Hint>) {
        let (s_c0, ht1) = Fq6::hinted_mul(0, t1, 18, a.c0);
        let (s_c1, ht2) = Fq6::hinted_mul(0, -a.c1, 12, t1);

        let mut hints: Vec<Hint> = vec![];
        for hint in vec![ht1, ht2] {
            hints.extend_from_slice(&hint);
        }

        let scr = script!{
            // dup inv v0
            { Fq6::copy(0) }
            // [c0, c1, t1, t1]

            // compute c0
            { s_c0 }
            // [c1, t1, d0]

            // compute c1
            { Fq6::neg(12) }
            // [t1, d0, -c1]
            { s_c1 }
            // [c0, c1, t1, d0, d1]
        };
        (scr, hints)
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq12) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq6::hinted_frobenius_map(i, a.c0);
        let (hinted_script2, hint2) = Fq6::hinted_frobenius_map(i, a.c1);
        let (hinted_script3, hint3) = Fq6::hinted_mul_by_fp2_constant(
            a.c1.frobenius_map(i),
            &ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1
                [i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()],
        );

        let mut script = script! {};
        let script_lines = [
            Fq6::roll(6),
            hinted_script1,
            Fq6::roll(6),
            hinted_script2,
            hinted_script3,
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
            { Fq6::toaltstack() }
            { Fq6::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq6::fromaltstack() }
            { Fq6::fromaltstack() }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq6::drop() }
            { Fq6::drop() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fq6::Fq6;
    use crate::{execute_script_without_stack_limit, treepp::*};
    use ark_ff::AdditiveGroup;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_bn254_fq12_add() {
        println!("Fq12.add: {} bytes", Fq12::add(12, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a + b;

            let script = script! {
                { Fq12::push(a) }
                { Fq12::push(b) }
                { Fq12::add(12, 0) }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_double() {
        println!("Fq12.double: {} bytes", Fq12::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fq12::push(a) }
                { Fq12::double(0) }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::Fq12::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq12::hinted_mul(12, a, 0, b);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { Fq12::push(b) }
                { hinted_mul.clone() }
                { Fq12::push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let res = execute_script_without_stack_limit(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq12::window_mul: {} @ {} stack",
                hinted_mul.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_mul_by_34() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::ONE;
            let c3 = ark_bn254::Fq2::rand(&mut prng);
            let c4 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_034(&c0, &c3, &c4);
            let (hinted_mul, hints) = Fq12::hinted_mul_by_34(a, c3, c4);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { Fq2::push(c3) }
                { Fq2::push(c4) }
                { hinted_mul.clone() }
                { Fq12::push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!(
                "Fq6::window_mul: {} @ {} stack",
                hinted_mul.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq12::hinted_square(a);

            let script = script! {
                for hint in hints {
                    { hint.push() }
                }
                { Fq12::push(a) }
                { hinted_square.clone() }
                { Fq12::push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!(
                "Fq12::hinted_square: {} @ {} stack",
                hinted_square.len(),
                max_stack
            );
        }
    }

    #[test]
    fn test_bn254_fq12_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::fq12::Fq12::rand(&mut prng);

        fn output_of_tap_inv0(
            a: ark_bn254::Fq12
        ) -> ark_bn254::Fq6 {
            let t1 = a.c1 * a.c1;
            let t0 = a.c0 * a.c0;
            let yt1 = Fq12::mul_fp6_by_nonresidue_in_place(t1);
            let t0 = t0-yt1;     
            t0
        }

        let t0 = output_of_tap_inv0(a);
        let chunk = Fq12::hinted_inv0(a);
        let scr = script!{
            for hints in &chunk.1 {
                {hints.push()}
            }
            {Fq12::push(a)}
            {chunk.0.clone()}
            {Fq6::push(t0)}
            {Fq6::equalverify()}
            OP_TRUE
        };
        let res = execute_script(scr);
        assert!(res.success);
        println!("Chunk 0; Fp12 Inv script len {} and max stack size {}", chunk.0.len(), res.stats.max_nb_stack_items, );

        let chunk = Fq12::hinted_inv1(t0);
        let t1 = t0.inverse().unwrap();
        let aux =  Fq6::aux_hints_for_fp6_inv(t0);
        let scr = script!{
            for hints in &chunk.1 {
                {hints.push()}
            }
            {Fq::push(aux)}
            {Fq6::push(t0)}
            {chunk.0.clone()}
            {Fq6::push(t1)}
            {Fq6::equalverify()}
            OP_TRUE
        };
        let res = execute_script(scr);
        assert!(res.success);
        println!("Chunk 1; Fp12 Inv script len {} and max stack size {}", chunk.0.len(), res.stats.max_nb_stack_items, );

        let chunk = Fq12::hinted_inv2(a, t1);
        let ainv = a.inverse().unwrap();
        let scr = script!{
            for hints in &chunk.1 {
                {hints.push()}
            }
            {Fq12::push(a)}
            {Fq6::push(t1)}
            {chunk.0.clone()}
            {Fq12::push(ainv)}
            {Fq12::equalverify()}
            OP_TRUE
        };
        let res = execute_script(scr);
        assert!(res.success);
        println!("Chunk 2; Fp12 Inv script len {} and max stack size {}", chunk.0.len(), res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_bn254_fq12_hinted_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..12 {
                let a = ark_bn254::Fq12::rand(&mut prng);
                let b = a.frobenius_map(i);

                let (hinted_frobenius_map, hints) = Fq12::hinted_frobenius_map(i, a);
                println!(
                    "Fq12.hinted_frobenius_map({}): {} bytes",
                    i,
                    hinted_frobenius_map.len()
                );

                let script = script! {
                    for hint in hints {
                        { hint.push() }
                    }
                    { Fq12::push(a) }
                    { hinted_frobenius_map.clone() }
                    { Fq12::push(b) }
                    { Fq12::equalverify() }
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }
}
