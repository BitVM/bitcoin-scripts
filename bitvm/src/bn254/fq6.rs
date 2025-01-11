use std::str::FromStr;

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::treepp::{script, Script};
use ark_ff::{Field, Fp6Config};
use num_bigint::BigUint;

use super::utils::Hint;

pub struct Fq6;

impl Fq6 {
    pub fn add(mut a: u32, mut b: u32) -> Script {
        if a < b {
            (a, b) = (b, a);
        }
        script! {
            { Fq2::add(a + 4, b + 4) }
            { Fq2::add(a + 2, b + 4) }
            { Fq2::add(a, b + 4) }
        }
    }

    pub fn sub(a: u32, b: u32) -> Script {
        if a > b {
            script! {
                { Fq2::sub(a + 4, b + 4) }
                { Fq2::sub(a + 2, b + 4) }
                { Fq2::sub(a, b + 4) }
            }
        } else {
            script! {
                { Fq2::sub(a + 4, b + 4) }
                { Fq2::sub(a + 4, b + 2) }
                { Fq2::sub(a + 4, b) }
            }
        }
    }

    pub fn double(a: u32) -> Script {
        script! {
            { Fq2::double(a + 4) }
            { Fq2::double(a + 4) }
            { Fq2::double(a + 4) }
        }
    }

    pub fn equalverify() -> Script {
        script! {
            for i in 0..6 {
                { Fq::equalverify(11 - i * 2, 5 - i) }
            }
        }
    }

    pub fn mul_fq2_by_nonresidue() -> Script {
        script! {
            { Fq2::copy(0) }
            { Fq2::double(0) }
            { Fq2::double(0) }
            { Fq2::double(0) }
            { Fq::copy(3) }
            { Fq::add(2, 0) }
            { Fq::copy(2) }
            { Fq::sub(1, 0) }
            { Fq::add(2, 1) }
            { Fq::add(2, 0) }
        }
    }

    pub fn hinted_mul_by_fp2_constant(a: ark_bn254::Fq6, constant: &ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(a.c0, constant);
        let (hinted_script2, hint2) = Fq2::hinted_mul_by_constant(a.c1, constant);
        let (hinted_script3, hint3) = Fq2::hinted_mul_by_constant(a.c2, constant);

        let mut script = script! {};
        let script_lines = [
            // compute p.c0 * c0
            Fq2::roll(4),
            hinted_script1,

            // compute p.c1 * c1
            Fq2::roll(4),
            hinted_script2,

            // compute p.c2 * c2
            Fq2::roll(4),
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

    pub fn push_zero() -> Script {
        script! {
            { Fq2::push_zero() }
            { Fq2::push_zero() }
            { Fq2::push_zero() }
        }
    }
    
    pub fn push(a: ark_bn254::Fq6) -> Script {
        script! {
            for elem in a.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    pub fn hinted_mul(mut a_depth: u32, mut a: ark_bn254::Fq6, mut b_depth: u32, mut b: ark_bn254::Fq6) -> (Script, Vec<Hint>) {
        // The degree-6 extension on BN254 Fq2 is under the polynomial y^3 - x - 9
        // Toom-Cook-3 from https://eprint.iacr.org/2006/471.pdf
        if a_depth < b_depth {
            (a_depth, b_depth) = (b_depth, a_depth);
            (a, b) = (b, a);
        }
        assert_ne!(a_depth, b_depth);
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq2::hinted_mul(2, a.c0, 0, b.c0);
        let (hinted_script2, hint2) = Fq2::hinted_mul(6, a.c0+a.c1+a.c2, 2, b.c0+b.c1+b.c2);
        let (hinted_script3, hint3) = Fq2::hinted_mul(4, a.c0-a.c1+a.c2, 2, b.c0-b.c1+b.c2);
        let (hinted_script4, hint4) = Fq2::hinted_mul(2, a.c0+a.c1+a.c1+a.c2+a.c2+a.c2+a.c2, 
                                                                                0, b.c0+b.c1+b.c1+b.c2+b.c2+b.c2+b.c2);
        let (hinted_script5, hint5) = Fq2::hinted_mul(2, a.c2, 0, b.c2);

        let mut script = script! {};
        let script_lines = [
            // compute ad = P(0)
            Fq2::copy(a_depth + 4),
            Fq2::copy(b_depth + 6),
            hinted_script1,

            // compute a+c
            Fq2::copy(a_depth + 6),
            Fq2::copy(a_depth + 4),
            Fq2::add(2, 0),

            // compute a+b+c, a-b+c
            Fq2::copy(0),
            Fq2::copy(a_depth + 8),
            Fq2::copy(0),
            Fq2::add(4, 0),
            Fq2::sub(4, 2),

            // compute d+f
            Fq2::copy(b_depth + 10),
            Fq2::copy(b_depth + 8),
            Fq2::add(2, 0),

            // compute d+e+f, d-e+f
            Fq2::copy(0),
            Fq2::copy(b_depth + 12),
            Fq2::copy(0),
            Fq2::add(4, 0),
            Fq2::sub(4, 2),

            // compute (a+b+c)(d+e+f) = P(1)
            hinted_script2,

            // compute (a-b+c)(d-e+f) = P(-1)
            hinted_script3,

            // compute 2b
            Fq2::roll(a_depth + 8),
            Fq2::double(0),

            // compute 4c
            Fq2::copy(a_depth + 8),
            Fq2::double(0),
            Fq2::double(0),

            // compute a+2b+4c
            Fq2::add(2, 0),
            Fq2::roll(a_depth + 10),
            Fq2::add(2, 0),

            // compute 2e
            Fq2::roll(b_depth + 10),
            Fq2::double(0),

            // compute 4f
            Fq2::copy(b_depth + 10),
            Fq2::double(0),
            Fq2::double(0),

            // compute d+2e+4f
            Fq2::add(2, 0),
            Fq2::roll(b_depth + 12),
            Fq2::add(2, 0),

            // compute (a+2b+4c)(d+2e+4f) = P(2)
            hinted_script4,

            // compute cf = P(inf)
            Fq2::roll(a_depth + 4),
            Fq2::roll(b_depth + 10),
            hinted_script5,

            // // at this point, we have v_0, v_1, v_2, v_3, v_4

            // compute 3v_0
            Fq2::triple(8),

            // compute 3v_1
            Fq2::triple(8),

            // compute 6v_4
            Fq2::triple(4),
            Fq2::double(0),

            // compute x = 3v_0 - 3v_1 - v_2 + v_3 - 12v_4
            Fq2::copy(4),
            Fq2::copy(4),
            Fq2::sub(2, 0),
            Fq2::copy(10),
            Fq2::sub(2, 0),
            Fq2::copy(8),
            Fq2::add(2, 0),
            Fq2::copy(2),
            Fq2::double(0),
            Fq2::sub(2, 0),

            // compute c_0 = 6v_0 + \beta x
            Fq6::mul_fq2_by_nonresidue(),
            Fq2::copy(6),
            Fq2::double(0),
            Fq2::add(2, 0),

            // compute y = -3v_0 + 6v_1 - 2v_2 - v_3 + 12v_4
            Fq2::copy(4),
            Fq2::double(0),
            Fq2::copy(8),
            Fq2::sub(2, 0),
            Fq2::copy(12),
            Fq2::double(0),
            Fq2::sub(2, 0),
            Fq2::roll(10),
            Fq2::sub(2, 0),
            Fq2::copy(4),
            Fq2::double(0),
            Fq2::add(2, 0),

            // compute c_1 = y + \beta 6v_4
            Fq2::copy(4),
            Fq6::mul_fq2_by_nonresidue(),
            Fq2::add(2, 0),

            // compute c_2 = 3v_1 - 6v_0 + 3v_2 - 6v_4
            Fq2::roll(6),
            Fq2::roll(8),
            Fq2::double(0),
            Fq2::sub(2, 0),
            Fq2::roll(8),
            Fq2::triple(0),
            Fq2::add(2, 0),
            Fq2::sub(0, 6),

            // divide by 6
            Fq2::roll(4),
            Fq2::div2(),
            Fq2::div3(),
            Fq2::roll(4),
            Fq2::div2(),
            Fq2::div3(),
            Fq2::roll(4),
            Fq2::div2(),
            Fq2::div3(),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
        hints.extend(hint4);
        hints.extend(hint5);

        (script, hints)
    }

    // input:
    //    p.c0   (2 elements)
    //    p.c1   (2 elements)
    //    p.c2   (2 elements)
    //    c0  (2 elements)
    //    c1  (2 elements)
    pub fn hinted_mul_by_01(p: ark_bn254::Fq6, c0: ark_bn254::Fq2, c1: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq2::hinted_mul(2, p.c0, 0, c0);
        let (hinted_script2, hint2) = Fq2::hinted_mul(2, p.c1, 0, c1);
        let (hinted_script3, hint3) = Fq2::hinted_mul(2, p.c1+p.c2, 0, c1);
        let (hinted_script4, hint4) = Fq2::hinted_mul(2, p.c0+p.c1, 0, c0+c1);
        let (hinted_script5, hint5) = Fq2::hinted_mul(10, c0, 0, p.c0+p.c2);

        let mut script = script! {};
        let script_lines = [
            // compute a_a = p.c0 * c0
            Fq2::copy(8),
            Fq2::copy(4),
            hinted_script1,

            // compute b_b = p.c1 * c1
            Fq2::copy(8),
            Fq2::copy(4),
            hinted_script2,

            // compute tmp = p.c1 + p.c2
            Fq2::copy(10),
            Fq2::copy(10),
            Fq2::add(2, 0),

            // t1 = c1 * tmp
            Fq2::copy(6),
            hinted_script3,

            // t1 = t1 - b_b
            Fq2::copy(2),
            Fq2::sub(2, 0),

            // t1 = t1 * nonresidue
            Fq6::mul_fq2_by_nonresidue(),

            // t1 = t1 + a_a
            Fq2::copy(4),
            Fq2::add(2, 0),

            // compute tmp = p.c0 + p.c1
            Fq2::copy(14),
            Fq2::roll(14),
            Fq2::add(2, 0),

            // t2 = c0 + c1
            Fq2::copy(10),
            Fq2::roll(10),
            Fq2::add(2, 0),

            // t2 = t2 * tmp
            hinted_script4,

            // t2 = t2 - a_a
            Fq2::copy(6),
            Fq2::sub(2, 0),

            // t2 = t2 - b_b
            Fq2::copy(4),
            Fq2::sub(2, 0),

            // compute tmp = p.c0 + p.c2
            Fq2::add(12, 10),

            // t3 = c0 * tmp
            hinted_script5,

            // t3 = t3 - a_a
            Fq2::sub(0, 8),

            // t3 = t3 + b_b
            Fq2::add(0, 6),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
        hints.extend(hint4);
        hints.extend(hint5);

        (script, hints)

    }

    /// Square the top Fq6 element
    /// CH-SQR3 from https://eprint.iacr.org/2006/471.pdf
    pub fn hinted_square(a: ark_bn254::Fq6) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hints1) = Fq2::hinted_square(a.c0);
        let (hinted_script2, hints2) = Fq2::hinted_square(a.c0 + a.c1 + a.c2);
        let (hinted_script3, hints3) = Fq2::hinted_square(a.c0 - a.c1 + a.c2);
        let (hinted_script4, hints4) = Fq2::hinted_mul(2, a.c1,0, a.c2);
        let (hinted_script5, hints5) = Fq2::hinted_square(a.c2);

        let mut script = script! {};
        let script_lines = [
            // compute s_0 = a_0 ^ 2
            Fq2::copy(4),
            hinted_script1,

            // compute a_0 + a_2
            Fq2::roll(6),
            Fq2::copy(4),
            Fq2::add(2, 0),

            // compute s_1 = (a_0 + a_1 + a_2) ^ 2
            Fq2::copy(0),
            Fq2::copy(8),
            Fq2::add(2, 0),
            hinted_script2,

            // compute s_2 = (a_0 - a_1 + a_2) ^ 2
            Fq2::copy(8),
            Fq2::sub(4, 0),
            hinted_script3,

            // compute s_3 = 2a_1a_2
            Fq2::roll(8),
            Fq2::copy(8),
            hinted_script4,
            Fq2::double(0),

            // compute s_4 = a_2 ^ 2
            Fq2::roll(8),
            hinted_script5,

            // compute t_1 = (s_1 + s_2) / 2
            Fq2::copy(6),
            Fq2::roll(6),
            Fq2::add(2, 0),
            Fq2::div2(),

            // at this point, we have s_0, s_1, s_3, s_4, t_1

            // compute c_0 = s_0 + \beta s_3
            Fq2::copy(4),
            Fq6::mul_fq2_by_nonresidue(),
            Fq2::copy(10),
            Fq2::add(2, 0),

            // compute c_1 = s_1 - s_3 - t_1 + \beta s_4
            Fq2::copy(4),
            Fq6::mul_fq2_by_nonresidue(),
            Fq2::copy(4),
            Fq2::add(10, 0),
            Fq2::sub(10, 0),
            Fq2::add(2, 0),

            // compute c_2 = t_1 - s_0 - s_4
            Fq2::add(8, 6),
            Fq2::sub(6, 0),
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hints1);
        hints.extend(hints2);
        hints.extend(hints3);
        hints.extend(hints4);
        hints.extend(hints5);
        
        (script, hints)
    }

    pub fn copy(a: u32) -> Script {
        script! {
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
            { Fq2::copy(a + 4) }
        }
    }

    pub fn roll(a: u32) -> Script {
        script! {
            { Fq2::roll(a + 4) }
            { Fq2::roll(a + 4) }
            { Fq2::roll(a + 4) }
        }
    }

    pub fn neg(a: u32) -> Script {
        script! {
            { Fq2::neg(a + 4) }
            { Fq2::neg(a + 4) }
            { Fq2::neg(a + 4) }
        }
    }

    pub fn aux_hints_for_fp6_inv(a: ark_bn254::Fq6) -> ark_bn254::Fq {
        let nine = ark_bn254::Fq::from_str("9").unwrap();
        let nonresidue: ark_bn254::Fq2 = ark_bn254::Fq2::new(nine, ark_bn254::Fq::ONE);
        
        let t0 = a.c0 * a.c0;
        let t1 = a.c1 * a.c1;
        let t2 = a.c2 * a.c2;

        let t3 = a.c0 * a.c1;
        let t4 = a.c0 * a.c2;
        let t5 = a.c1 * a.c2;

        let s0 = t0 - t5 * nonresidue;
        let s1 = t2 * nonresidue - t3;
        let s2 = t1 - t4;

        let a1 = a.c2 * s1;
        let a2 = a.c1 * s2;
        let a3 = (a1 + a2) * nonresidue;

        let t6 = a.c0 * s0 + a3;

        let t6aux = (t6.c0 * t6.c0 + t6.c1 *t6.c1).inverse().unwrap();

        t6aux
    }

    pub fn hinted_inv(a: ark_bn254::Fq6) -> (Script, Vec<Hint>) { 
        let nine = ark_bn254::Fq::from_str("9").unwrap();
        let nonresidue: ark_bn254::Fq2 = ark_bn254::Fq2::new(nine, ark_bn254::Fq::ONE);

        let t0 = a.c0 * a.c0;
        let t1 = a.c1 * a.c1;
        let t2 = a.c2 * a.c2;

        let t3 = a.c0 * a.c1;
        let t4 = a.c0 * a.c2;
        let t5 = a.c1 * a.c2;

        let s0 = t0 - t5 * nonresidue;
        let s1 = t2 * nonresidue - t3;
        let s2 = t1 - t4;

        let a1 = a.c2 * s1;
        let a2 = a.c1 * s2;
        let a3 = (a1 + a2) * nonresidue;

        let t6 = a.c0 * s0 + a3;
        let t6inv = t6.inverse().unwrap();

        let c0 = s0 * t6inv;
        let c1 = s1 * t6inv;
        let c2 = s2 * t6inv;
        assert_eq!(ark_bn254::Fq6::new(c0, c1, c2), a.inverse().unwrap());

        let (s_t0, h_t0) = Fq2::hinted_square(a.c0);
        let (s_t1, h_t1) = Fq2::hinted_square(a.c1);
        let (s_t2, h_t2) = Fq2::hinted_square(a.c2);
        let (s_t3, h_t3) = Fq2::hinted_mul(0, a.c1, 2, a.c0);
        let (s_t4, h_t4) = Fq2::hinted_mul(0, a.c2, 2, a.c0);
        let (s_t5, h_t5) = Fq2::hinted_mul(0, a.c2, 2, a.c1);

        let (s_a1, h_a1) = Fq2::hinted_mul(0, s1, 8, a.c2);
        let (s_a2, h_a2) = Fq2::hinted_mul(0, s2, 10, a.c1);
        
        let (s_t6, h_t6) = Fq2::hinted_mul(0, s0, 10, a.c0);
        let (s_t6inv, h_t6inv) = Fq2::hinted_inv(t6);

        let (s_c0, h_c0) = Fq2::hinted_mul(0, t6inv, 8, s0);
        let (s_c1, h_c1) = Fq2::hinted_mul(0, t6inv, 8, s1);
        let (s_c2, h_c2) = Fq2::hinted_mul(4, t6inv, 6, s2);

        let mut hints: Vec<Hint> = vec![];
        for hint in vec![h_t0, h_t1, h_t2, h_t3, h_t4, h_t5, h_a1, h_a2, h_t6, h_t6inv, h_c0, h_c1, h_c2] {
            hints.extend_from_slice(&hint);
        }

        let scr = script! {
            // [t6aux, a0, a1, a2]
            // compute t0 = c0^2, t1 = c1^2, t2 = c2^2
            { Fq2::copy(4) }
            { s_t0 }
            { Fq2::copy(4) }
            { s_t1 }
            { Fq2::copy(4) }
            { s_t2 }
             // [a0, a1, a2, t0, t1, t2, t3, t4,t5]

            // compute t3 = c0 * c1, t4 = c0 * c2, t5 = c1 * c2
            { Fq2::copy(10) }
            { Fq2::copy(10) }
            { s_t3 }
            { Fq2::copy(12) }
            { Fq2::copy(10) }
            { s_t4 }
            { Fq2::copy(12) }
            { Fq2::copy(12) }
            { s_t5 }

            // [a0, a1, a2, t0, t1, t2, t3, t4, t5]
            // update t5 = t5 * beta
            { Fq6::mul_fq2_by_nonresidue() }

            // compute s0 = t0 - t5
            { Fq2::sub(10, 0) }
            // [a0, a1, a2, t1, t2, t3, t4, s0]

            // compute s1 = t2 * beta - t3
            { Fq2::roll(6) }
            { Fq6::mul_fq2_by_nonresidue() }
            { Fq2::sub(0, 6) }
            // [a0, a1, a2, t1, t4, s0, s1]

            // compute s2 = t1 - t4
            { Fq2::sub(6, 4) }
            // [c0, c1, c2, s0, s1, s2]

            // compute a1 = c2 * s1
            { Fq2::copy(2) }
            { s_a1 }
            // [c0, c1, s0, s1, s2, a1]

            // compute a2 = c1 * s2
            { Fq2::copy(2) }
            { s_a2 }
            // [c0, s0, s1, s2, a1, a2]

            // compute a3 = beta * (a1 + a2)
            { Fq2::add(2, 0) }
            { Fq6::mul_fq2_by_nonresidue() }
            // [c0, s0, s1, s2, a3]

            // compute t6 = c0 * s0 + a3
            { Fq2::copy(6) }
            // [c0, s0, s1, s2, a3, s0]
            { s_t6 }
            { Fq2::add(2, 0) }
            // [t6aux, s0, s1, s2, t6]

            // inverse t6
            {Fq2::toaltstack()}
            {Fq::roll(6)}
            {Fq2::fromaltstack()}
            { s_t6inv }
            // [s0, s1, s2, t6]

            // compute final c0 = s0 * t6
            { Fq2::copy(0) }
            { s_c0 }
            // [s1, s2, t6, c0]

            // compute final c1 = s1 * t6
            { Fq2::copy(2) }
            { s_c1 }
            // [s2, t6, c0, c1]

            // compute final c2 = s2 * t6
            { s_c2 }
            // [c0, c1, c2]
        };
    
        return (scr, hints);
    }

    pub fn hinted_frobenius_map(i: usize, a: ark_bn254::Fq6) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Fq2::hinted_frobenius_map(i, a.c0);
        let (hinted_script2, hint2) = Fq2::hinted_frobenius_map(i, a.c1);
        let (hinted_script3, hint3) = Fq2::hinted_mul_by_constant(a.c1.frobenius_map(i), &ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1[i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1.len()]);
        let (hinted_script4, hint4) = Fq2::hinted_frobenius_map(i, a.c2);
        let (hinted_script5, hint5) = Fq2::hinted_mul_by_constant(a.c2.frobenius_map(i), &ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2[i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2.len()]);

        let mut script = script! {};
        let script_lines = [
            Fq2::roll(4),
            hinted_script1,
            Fq2::roll(4),
            hinted_script2,
            hinted_script3,
            Fq2::roll(4),
            hinted_script4,
            hinted_script5,
        ];
        for script_line in script_lines {
            script = script.push_script(script_line.compile());
        }

        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
        hints.extend(hint4);
        hints.extend(hint5);

        (script, hints)
    }

    pub fn toaltstack() -> Script {
        script! {
            { Fq2::toaltstack() }
            { Fq2::toaltstack() }
            { Fq2::toaltstack() }
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
            { Fq2::fromaltstack() }
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq2::drop() }
            { Fq2::drop() }
            { Fq2::drop() }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::bn254::fq6::Fq6;
    use crate::treepp::*;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use core::ops::Mul;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_bn254_fq6_add() {
        println!("Fq6.add: {} bytes", Fq6::add(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = a + b;

            let script = script! {
                { Fq6::push(a) }
                { Fq6::push(b) }
                { Fq6::add(6, 0) }
                { Fq6::push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq6_sub() {
        println!("Fq6.sub: {} bytes", Fq6::sub(6, 0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = a - b;

            let script = script! {
                { Fq6::push(a) }
                { Fq6::push(b) }
                { Fq6::sub(6, 0) }
                { Fq6::push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            run(script);

            let script = script! {
                { Fq6::push(b) }
                { Fq6::push(a) }
                { Fq6::sub(0, 6) }
                { Fq6::push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq6_double() {
        println!("Fq6.double: {} bytes", Fq6::double(0).len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..50 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c = a.double();

            let script = script! {
                { Fq6::push(a) }
                { Fq6::double(0) }
                { Fq6::push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_bn254_fq6_hinted_mul() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = ark_bn254::Fq6::rand(&mut prng);
            let c = a.mul(&b);

            let (hinted_mul, hints) = Fq6::hinted_mul(6, a, 0, b);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq6::push(a) }
                { Fq6::push(b) }
                { hinted_mul.clone() }
                { Fq6::push(c) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq6::hinted_mul: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_fq6_hinted_mul_by_01() {
        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..100 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let mut b = a;
            b.mul_by_01(&c0, &c1);

            let (hinted_mul, hints) = Fq6::hinted_mul_by_01(a, c0, c1);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq6::push(a) }
                { Fq2::push(c0) }
                { Fq2::push(c1) }
                { hinted_mul.clone() }
                { Fq6::push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let res = execute_script(script);
            assert!(res.success);

            max_stack = max_stack.max(res.stats.max_nb_stack_items);
            println!("Fq6::hinted_mul_by_01: {} @ {} stack", hinted_mul.len(), max_stack);
        }

    }

    #[test]
    fn test_bn254_fq6_hinted_inv() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = a.inverse().unwrap();
            let (_, hints) = Fq6::hinted_inv(a);
            let (scr, _) = Fq6::hinted_inv(ark_bn254::Fq6::ONE);
            let aux_t6 = Fq6::aux_hints_for_fp6_inv(a);
            let len = scr.len();
            
            let script = script! {
                for hint in hints {
                    {hint.push()}
                }
                { Fq::push(aux_t6) } // auxilary hint
                { Fq6::push(a) }
                { scr }
                { Fq6::push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };

            let res = execute_script(script);
            for i in 0..res.final_stack.len() {
                println!("{i:3}: {:?}", res.final_stack.get(i));
            }
            println!("fq6 inv len {} and stack {}", len, res.stats.max_nb_stack_items);
        }
    }

    #[test]
    fn test_bn254_fq6_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        for _ in 0..1 {
            let a = ark_bn254::Fq6::rand(&mut prng);
            let b = a.square();

            let (hinted_square, hints) = Fq6::hinted_square(a);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq6::push(a) }
                { hinted_square.clone() }
                { Fq6::push(b) }
                { Fq6::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);

            max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
            println!("Fq6::hinted_square: {} @ {} stack", hinted_square.len(), max_stack);
        }
    }

    #[test]
    fn test_bn254_fq6_hinted_frobenius_map() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            for i in 0..6 {
                let a = ark_bn254::Fq6::rand(&mut prng);
                let b = a.frobenius_map(i);

                let (hinted_frobenius_map, hints) = Fq6::hinted_frobenius_map(i, a);
                println!("Fq6.hinted_frobenius_map({}): {} bytes", i, hinted_frobenius_map.len());

                let script = script! {
                    for hint in hints { 
                        { hint.push() }
                    }
                    { Fq6::push(a) }
                    { hinted_frobenius_map.clone() }
                    { Fq6::push(b) }
                    { Fq6::equalverify() }
                    OP_TRUE
                };
                let exec_result = execute_script(script);
                assert!(exec_result.success);
            }
        }
    }
}
