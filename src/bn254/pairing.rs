use crate::bn254::ell_coeffs::{EllCoeff, G2HomProjective, G2Prepared};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::treepp::*;
use ark_ec::bn::BnConfig;

pub struct Pairing;

impl Pairing {
    // input:
    //  f            12 elements
    //  coeffs.c0    2 elements
    //  coeffs.c1    2 elements
    //  coeffs.c2    2 elements
    //  p.x          1 element
    //  p.y          1 element
    //
    // output:
    //  new f        12 elements
    pub fn ell() -> Script {
        script! {
            // compute the new c0
            { Fq2::mul_by_fq(6, 0) }

            // compute the new c1
            { Fq2::mul_by_fq(5, 2) }

            // roll c2
            { Fq2::roll(4) }

            // compute the new f
            { Fq12::mul_by_034() }
        }
    }

    // input:
    //  f            12 elements
    //  p.x          1 element
    //  p.y          1 element
    //  c0, c1, c2
    pub fn ell_by_non_constant() -> Script {
        script! {
            // compute the new c0
            { Fq::copy(6) }
            { Fq::roll(6) }
            { Fq::mul() }
            { Fq::roll(6) }
            { Fq::roll(6) }
            { Fq::mul() }

            // compute the new c1
            { Fq::copy(6) }
            { Fq::roll(6) }
            { Fq::mul() }
            { Fq::roll(6) }
            { Fq::roll(6) }
            { Fq::mul() }

            // compute the new f
            // { Fq12::mul_by_034_with_4_constant(&constant.2) }
            { Fq12::mul_by_034() }
        }
    }

    // input:
    //  f            12 elements
    //  p.x          1 element
    //  p.y          1 element
    //
    // output:
    //  new f        12 elements
    pub fn ell_by_constant(constant: &EllCoeff) -> Script {
        script! {
            // compute the new c0
            { Fq::copy(0) }
            { Fq::mul_by_constant(&constant.0.c0) }
            { Fq::roll(1) }
            { Fq::mul_by_constant(&constant.0.c1) }

            // compute the new c1
            { Fq::copy(2) }
            { Fq::mul_by_constant(&constant.1.c0) }
            { Fq::roll(3) }
            { Fq::mul_by_constant(&constant.1.c1) }

            // compute the new f
            { Fq12::mul_by_034_with_4_constant(&constant.2) }
        }
    }

    // input:
    //   p.x
    //   p.y
    pub fn miller_loop(constant: &G2Prepared) -> Script {
        let mut script_bytes = vec![];

        script_bytes.extend(Fq12::push_one().as_bytes());

        let fq12_square = Fq12::square();

        let mut constant_iter = constant.ell_coeffs.iter();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }

            script_bytes.extend(Fq2::copy(12).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(12).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());
            }
        }

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_iter.next(), None);

        Script::from(script_bytes)
    }

    // input:
    //   p.x
    //   p.y
    //   q.x
    //   q.y
    pub fn dual_miller_loop(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut script_bytes = vec![];

        script_bytes.extend(Fq12::push_one().as_bytes());

        let fq12_square = Fq12::square();

        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();

        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                script_bytes.extend(fq12_square.as_bytes());
            }

            script_bytes.extend(Fq2::copy(14).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

            script_bytes.extend(Fq2::copy(12).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(14).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

                script_bytes.extend(Fq2::copy(12).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());
            }
        }

        script_bytes.extend(Fq2::copy(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
    }

    // input on stack (non-fixed) : [P1, P2, c, c_inv, wi]
    // input outside (fixed): L1(Q1), L2(Q2)
    pub fn dual_miller_loop_with_c_wi(constant_1: &G2Prepared, constant_2: &G2Prepared) -> Script {
        let mut script_bytes: Vec<u8> = vec![];

        // f = c_inv
        script_bytes.extend(
            script! {
                { Fq12::copy(12) }
            }
            .as_bytes(),
        );

        let fq12_square = Fq12::square();

        let mut constant_1_iter = constant_1.ell_coeffs.iter();
        let mut constant_2_iter = constant_2.ell_coeffs.iter();
        // miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // update f (double), f = f * f
            script_bytes.extend(fq12_square.as_bytes());

            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(24) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(36) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }

            // update f, f = f * double_line_eval
            script_bytes.extend(Fq2::copy(50).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

            script_bytes.extend(Fq2::copy(48).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                script_bytes.extend(Fq2::copy(50).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

                script_bytes.extend(Fq2::copy(48).as_bytes());
                script_bytes
                    .extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());
            }

            println!("Miller loop [{}]", i - 1);
        }

        // update c_inv
        // f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(24) }
                { Fq12::frobenius_map(1) }
                { Fq12::mul(12, 0) }
                { Fq12::roll(24) }
                { Fq12::frobenius_map(2) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // scale f
        // f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // update f (frobenius map): f = f * add_line_eval([p])
        script_bytes.extend(Fq2::copy(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::copy(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        // update f (frobenius map): f = f * add_line_eval([-p^2])
        script_bytes.extend(Fq2::roll(14).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_1_iter.next().unwrap()).as_bytes());

        script_bytes.extend(Fq2::roll(12).as_bytes());
        script_bytes.extend(Pairing::ell_by_constant(&constant_2_iter.next().unwrap()).as_bytes());

        assert_eq!(constant_1_iter.next(), None);
        assert_eq!(constant_2_iter.next(), None);

        Script::from(script_bytes)
    }

    // input on stack (non-fixed) : [1/2, B, P1, P2, P3, P4, Q4, c, c_inv, wi, T4]
    // [Fp, Fp2, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp, 2 * Fp2, Fp12, Fp12, Fp12, 3 * Fp2]
    // input outside stack (fixed): [L1, L2, L3]
    pub fn quad_miller_loop_with_c_wi(constants: &Vec<G2Prepared>) -> Script {
        let num_constant = constants.len();
        assert_eq!(num_constant, 3);
        let num_non_constant = 1;
        let num_pairs = 4;
        let mut script_bytes: Vec<u8> = vec![];

        // f = c_inv
        script_bytes.extend(
            script! {
                { Fq12::copy(12) }
            }
            .as_bytes(),
        );

        let fq12_square = Fq12::square();

        let mut constant_iters = constants
            .iter()
            .map(|item| item.ell_coeffs.iter())
            .collect::<Vec<_>>();

        // miller loop part, 6x + 2
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];

            // update f (double), f = f * f
            script_bytes.extend(fq12_square.as_bytes());

            // update c_inv
            // f = f * c_inv, if digit == 1
            // f = f * c, if digit == -1
            if bit == 1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(30) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            } else if bit == -1 {
                script_bytes.extend(
                    script! {
                        { Fq12::copy(42) }
                        { Fq12::mul(12, 0) }
                    }
                    .as_bytes(),
                );
            }

            ////////////////////////// accumulate double lines (fixed and non-fixed)
            // f = f^2 * double_line_Q(P)
            // fixed (constant part)
            for j in 0..num_constant {
                let offset = (4 * 12) as u32
                    + (num_non_constant * 3 * 2) as u32
                    + (num_non_constant * 2 * 2) as u32
                    + (num_pairs - 1 - j) as u32 * 2;
                script_bytes.extend(Fq2::copy(offset).as_bytes());
                script_bytes.extend(
                    Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                );
            }

            // non-fixed (non-constant part)
            let offset_P = (4 * 12) as u32
                + (num_non_constant * 3 * 2) as u32
                + (num_non_constant * 2 * 2) as u32;
            script_bytes.extend(Fq2::copy(offset_P).as_bytes());
            // roll T, and double line with T (projective coordinates)
            // ..., f, P, T
            let offset_T = 14 as u32;
            script_bytes.extend(Fq2::roll(offset_T).as_bytes());
            // ..., f, P, (,,) | T
            script_bytes.extend(G2HomProjective::double_line().as_bytes());
            script_bytes.extend(Fq6::toaltstack().as_bytes());
            // line evaluation and update f
            // ..., f | T
            script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
            // rollback T
            // ..., T, f
            script_bytes.extend(Fq6::fromaltstack().as_bytes());
            script_bytes.extend(Fq12::roll(6).as_bytes());

            // update f (add), f = f * add_line_eval
            if bit == 1 || bit == -1 {
                // f = f * add_line_Q(P)
                // fixed (constant part)
                for j in 0..num_constant {
                    let offset = (4 * 12) as u32
                        + (num_non_constant * 3 * 2) as u32
                        + (num_non_constant * 2 * 2) as u32
                        + (num_pairs - 1 - j) as u32 * 2;
                    script_bytes.extend(Fq2::copy(offset).as_bytes());
                    script_bytes.extend(
                        Pairing::ell_by_constant(&constant_iters[j].next().unwrap()).as_bytes(),
                    );
                }

                // non-fixed (non-constant part)
                let offset_P = (4 * 12) as u32
                    + (num_non_constant * 3 * 2) as u32
                    + (num_non_constant * 2 * 2) as u32;
                script_bytes.extend(Fq2::copy(offset_P).as_bytes());
                // roll T and copy Q, and add line with T and Q(projective coordinates)
                // ..., f, P, T
                let offset_T = 14 as u32;
                script_bytes.extend(Fq2::roll(offset_T).as_bytes());
                let offset_Q = (4 * 12 + num_non_constant * 3 * 2) as u32;
                script_bytes.extend(Fq2::copy(offset_Q).as_bytes());
                // ..., f, P, (,,) | T
                script_bytes.extend(G2HomProjective::add_line().as_bytes());
                script_bytes.extend(Fq6::toaltstack().as_bytes());
                // line evaluation and update f
                // ..., f | T
                script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
                // rollback T
                // ..., T, f
                script_bytes.extend(Fq6::fromaltstack().as_bytes());
                script_bytes.extend(Fq12::roll(6).as_bytes());
            }

            println!("Miller loop [{}]", i - 1);
        }

        // update c_inv
        // f = f * c_inv^p * c^{p^2}
        script_bytes.extend(
            script! {
                { Fq12::roll(30) }
                { Fq12::frobenius_map(1) }
                { Fq12::mul(12, 0) }
                { Fq12::roll(30) }
                { Fq12::frobenius_map(2) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // scale f
        // f = f * wi
        script_bytes.extend(
            script! {
                { Fq12::roll(18) }
                { Fq12::mul(12, 0) }
            }
            .as_bytes(),
        );

        // frobenius map on fixed and non-fixed lines

        // update f (frobenius map): f = f * add_line_eval([p])
        for i in 0..num_constant {
            let offset = (12
                + num_non_constant * 3 * 2
                + num_non_constant * 2 * 2
                + (num_pairs - 1 - i) * 2) as u32;
            script_bytes.extend(Fq2::copy(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[i].next().unwrap()).as_bytes());
        }

        // non-fixed
        // copy P, and T
        script_bytes.extend(Fq2::copy(22).as_bytes());
        script_bytes.extend(Fq6::copy(12).as_bytes());

        // phi(Q)
        // Qx.conjugate * beta^{2 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        script_bytes.extend(Fq2::copy(39).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // Qy.conjugate * beta^{3 * (p - 1) / 6}
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq::neg(0).as_bytes());
        script_bytes.extend(Fq2::copy(39).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());

        // add line with T and phi(Q)
        script_bytes.extend(G2HomProjective::add_line().as_bytes());
        script_bytes.extend(Fq6::toaltstack().as_bytes());

        // line evaluation and update f
        script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());
        script_bytes.extend(Fq6::fromaltstack().as_bytes());
        script_bytes.extend(Fq12::roll(6).as_bytes());

        for i in 0..num_constant {
            let offset = (12
                + num_non_constant * 3 * 2
                + num_non_constant * 2 * 2
                + (num_pairs - 1 - i) * 2) as u32;
            script_bytes.extend(Fq2::roll(offset).as_bytes());
            script_bytes
                .extend(Pairing::ell_by_constant(&constant_iters[i].next().unwrap()).as_bytes());
        }

        // non-fixed
        // copy P, and T
        script_bytes.extend(Fq2::roll(22).as_bytes());
        script_bytes.extend(Fq6::roll(12).as_bytes());

        // phi(Q)
        // Qx * beta^{2 * (p^2 - 1) / 6}
        script_bytes.extend(Fq2::roll(20).as_bytes());
        script_bytes.extend(Fq2::roll(33).as_bytes());
        script_bytes.extend(Fq2::mul(2, 0).as_bytes());
        // - Qy
        script_bytes.extend(Fq2::copy(20).as_bytes());
        script_bytes.extend(Fq2::neg(0).as_bytes());

        // add line with T and phi(Q)
        script_bytes.extend(G2HomProjective::add_line().as_bytes());
        script_bytes.extend(Fq6::drop().as_bytes());
        // line evaluation and update f
        script_bytes.extend(Pairing::ell_by_non_constant().as_bytes());

        for i in 0..num_constant {
            assert_eq!(constant_iters[i].next(), None);
        }

        Script::from(script_bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::pairing::Pairing;
    use crate::treepp::*;
    use ark_bn254::Bn254;
    use ark_ec::bn::{BnConfig, TwistType};
    use ark_ec::pairing::Pairing as _;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use num_traits::Num;
    use num_traits::One;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::str::FromStr;

    fn fq2_push(element: ark_bn254::Fq2) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(element.c0).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(element.c1).to_u32_digits()) }
        }
    }

    fn fq12_push(element: ark_bn254::Fq12) -> Script {
        script! {
            for elem in element.to_base_prime_field_elements() {
                { Fq::push_u32_le(&BigUint::from(elem).to_u32_digits()) }
           }
        }
    }

    #[test]
    fn test_ell() {
        println!("Pairing.ell: {} bytes", Pairing::ell().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let c0 = ark_bn254::Fq2::rand(&mut prng);
            let c1 = ark_bn254::Fq2::rand(&mut prng);
            let c2 = ark_bn254::Fq2::rand(&mut prng);
            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = c0.clone();
                c0new.mul_assign_by_fp(&py);

                let mut c1new = c1.clone();
                c1new.mul_assign_by_fp(&px);

                let mut b = a.clone();
                b.mul_by_034(&c0new, &c1new, &c2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { fq2_push(c0) }
                { fq2_push(c1) }
                { fq2_push(c2) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { Pairing::ell() }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_ell_by_constant() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let a = ark_bn254::Fq12::rand(&mut prng);
            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let coeffs = G2Prepared::from(b);

            let ell_by_constant = Pairing::ell_by_constant(&coeffs.ell_coeffs[0]);
            println!("Pairing.ell_by_constant: {} bytes", ell_by_constant.len());

            let px = ark_bn254::Fq::rand(&mut prng);
            let py = ark_bn254::Fq::rand(&mut prng);

            let b = {
                let mut c0new = coeffs.ell_coeffs[0].0.clone();
                c0new.mul_assign_by_fp(&py);

                let mut c1new = coeffs.ell_coeffs[0].1.clone();
                c1new.mul_assign_by_fp(&px);

                let mut b = a.clone();
                b.mul_by_034(&c0new, &c1new, &coeffs.ell_coeffs[0].2);
                b
            };

            let script = script! {
                { fq12_push(a) }
                { Fq::push_u32_le(&BigUint::from(px).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(py).to_u32_digits()) }
                { Pairing::ell_by_constant(&coeffs.ell_coeffs[0]) }
                { fq12_push(b) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let miller_loop = Pairing::miller_loop(&a_prepared);
            println!("Pairing.miller_loop: {} bytes", miller_loop.len());

            let c = Bn254::miller_loop(p, a).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let p = ark_bn254::G1Affine::rand(&mut prng);
            let q = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let b_prepared = G2Prepared::from(b);

            let dual_miller_loop = Pairing::dual_miller_loop(&a_prepared, &b_prepared);
            println!("Pairing.dual_miller_loop: {} bytes", dual_miller_loop.len());

            let c = Bn254::multi_miller_loop([p, q], [a, b]).0;

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { dual_miller_loop.clone() }
                { fq12_push(c) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_dual_millerloop_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            // exp = 6x + 2 + p - p^2 = lambda - p^3
            let p_pow3 = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
            let lambda = BigUint::from_str(
                "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
            ).unwrap();
            let (exp, sign) = if lambda > p_pow3 {
                (lambda - p_pow3, true)
            } else {
                (p_pow3 - lambda, false)
            };
            // random c and wi
            let c = ark_bn254::Fq12::rand(&mut prng);
            let c_inv = c.inverse().unwrap();
            let wi = ark_bn254::Fq12::rand(&mut prng);

            let p = ark_bn254::G1Affine::rand(&mut prng);
            let q = ark_bn254::G1Affine::rand(&mut prng);

            let a = ark_bn254::g2::G2Affine::rand(&mut prng);
            let a_prepared = G2Prepared::from(a);

            let b = ark_bn254::g2::G2Affine::rand(&mut prng);
            let b_prepared = G2Prepared::from(b);

            let dual_miller_loop_with_c_wi =
                Pairing::dual_miller_loop_with_c_wi(&a_prepared, &b_prepared);
            println!(
                "Pairing.dual_miller_loop_with_c_wi: {} bytes",
                dual_miller_loop_with_c_wi.len()
            );

            let f = Bn254::multi_miller_loop([p, q], [a, b]).0;
            println!("Bn254::multi_miller_loop done!");
            let hint = if sign {
                f * wi * (c_inv.pow(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
            };
            println!("Accumulated f done!");

            // p, q, c, c_inv, wi
            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }
                { dual_miller_loop_with_c_wi.clone() }
                { fq12_push(hint) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_quad_miller_loop_with_c_wi() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            // exp = 6x + 2 + p - p^2 = lambda - p^3
            let p_pow3 = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap().pow(3_u32);
            let lambda = BigUint::from_str(
                "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
            ).unwrap();
            let (exp, sign) = if lambda > p_pow3 {
                (lambda - p_pow3, true)
            } else {
                (p_pow3 - lambda, false)
            };
            // random c and wi
            let c = ark_bn254::Fq12::rand(&mut prng);
            let c_inv = c.inverse().unwrap();
            let wi = ark_bn254::Fq12::rand(&mut prng);

            let P1 = ark_bn254::G1Affine::rand(&mut prng);
            let P2 = ark_bn254::G1Affine::rand(&mut prng);
            let P3 = ark_bn254::G1Affine::rand(&mut prng);
            let P4 = ark_bn254::G1Affine::rand(&mut prng);

            let Q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
            let Q1_prepared = G2Prepared::from(Q1);
            let Q2_prepared = G2Prepared::from(Q2);
            let Q3_prepared = G2Prepared::from(Q3);

            let dual_miller_loop_with_c_wi = Pairing::quad_miller_loop_with_c_wi(
                &[Q1_prepared, Q2_prepared, Q3_prepared].to_vec(),
            );
            println!(
                "Pairing.dual_miller_loop_with_c_wi: {} bytes",
                dual_miller_loop_with_c_wi.len()
            );

            let f = Bn254::multi_miller_loop([P1, P2, P3, P4], [Q1, Q2, Q3, Q4]).0;
            println!("Bn254::multi_miller_loop done!");
            let hint = if sign {
                f * wi * (c_inv.pow(exp.to_u64_digits()))
            } else {
                f * wi * (c_inv.pow(exp.to_u64_digits()).inverse().unwrap())
            };
            println!("Accumulated f done!");

            // beta^{2 * (p - 1) / 6}, beta^{3 * (p - 1) / 6}, beta^{2 * (p^2 - 1) / 6}, 1/2, B / beta,
            // P1, P2, P3, P4, Q4, c, c_inv, wi
            let script = script! {
                { Fq::push_u32_le(&BigUint::from_str("21575463638280843010398324269430826099269044274347216827212613867836435027261").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("10307601595873709700152284273816112264069230130616436755625194854815875713954").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("2821565182194536844548159561693502659359617185244120367078079554186484126554").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("3505843767911556378687030309984248845540243509899259641013678093033130930403").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from_str("21888242871839275220042445260109153167277707414472061641714758635765020556616").unwrap().to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from_str("0").unwrap().to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::Fq::one().double().inverse().unwrap()).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(ark_bn254::g2::Config::COEFF_B.c1).to_u32_digits()) }

                { Fq::push_u32_le(&BigUint::from(P1.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P1.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P2.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P3.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(P4.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.x.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.x.c1).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.y.c0).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(Q4.y.c1).to_u32_digits()) }
                { fq12_push(c) }
                { fq12_push(c_inv) }
                { fq12_push(wi) }
                { dual_miller_loop_with_c_wi.clone() }
                { fq12_push(hint) }
                { Fq12::equalverify() }
                OP_TRUE
            };
            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}
