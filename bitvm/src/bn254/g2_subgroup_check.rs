use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use std::ops::{Add, Div, Mul, Sub};

use crate::bn254::fq2::Fq2;
use crate::treepp::*;
use bitcoin::ScriptBuf;

#[derive(Debug, Default, Clone)]
pub struct ScriptContext<F: ark_ff::Field> {
    pub inputs: Vec<F>,
    pub outputs: Vec<F>,
    pub montgomery_form: bool,
    pub auxiliary: Vec<usize>,
    pub auxiliary_output: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct SplitScript {
    pub script: ScriptBuf,
    pub input_len: u32,
    pub output_len: u32,
}

pub struct PairingNative;

impl PairingNative {
    // Reference: https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/curves/g2.rs#L59
    // https://github.com/BitVM/BitVM/issues/109
    pub fn witness_g2_subgroup_check(
        point: &ark_bn254::g2::G2Affine,
        constants: [ark_bn254::Fq2; 2],
        scalar_bit: Vec<bool>,
    ) -> (bool, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let mut script_contexts = vec![];

        let mut script_context = ScriptContext::default();

        // Maps (x,y) -> (x^p * (u+9)^((p-1)/3), y^p * (u+9)^((p-1)/2))
        script_context
            .inputs
            .push(point.clone().x().unwrap().to_owned());
        script_context
            .inputs
            .push(point.clone().y().unwrap().to_owned());

        let mut p_times_point = *point;
        p_times_point.x.frobenius_map_in_place(1);
        p_times_point.y.frobenius_map_in_place(1);

        p_times_point.x *= constants[0];
        p_times_point.y *= constants[1];

        script_context
            .outputs
            .push(p_times_point.clone().x().unwrap().to_owned());
        script_context
            .outputs
            .push(p_times_point.clone().y().unwrap().to_owned());

        script_contexts.push(script_context);

        let (x_times_point, witness) = Self::witness_split_scalar_mul_g2(point, &scalar_bit);

        assert_eq!(p_times_point, x_times_point);

        script_contexts.extend(witness);

        (true, script_contexts)
    }
    pub fn witness_split_scalar_mul_g2(
        base: &ark_bn254::G2Affine,
        scalar: &[bool],
    ) -> (ark_bn254::G2Affine, Vec<ScriptContext<ark_bn254::Fq2>>) {
        let res = base.to_owned();
        let mut tmp = base.to_owned();

        let mut script_contexts = vec![];

        for b in scalar.iter().skip(1) {
            let (lambda, miu, res_x, res_y) = PairingNative::line_double_g2(&tmp);

            let mut script_context = ScriptContext::default();

            script_context.inputs.push(lambda);
            script_context.inputs.push(miu);
            script_context.inputs.push(tmp.x().unwrap().to_owned());
            script_context.inputs.push(tmp.y().unwrap().to_owned());
            script_context.outputs.push(res_x);
            script_context.outputs.push(res_y);

            tmp = tmp.add(tmp).into_affine();

            assert_eq!(res_x, tmp.x().unwrap().clone());
            assert_eq!(res_y, tmp.y().unwrap().clone());

            // ecc_double_add_data_set.push(ecc_double_add_data_tmp);
            script_contexts.push(script_context);

            if *b {
                let mut script_context = ScriptContext::default();

                let (lambda, miu, res_x, res_y) = PairingNative::line_add_g2(&res, &tmp);

                script_context.inputs.push(lambda);
                script_context.inputs.push(miu);
                script_context.inputs.push(res.x().unwrap().to_owned());
                script_context.inputs.push(res.y().unwrap().to_owned());
                script_context.inputs.push(tmp.x().unwrap().to_owned());
                script_context.inputs.push(tmp.y().unwrap().to_owned());
                script_context.outputs.push(res_x);
                script_context.outputs.push(res_y);

                tmp = tmp.add(res).into_affine();

                assert_eq!(res_x, tmp.x().unwrap().clone());
                assert_eq!(res_y, tmp.y().unwrap().clone());

                script_contexts.push(script_context);
            }
        }

        (tmp, script_contexts)
    }

    pub fn line_add_g2(
        point1: &ark_bn254::G2Affine,
        point2: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x1, y1) = (point1.x, point1.y);
        let (x2, y2) = (point2.x, point2.y);

        // slope: alpha = (y2-y1)/(x2-x1)
        let alpha = (y2.sub(y1)).div(x2.sub(x1));
        // bias = y1 - alpha * x1
        let bias = y1 - alpha * x1;

        let x3 = alpha.square() - x1 - x2;
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }

    pub fn line_double_g2(
        point: &ark_bn254::G2Affine,
    ) -> (
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
        ark_bn254::Fq2,
    ) {
        let (x, y) = (point.x, point.y);

        // slope: alpha = 3 * x ^ 2 / (2 * y)
        let alpha = x
            .square()
            .mul(ark_bn254::Fq2::from(3))
            .div(y.mul(ark_bn254::Fq2::from(2)));
        // bias = y - alpha * x
        let bias = y - alpha * x;

        let x3 = alpha.square() - x.double();
        let y3 = -(bias + alpha * x3);

        (alpha, bias, x3, y3)
    }
}
pub struct PairingSplitScript;

impl PairingSplitScript {
    pub fn scalar_mul_split_g2(scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut script_chunks: Vec<Script> = vec![];

        for bit in scalar_bit.iter().skip(1) {
            script_chunks.push(Self::double_line_g2());

            if *bit {
                script_chunks.push(Self::add_line_g2());
            }
        }

        script_chunks
    }

    // Stack top: [Q.x, Q.y]
    // Stack top: [Q.x, Q.y * fro]
    // Stack top: [Q.x, Q.y * fro * constant_1]
    // Stack top: [Q.x] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0] | [Q.y * fro * constant_1]
    // Stack top: [Q.x * fro * constant_0, Q.y * fro * constant_1]
    pub fn g2_subgroup_check(constants: [ark_bn254::Fq2; 2], scalar_bit: Vec<bool>) -> Vec<Script> {
        let mut res = vec![];

        res.push(script! {

            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[1])}
            { Fq2::toaltstack()}
            { Fq2::frobenius_map(1)}
            { Fq2::mul_by_constant(&constants[0])}
            { Fq2::fromaltstack()}

        });

        res.extend(Self::scalar_mul_split_g2(scalar_bit));

        res
    } // Stack top: [lamda, mu,   Q.x, Q.y ]
      // Type:      [Fq2,   Fq2, (Fq2, Fq2)]
    pub fn double_line_g2() -> Script {
        script! {
            // check 2*lamda*y == 3 * q.x^2
            // [lamda, mu, x, y, y ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, y, lamda ]
            { Fq2::copy(8) }
            // [lamda, mu, x, y, y * lamda ]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y, 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y] | [ 2 *y * lamda ]
            { Fq2::toaltstack() }
            // 2 * lamda * y == 3 * x^2
            // [lamda, mu, x, y, x] | [ 2 *y * lamda ]
            { Fq2::copy(2) }
            // [lamda, mu, x, y, x^2] | [ 2 *y * lamda ]
            { Fq2::square() }
            // [lamda, mu, x, y, x^2, x^2] | [ 2 *y * lamda ]
            { Fq2::copy(0) }
            // [lamda, mu, x, y, x^2, 2x^2] | [ 2 *y * lamda ]
            { Fq2::double(0) }
            // [lamda, mu, x, y, 3x^2] | [ 2 *y * lamda ]
            { Fq2::add(0, 2) }
            // [lamda, mu, x, y, 3x^2, 2 *y * lamda ]
            { Fq2::fromaltstack() }
            // [lamda, mu, x, y]
            { Fq2::equalverify() }
            // check y - lamda * x _ mu == 0
            // [lamda, mu, x, y, mu]
            { Fq2::copy(4) }
            // [lamda, mu, x, y - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu, x]
            { Fq2::copy(2) }
            // [lamda, mu, x, y - mu, x, lamda]
            { Fq2::copy(8) }
            // [lamda, mu, x, y - mu, x * lamda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x, y - mu - x * lamda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x, y - mu - x * lamda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - 2x
            // [lamda, mu, x, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2, 2x]
            { Fq2::double(2) }
            // [lamda, mu, lamda^2 - 2x]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }

    // Stack top: [lamda, mu,  Q.x1, Q.y1, Q.x2, Q.y2 ]
    // Type:      [Fq2,   Fq2, (Fq2, Fq2), (Fq2, Fq2)]
    pub fn add_line_g2() -> Script {
        script! {
            // check y2 - lamda * x2 - mu == 0
            // [lamda, mu, x1, y1, x2, y2, mu]
            { Fq2::copy(8) }
            // [lamda, mu, x1, y1, x2, y2 - mu]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2]
            { Fq2::copy(2) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2, lambda]
            { Fq2::copy(12) }
            // [lamda, mu, x1, y1, x2, y2 - mu, x2 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, y1, x2, y2 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, y1, x2]
            { Fq2::equalverify() }
            // check y1 - lamda * x1 - mu == 0
            // [lamda, mu, x1, y1, x2, mu]
            { Fq2::copy(6) }
            // [lamda, mu, x1, x2, y1 - mu]
            { Fq2::sub(4, 0) }
            // [lamda, mu, x1, x2, y1 - mu, x1]
            { Fq2::copy(4) }
            // [lamda, mu, x1, x2, y1 - mu, x1, lambda]
            { Fq2::copy(10) }
            // [lamda, mu, x1, x2, y1 - mu, x1 * lambda]
            { Fq2::mul(0, 2) }
            // [lamda, mu, x1, x2, y1 - mu - x1 * lambda]
            { Fq2::sub(2, 0) }
            // [lamda, mu, x1, x2, y1 - mu - x2 * lambda, 0]
            { Fq2::push_zero() }
            // [lamda, mu, x1, x2]
            { Fq2::equalverify() }
            // calcylate x_3 = lamda^2 - x1 - x2
            // [lamda, mu, x1 + x2]
            {Fq2::add(0, 2)}
            // [lamda, mu, x1 + x2, lamda]
            { Fq2::copy(4) }
            // [lamda, mu, x1 + x2, lamda^2]
            { Fq2::square() }
            // [lamda, mu, lamda^2 - (x1 + x2)]
            { Fq2::sub(0, 2) }
            // [lamda, mu, x3, x3 ]
            { Fq2::copy(0) }
            // [mu, x3, lamda * x3 ]
            { Fq2::mul(0, 6) }
            // [x3, lamda * x3 + mu ]
            { Fq2::add(0, 4) }
            // [x3, y3 ]
            { Fq2::neg(0) }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;

    use ark_ff::UniformRand;
    use ark_std::end_timer;
    use ark_std::start_timer;

    use num_bigint::BigUint;

    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_g2_subgroup_check() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        #[allow(non_snake_case)]
        for _ in 0..1 {
            let P_POWER_ENDOMORPHISM_COEFF_0 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "21575463638280843010398324269430826099269044274347216827212613867836435027261",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "10307601595873709700152284273816112264069230130616436755625194854815875713954",
                )
                .unwrap(),
            );

            // PSI_Y = (u+9)^((p-1)/2) = TWIST_MUL_BY_Q_Y
            let P_POWER_ENDOMORPHISM_COEFF_1 = ark_bn254::Fq2::new(
                ark_bn254::Fq::from_str(
                    "2821565182194536844548159561693502659359617185244120367078079554186484126554",
                )
                .unwrap(),
                ark_bn254::Fq::from_str(
                    "3505843767911556378687030309984248845540243509899259641013678093033130930403",
                )
                .unwrap(),
            );

            let scalar_bit: Vec<bool> = ark_ff::BitIteratorBE::without_leading_zeros(&[
                17887900258952609094,
                8020209761171036667,
            ])
            .collect();

            let p = ark_bn254::G2Affine::rand(&mut prng);

            let scripts = PairingSplitScript::g2_subgroup_check(
                [P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1],
                scalar_bit.clone(),
            );

            println!(
                "curves::test_g2_subgroup_check script chunk num = {}",
                scripts.len()
            );

            // **************** prepare witness data ******************

            let (res, witness) = PairingNative::witness_g2_subgroup_check(
                &p,
                [P_POWER_ENDOMORPHISM_COEFF_0, P_POWER_ENDOMORPHISM_COEFF_1],
                scalar_bit.clone(),
            );

            assert!(res);

            println!(
                "curves::test_g2_subgroup_check witness data len = {}",
                witness.len()
            );

            //********** Check ech script chunk with witness data *************//

            // execute for each msm-script and witness
            for (i, (wit, scp)) in witness.iter().zip(scripts).enumerate() {
                let final_script = script! {
                    for input in wit.inputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(input.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(input.c1).to_u32_digits()) }
                    }
                    { scp.clone() }
                    for output in wit.outputs.iter() {
                        { Fq::push_u32_le(&BigUint::from(output.c0).to_u32_digits()) }
                        { Fq::push_u32_le(&BigUint::from(output.c1).to_u32_digits()) }

                    }
                    { Fq::equalverify(4,0) }
                    { Fq::equalverify(3,0) }
                    { Fq::equalverify(2,0) }
                    { Fq::equalverify(1,0) }
                    OP_TRUE
                };
                let start = start_timer!(|| "execute_test_g2_subgroup_check_script");
                let exec_result = execute_script(final_script);
                assert!(exec_result.success);
                println!("subscript[{}] runs successfully!", i);
                end_timer!(start);
            }
        }
    }
}
