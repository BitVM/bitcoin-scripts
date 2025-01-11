#![allow(non_snake_case)]
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::g2::{collect_line_coeffs, hinted_affine_add_line, hinted_affine_double_line, hinted_check_chord_line, hinted_check_tangent_line};
use crate::chunker::elements::ElementTrait;
use crate::treepp::*;
use ark_ec::bn::BnConfig;
use ark_ff::{AdditiveGroup, Field};
use num_bigint::BigUint;
use num_traits::One;
use std::{ops::Neg, str::FromStr};

use super::assigner::BCAssigner;
use super::elements::{Fq6Type, G2PointType};
use super::segment::Segment;

pub fn chunk_q4<T: BCAssigner>(
    constants: Vec<G2Prepared>,
    line_coeffs_4: &Vec<Vec<Fq6Type>>,
    q4: ark_bn254::G2Affine,
    q4_input: G2PointType,
    assigner: &mut T,
) -> Vec<Segment> {
    assert_eq!(constants.len(), 4);
    let num_line_groups = constants.len();
    let num_constant = 3;
    let line_coeffs = collect_line_coeffs(constants);
    let num_lines = line_coeffs.len();

    let mut segments = vec![];

    // 1. copy q4 to t4
    let mut t4 = q4;

    let mut t4_acc = G2PointType::new(assigner, "t4_init");
    t4_acc.fill_with_data(crate::chunker::elements::DataType::G2PointData(t4));
    let segment = Segment::new_with_name("copy_q4_to_t4".into(), script! {})
        .add_parameter(&q4_input)
        .add_result(&t4_acc);
    segments.push(segment);

    // 2. looped double-add
    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        for j in 0..num_line_groups {
            if j == num_constant {
                let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
                let three_div_two =
                    (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
                let mut alpha = t4.x.square();
                alpha /= t4.y;
                alpha.mul_assign_by_fp(&three_div_two);
                let bias_minus = alpha * t4.x - t4.y;
                let x = alpha.square() - t4.x.double();
                let y = bias_minus - alpha * x;
                let t4x = ark_bn254::G2Affine::new(x, y);

                let mut hints = vec![];
                let (hinted_script0, hint) = hinted_check_tangent_line(
                    t4,
                    line_coeffs[num_lines - (i + 2)][j][0].1,
                    line_coeffs[num_lines - (i + 2)][j][0].2,
                );
                hints.extend(hint);

                let (hinted_script1, hint) = hinted_affine_double_line(
                    t4.x,
                    line_coeffs[num_lines - (i + 2)][j][0].1,
                    line_coeffs[num_lines - (i + 2)][j][0].2,
                );
                hints.extend(hint);

                let mut t4_update = G2PointType::new(assigner, &format!("T4_{}_double", i));
                t4_update.fill_with_data(crate::chunker::elements::DataType::G2PointData(t4x));
                let segment = Segment::new_with_name(
                    format!("check and double_{}", i),
                    script! {
                        // [fq2(2),c3(2),c4(2),t4(4) ]
                        {Fq2::roll(8)}
                        {Fq2::drop()}
                        // [c3(2),c4(2),t4(4)]
                        { Fq2::copy(2) }
                        { Fq2::toaltstack() }
                        // [c3(2),c4(2),t4(4) | t4.x(2)]
                        {hinted_script0}
                        { Fq2::fromaltstack() }
                        // [c3(2),c4(2), t4.x(2)]
                        {hinted_script1}
                        // [c3(2),c4(2),t4'(4)]
                        { Fq2::roll(6) }
                        { Fq2::roll(6) }
                        // [t4'(4), c3(2),c4(2)]
                        { Fq2::drop() }
                        { Fq2::drop() }
                        //[t4'(4)]
                    },
                )
                .add_parameter(&line_coeffs_4[num_lines - (i + 2)][0])
                .add_parameter(&t4_acc)
                .add_result(&t4_update)
                .add_hint(hints);

                segments.push(segment);

                t4 = t4x;
                t4_acc = t4_update;
            }
        }

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
            || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
        {
            for j in 0..num_line_groups {
                if j == num_constant {
                    let mut script = script! {};
                    let mut hints = vec![];

                    let mut pm_q4 = q4;
                    if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
                        pm_q4 = q4.neg();
                        script = script.push_script(Fq2::neg(0).compile());
                    }
                    let alpha = (t4.y - pm_q4.y) / (t4.x - pm_q4.x);
                    let bias_minus = alpha * t4.x - t4.y;
                    let x = alpha.square() - t4.x - pm_q4.x;
                    let y = bias_minus - alpha * x;
                    let t4x = ark_bn254::G2Affine::new(x, y);

                    let (hinted_script0, hint) = hinted_check_chord_line(
                        t4,
                        pm_q4,
                        line_coeffs[num_lines - (i + 2)][j][1].1,
                        line_coeffs[num_lines - (i + 2)][j][1].2,
                    );
                    hints.extend(hint);

                    let (hinted_script1, hint) = hinted_affine_add_line(
                        t4.x,
                        q4.x,
                        line_coeffs[num_lines - (i + 2)][j][1].1,
                        line_coeffs[num_lines - (i + 2)][j][1].2,
                    );
                    hints.extend(hint);

                    script = script.push_script(
                        script! {
                            // [fq2(2),c3, c4, t4, pm_q4 ]
                            {Fq2::roll(12)}
                            {Fq2::drop()}
                            // [c3, c4, t4, pm_q4]
                            {Fq2::copy(2)}
                            {Fq2::toaltstack()}
                            {Fq2::copy(6)}
                            {Fq2::toaltstack()}
                            // [c3, c4, t4, pm_q4 | t4.x, pm_q4.x]
                            {hinted_script0}
                            //[c3,c4]
                            {Fq2::fromaltstack()}
                            {Fq2::fromaltstack()}
                            // [c3, c4, t4.x, pm_q4.x]
                            {hinted_script1}
                            // [c3(2),c4(2),updated_t4]
                            { Fq2::roll(6) }
                            { Fq2::roll(6) }
                            // [updated_t4, c3(2),c4(2)]
                            { Fq2::drop() }
                            { Fq2::drop() }
                            // [updated_t4]
                        }
                        .compile(),
                    );

                    let mut t4_update = G2PointType::new(assigner, &format!("T4_{}_add", i));
                    t4_update.fill_with_data(crate::chunker::elements::DataType::G2PointData(t4x));
                    let segment = Segment::new_with_name(format!("check and add{}", i), script)
                        .add_parameter(&line_coeffs_4[num_lines - (i + 2)][1])
                        .add_parameter(&t4_acc)
                        .add_parameter(&q4_input)
                        .add_result(&t4_update)
                        .add_hint(hints);
                    segments.push(segment);

                    t4 = t4x;
                    t4_acc = t4_update;
                }
            }
        }
    }

    // 3. phi_Q4
    for j in 0..num_line_groups {
        if j == num_constant {
            let beta_12x = BigUint::from_str(
                "21575463638280843010398324269430826099269044274347216827212613867836435027261",
            )
            .unwrap();
            let beta_12y = BigUint::from_str(
                "10307601595873709700152284273816112264069230130616436755625194854815875713954",
            )
            .unwrap();
            let beta_12 = ark_bn254::Fq2::from_base_prime_field_elems([
                ark_bn254::Fq::from(beta_12x.clone()),
                ark_bn254::Fq::from(beta_12y.clone()),
            ])
            .unwrap();
            let beta_13x = BigUint::from_str(
                "2821565182194536844548159561693502659359617185244120367078079554186484126554",
            )
            .unwrap();
            let beta_13y = BigUint::from_str(
                "3505843767911556378687030309984248845540243509899259641013678093033130930403",
            )
            .unwrap();
            let beta_13 = ark_bn254::Fq2::from_base_prime_field_elems([
                ark_bn254::Fq::from(beta_13x.clone()),
                ark_bn254::Fq::from(beta_13y.clone()),
            ])
            .unwrap();

            let mut hints = vec![];

            let mut q4y = q4.y;
            q4y.conjugate_in_place();
            let (q4y_mul_hinted_script, hint) = Fq2::hinted_mul(2, q4y, 0, beta_13);
            hints.extend(hint);
            q4y *= beta_13;

            let mut q4x = q4.x;
            q4x.conjugate_in_place();
            let (q4x_mul_hinted_script, hint) = Fq2::hinted_mul(2, q4x, 0, beta_12);
            hints.extend(hint);
            q4x *= beta_12;

            // ================================

            let alpha = (t4.y - q4y) / (t4.x - q4x);
            let bias_minus = alpha * t4.x - t4.y;
            let x = alpha.square() - t4.x - q4x;
            let y = bias_minus - alpha * x;
            let t4x = ark_bn254::G2Affine::new(x, y);
            let q4_new = ark_bn254::G2Affine::new(q4x, q4y);

            let (check_hinted_script, hint) = hinted_check_chord_line(
                t4,
                q4_new,
                line_coeffs[num_lines - 2][j][0].1,
                line_coeffs[num_lines - 2][j][0].2,
            );
            hints.extend(hint);

            let (add_hinted_script, hint) = hinted_affine_add_line(
                t4.x,
                q4_new.x,
                line_coeffs[num_lines - 2][j][0].1,
                line_coeffs[num_lines - 2][j][0].2,
            );
            hints.extend(hint);

            let script = script! {
                 // [fq2(2),c3, c4, t4, q4 ]
                 {Fq2::roll(12)}
                 {Fq2::drop()}
                // [c3(2), c4(2), t4(4), q4(4)]
                {Fq::neg(0)}
                { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
                { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }
                // [c3(2), c4(2), t4(4), q4.x(2), -q4.y(2), beta13(2)]
                { q4y_mul_hinted_script }
                { Fq2::toaltstack() }

                {Fq::neg(0)}
                // [t4, -q4.x]
                { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
                { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }
                // [t4, q4x, beta12]
                { q4x_mul_hinted_script }
                { Fq2::fromaltstack() }

                // [t4, phi_q4]
                {Fq2::copy(2)}
                {Fq2::toaltstack()}
                {Fq2::copy(6)}
                {Fq2::toaltstack()}
                // [c3(2), c4(2), t4(4), phi_q4(4)]
                {check_hinted_script}
                {Fq2::fromaltstack()}
                {Fq2::fromaltstack()}
                // [c3(2), c4(2), t4.x, phi_q4.x]
                {add_hinted_script}
                // [c3(2), c4(2), updated_t4]
                {Fq2::roll(6)}
                {Fq2::roll(6)}
                // [ updated_t4, c4(2), c3(2)]
                {Fq2::drop()}
                {Fq2::drop()}
                // [ updated_t4]
            };

            let mut t4_update = G2PointType::new(assigner, "T4_final_add");
            t4_update.fill_with_data(crate::chunker::elements::DataType::G2PointData(t4x));
            let segment = Segment::new_with_name("final check and add".into(), script)
                .add_parameter(&line_coeffs_4[num_lines - 2][0])
                .add_parameter(&t4_acc)
                .add_parameter(&q4_input)
                .add_result(&t4_update)
                .add_hint(hints);
            segments.push(segment);

            t4 = t4x;
            t4_acc = t4_update;
        }
    }

    // 4. phi_2_Q4 and Chord Check

    for j in 0..num_line_groups {
        if j == num_constant {
            let beta_22x = BigUint::from_str(
                "21888242871839275220042445260109153167277707414472061641714758635765020556616",
            )
            .unwrap();
            let beta_22y = BigUint::from_str("0").unwrap();
            let beta_22 = ark_bn254::Fq2::from_base_prime_field_elems([
                ark_bn254::Fq::from(beta_22x.clone()),
                ark_bn254::Fq::from(beta_22y.clone()),
            ])
            .unwrap();

            let mut hints = vec![];

            let (mul_x_hinted_script, hint) = Fq2::hinted_mul(2, q4.x, 0, beta_22);
            hints.extend(hint);

            let q4_new = ark_bn254::G2Affine::new(q4.x * beta_22, q4.y);

            let (check_hinted_script, hint) = hinted_check_chord_line(
                t4,
                q4_new,
                line_coeffs[num_lines - 1][j][0].1,
                line_coeffs[num_lines - 1][j][0].2,
            );
            hints.extend(hint);

            let script = script! {
                // [fq2(2),c3, c4, t4, q4 ]
                {Fq2::roll(12)}
                {Fq2::drop()}
                // [c3(2),c4(2),t4(4), q4(4)]
                {Fq2::toaltstack()}
                // [c3(2),c4(2),t4(4), q4x(2) | q4y(2)]
                { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
                { Fq::push_zero() }
                {mul_x_hinted_script}
                { Fq2::fromaltstack() }
                // [c3(2),c4(2),t4(4),  q4x'(2), q4y(2)]
                {check_hinted_script}
                //[c3(2),c4(2)]
                {Fq2::drop()}
                {Fq2::drop()}
                // []
            };

            let segment = Segment::new_with_name("final_final check".into(), script)
                .add_parameter(&line_coeffs_4[num_lines - 1][0])
                .add_parameter(&t4_acc)
                .add_parameter(&q4_input)
                .add_hint(hints);
            segments.push(segment);
        }
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::chunk_q4;
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::g2::collect_line_coeffs;
    use crate::chunker::assigner::DummyAssigner;
    use crate::chunker::elements::{ElementTrait, DataType::Fq6Data, Fq6Type, G2PointType};
    use crate::execute_script_with_inputs;
    use ark_std::UniformRand;
    use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_check_q4() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut assigner = DummyAssigner::default();

        // exp = 6x + 2 + p - p^2 = lambda - p^3
        let q1 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::g2::G2Affine::rand(&mut prng);
        let q1_prepared = G2Prepared::from_affine(q1);
        let q2_prepared = G2Prepared::from_affine(q2);
        let q3_prepared = G2Prepared::from_affine(q3);
        let q4_prepared = G2Prepared::from_affine(q4);

        let mut q4_input = G2PointType::new(&mut assigner, "q4");
        q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));

        let constants = [q1_prepared.clone(), q2_prepared.clone(), q3_prepared.clone(), q4_prepared.clone()].to_vec();
        assert_eq!(constants.len(), 4);
        let num_line_groups = constants.len();
        let mut line_coeffs_4: Vec<Vec<Fq6Type>> = vec![];
        let line_coeffs = collect_line_coeffs(constants);
        for i in 0..line_coeffs.len() {
            let line_coeff = &line_coeffs[i];
            assert_eq!(line_coeff.len(), num_line_groups);
            let mut line_coeff_4 = vec![];
            for j in 0..line_coeff[num_line_groups-1].len() {
                let coeff = &line_coeff[num_line_groups-1][j];
                let mut fq6 = Fq6Type::new(&mut assigner, &format!("line_coeffs_4_{i}{j}"));
                let data = ark_bn254::Fq6::new(coeff.0,coeff.1,coeff.2);
                fq6.fill_with_data(Fq6Data(data));
                line_coeff_4.push(fq6);
            }
            line_coeffs_4.push(line_coeff_4);
        }
        
        let segments = chunk_q4(
            [q1_prepared, q2_prepared, q3_prepared, q4_prepared].to_vec(),
            &line_coeffs_4,
            q4,
            q4_input,
            &mut assigner,
        );

        println!("segments number :{}", segments.len());

        // let witness = segments[91].witness(&assigner);
        // let script = segments[91].script(&assigner);
        // let res = execute_script_with_inputs(script, witness);
        // println!("res: {}", res);

        for segment in segments.iter() {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let hash1 = Sha256::hash(segment.script.clone().compile().as_bytes());
            let hash2 = Sha256::hash(script.clone().compile().as_bytes());
            println!(
                "segment {} hash {} {} ",
                segment.name,
                hash1.clone(),
                hash2.clone()
            );

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );
        }
    }
}
