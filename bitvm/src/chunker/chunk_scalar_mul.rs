use std::cmp::min;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use bitcoin_script::script;

use super::assigner::BCAssigner;
use super::elements::FrType;
use super::segment::Segment;
use crate::{
    bn254::{g1::G1Affine, fp254impl::Fp254Impl, fr::Fr},
    chunker::elements::{ElementTrait, G1PointType},
};

/// This function do scalar multiplication in G1 curve group.
/// Return all segements generated and the result of scalar multiplication.
#[allow(clippy::too_many_arguments)]
pub fn chunk_hinted_scalar_mul_by_constant<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    scalar: ark_bn254::Fr,
    scalar_type: FrType,
    p: &mut ark_bn254::G1Affine,
    coeff: Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
    step_p: Vec<ark_bn254::G1Affine>,
    trace: Vec<ark_bn254::G1Affine>,
) -> (Vec<Segment>, G1PointType) {
    let mut segments = vec![];
    let mut type_acc = G1PointType::new(assigner, &format!("{}_{}", prefix, 0));

    let mut hints = vec![];
    let mut coeff_iter = coeff.iter();
    let mut step_p_iter = step_p.iter();
    let mut trace_iter = trace.iter();
    let mut loop_scripts = Vec::new();
    let mut i = 0;
    // options: i_step = 2-15
    let i_step = 12;

    // precomputed lookup table (affine)
    let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
    p_mul.push(ark_bn254::G1Affine::zero());
    for _ in 1..(1 << i_step) {
        p_mul.push((*p_mul.last().unwrap() + *p).into_affine());
    }
    let mut c: ark_bn254::G1Affine = ark_bn254::G1Affine::zero();
    let scalar_bigint = scalar.into_bigint();

    while i < Fr::N_BITS {
        let depth = min(Fr::N_BITS - i, i_step);
        // double(step-size) point
        if i > 0 {
            // divide this part into three to fit into 4mb chunk and 1000 stack limit
            if depth > 2 * i_step / 3 {
                for _ in 0..(i_step / 3) {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);

                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_1", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_1", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;

                for _ in (i_step / 3)..(2 * i_step / 3) {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);
    
                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_2", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_2", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;

                for _ in (2 * i_step / 3)..depth {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);
    
                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_3", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_3", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;
            } else if depth > i_step / 3 {
                for _ in 0..(i_step / 3) {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);
    
                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_1", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_1", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;

                for _ in (i_step / 3)..depth {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);
    
                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_2", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_2", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;
            } else {
                for _ in 0..depth {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();

                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);

                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);

                    c = (c + c).into_affine();
                }

                let mut segment_script = script! {};
                for script in loop_scripts.clone() {
                    segment_script = segment_script.push_script(script.compile());
                }
                loop_scripts.clear();

                let mut update = G1PointType::new(assigner, &format!("{}_{}_piece_3", prefix, i));
                update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
                let segment = Segment::new_with_name(
                    format!("{}_loop_{}_piece_3", prefix, i),
                    segment_script,
                )
                .add_parameter(&type_acc)
                .add_result(&update)
                .add_hint(hints.clone());
                hints.clear();
                segments.push(segment);

                type_acc = update;
            }
        }

        // squeeze a bucket scalar
        loop_scripts.push(script! {
            for _ in 0..i {
                OP_FROMALTSTACK OP_DROP
            }
            for _ in 0..depth {
                OP_FROMALTSTACK
            }
            for _ in 0..(Fr::N_BITS - i - depth) {
                OP_FROMALTSTACK
                OP_DROP
            }
        });

        let mut mask = 0;

        for j in 0..depth {
            mask *= 2;
            mask += scalar_bigint.get_bit((Fr::N_BITS - i - j - 1) as usize) as u32;
        }

        // add point
        if i == 0 {
            loop_scripts.push(G1Affine::dfs_with_constant_mul(
                0,
                depth - 1,
                0,
                &p_mul,
            ));
            let _point_after_add = trace_iter.next().unwrap();
        } else {
            let add_coeff = *coeff_iter.next().unwrap();
            let _point_after_add = trace_iter.next().unwrap();
            let (add_script, add_hints) =
            G1Affine::hinted_check_add(c, p_mul[mask as usize], add_coeff.0); // add_coeff.1

            let add_loop = script! {
                // query bucket point through lookup table
                { G1Affine::dfs_with_constant_mul(0, depth - 1, 0, &p_mul) }
                // check before usage
                { add_script }
            };
            loop_scripts.push(add_loop.clone());
            hints.extend(add_hints);
        }
        c = (c + p_mul[mask as usize]).into_affine();

        let mut segment_script = script! {
            { Fr::convert_to_le_bits_toaltstack() }
        };
        for script in loop_scripts.clone() {
            segment_script = segment_script.push_script(script.compile());
        }
        loop_scripts.clear();

        if i == 0 {
            type_acc.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
            let segment = Segment::new_with_name(format!("{}_loop_{}", prefix, i), segment_script)
                .add_parameter(&scalar_type)
                .add_result(&type_acc)
                .add_hint(hints.clone());
            hints.clear();
            segments.push(segment);
        } else {
            let mut update = G1PointType::new(assigner, &format!("{}_{}", prefix, i));
            update.fill_with_data(crate::chunker::elements::DataType::G1PointData(c));
            let segment = Segment::new_with_name(format!("{}_loop_{}", prefix, i), segment_script)
                .add_parameter(&type_acc)
                .add_parameter(&scalar_type)
                .add_result(&update)
                .add_hint(hints.clone());
            hints.clear();
            segments.push(segment);

            type_acc = update;
        }

        i += i_step;
    }
    assert!(coeff_iter.next().is_none());
    assert!(step_p_iter.next().is_none());
    assert!(trace_iter.next().is_none());

    println!("debug: c:{:?}", c);
    *p = c;

    (segments, type_acc)
}

#[cfg(test)]
mod tests {
    use crate::{
        bn254::{g1::G1Affine, msm::prepare_msm_input},
        chunker::{
            assigner::DummyAssigner,
            chunk_scalar_mul::chunk_hinted_scalar_mul_by_constant,
            elements::{ElementTrait, FrType},
        },
        execute_script_with_inputs,
        treepp::*,
    };
    
    use ark_ec::{AffineRepr as _, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::ops::Mul;

    #[test]
    fn test_stable_script() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();
        let mut assigner = DummyAssigner::default();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        // first run
        let mut bases1 = bases.clone();
        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();
        let q = bases[0].mul(scalars[0]).into_affine();
        println!("debug: expected res:{:?}", q);
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);
        let mut scalar_type = FrType::new(&mut assigner, "init");
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalars[0]));

        let (segments1, _) = chunk_hinted_scalar_mul_by_constant(
            &mut assigner,
            "g1_mul",
            scalars[0],
            scalar_type,
            &mut bases1[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
            inner_coeffs[0].2.clone(),
        );

        // second run
        let mut bases2 = bases.clone();
        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();
        let q = bases[0].mul(scalars[0]).into_affine();
        println!("debug: expected res:{:?}", q);
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);
        let mut scalar_type = FrType::new(&mut assigner, "init");
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalars[0]));

        let (segments2, _) = chunk_hinted_scalar_mul_by_constant(
            &mut assigner,
            "g1_mul",
            scalars[0],
            scalar_type,
            &mut bases2[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
            inner_coeffs[0].2.clone(),
        );

        assert_eq!(segments1.len(), segments2.len());
        for (seg1, seg2) in segments1.into_iter().zip(segments2) {
            if seg1.script.compile().into_bytes() != seg2.script.compile().into_bytes() {
                println!("bad {} != {}", seg1.name, seg2.name);
            } else {
                println!("good {} == {}", seg1.name, seg2.name);
            }
        }
    }

    #[test]
    fn test_dfs() {
        let depth = 12;
        let i_step = 12;

        let rng = &mut test_rng();
        let p = ark_bn254::G1Projective::rand(rng).into_affine();

        // precomputed lookup table (affine)
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << i_step) {
            p_mul.push((*p_mul.last().unwrap() + p).into_affine());
        }

        let script1 = script! {
            { G1Affine::dfs_with_constant_mul(0, depth - 1, 0, &p_mul) }
        };

        let script2 = script! {
            { G1Affine::dfs_with_constant_mul(0, depth - 1, 0, &p_mul) }
        };

        if script1.compile().into_bytes() != script2.compile().into_bytes() {
            println!("bad");
        } else {
            println!("good");
        }
    }

    #[test]
    fn test_hinted_scalar_mul_by_constant_g1_affine() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();
        let mut assigner = DummyAssigner::default();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let mut bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let q = bases[0].mul(scalars[0]).into_affine();
        println!("debug: expected res:{:?}", q);
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);

        let mut scalar_type = FrType::new(&mut assigner, "init");
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(scalars[0]));

        let (segments, _) = chunk_hinted_scalar_mul_by_constant(
            &mut assigner,
            "g1_mul",
            scalars[0],
            scalar_type,
            &mut bases[0],
            inner_coeffs[0].0.clone(),
            inner_coeffs[0].1.clone(),
            inner_coeffs[0].2.clone(),
        );

        println!("segments count: {}", segments.len());

        for segment in segments.iter() {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {} in {}",
                script.len() + lenw,
                segment.name
            );

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "stack limit exceeded {} in {}",
                res.stats.max_nb_stack_items,
                segment.name
            );
        }
    }
}
