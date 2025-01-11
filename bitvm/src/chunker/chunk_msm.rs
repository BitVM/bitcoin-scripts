use crate::bn254::msm::prepare_msm_input;
use crate::chunker::chunk_scalar_mul::chunk_hinted_scalar_mul_by_constant;
use crate::chunker::elements::DataType::G1PointData;
use ark_ec::CurveGroup;
use ark_ff::Field;
use bitcoin_script::script;

use super::assigner::BCAssigner;
use super::elements::FrType;
use super::segment::Segment;
use crate::{
    bn254::g1::G1Affine,
    chunker::elements::{ElementTrait, G1PointType},
};

/// With constant bases, this function generate all msm-related segments
/// and return the result additionally.
pub fn chunk_hinted_msm_with_constant_bases_affine<T: BCAssigner>(
    assigner: &mut T,
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
    scalar_types: &[FrType],
) -> (Vec<Segment>, G1PointType) {
    println!("use hinted_msm_with_constant_bases_affine");
    assert_eq!(bases.len(), scalars.len());
    assert_eq!(scalar_types.len(), scalars.len());
    assert_eq!(scalars[0], ark_bn254::Fr::ONE);

    let mut segments = vec![];

    let len = bases.len();
    let i_step = 12_u32;
    let (inner_coeffs, outer_coeffs) = prepare_msm_input(bases, scalars, i_step);

    let mut type_acc = G1PointType::new(assigner, "msm_init");
    type_acc.fill_with_data(G1PointData(bases[0]));

    // 1. init the sum=0;
    let mut p = (bases[0] * scalars[0]).into_affine();
    let _is_scalar_one = false;

    for i in 0..len {
        let mut c = bases[i];
        if i == 0 {
            let segment = Segment::new_with_name(
                format!("msm_add_{}", i),
                script! {
                    {G1Affine::push(bases[i])}
                },
            )
            .add_result(&type_acc);
            segments.push(segment);
            continue;
        }

        let (segment, mul_result) = chunk_hinted_scalar_mul_by_constant(
            assigner,
            &format!("msm_{}", i),
            scalars[i],
            scalar_types[i].clone(),
            &mut c,
            inner_coeffs[i].0.clone(),
            inner_coeffs[i].1.clone(),
            inner_coeffs[i].2.clone(),
        );
        segments.extend(segment);

        // check coeffs before using
        let (hinted_script, hint) =
            G1Affine::hinted_check_add(p, c, outer_coeffs[i - 1].0); // outer_coeffs[i - 1].1

        p = (p + c).into_affine();

        let mut update = G1PointType::new(assigner, &format!("msm_update_{}", i));
        update.fill_with_data(G1PointData(p));
        let segment = Segment::new_with_name(
            format!("msm_add_{}", i),
            script! {
                {hinted_script}
            },
        )
        .add_parameter(&type_acc)
        .add_parameter(&mul_result)
        .add_result(&update)
        .add_hint(hint);

        segments.push(segment);

        type_acc = update;
    }
    (segments, type_acc)
}

#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_ff::{Field, UniformRand};
    use ark_std::test_rng;

    use crate::{
        chunker::{
            assigner::DummyAssigner,
            elements::{ElementTrait, FrType},
        },
        execute_script_with_inputs,
    };

    use super::chunk_hinted_msm_with_constant_bases_affine;

    #[test]
    fn test_hinted_msm_with_constant_bases_affine_script() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();
        let mut assigner = DummyAssigner::default();

        let scalars = (0..n - 1)
            .map(|_| ark_bn254::Fr::rand(rng))
            .collect::<Vec<_>>();

        let scalars = [vec![ark_bn254::Fr::ONE], scalars].concat();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let mut scalar_types = vec![];
        for (idx, scalar) in scalars.iter().enumerate() {
            let mut scalar_type = FrType::new(&mut assigner, &format!("scalar_{}", idx));
            scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(*scalar));
            scalar_types.push(scalar_type);
        }

        let (segments, _) = chunk_hinted_msm_with_constant_bases_affine(
            &mut assigner,
            &bases,
            &scalars,
            &scalar_types,
        );

        println!("segments number {}", segments.len());

        for segment in segments.iter() {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

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
