use super::elements::DataType::{Fq2Data, FqData, G1PointData};
use super::elements::{Fq2Type, FqType, G1PointType};

use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::chunker::assigner::*;
use crate::chunker::elements::ElementTrait;
use crate::chunker::segment::Segment;
use crate::treepp::script;

use ark_bn254::Bn254;
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

pub fn g1_points<T: BCAssigner>(
    assigner: &mut T,
    g1p: G1PointType,
    g1a: ark_bn254::G1Affine,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> (Vec<Segment>, Vec<Fq2Type>) {
    let mut segments = vec![];

    let (p2, p3, p4) = (proof.c, vk.alpha_g1, proof.a);
    let mut g2p = G1PointType::new(assigner, "F_p2_init");
    g2p.fill_with_data(G1PointData(p2));
    let mut g3p = G1PointType::new(assigner, "F_p3_init");
    g3p.fill_with_data(G1PointData(p3));
    let mut g4p = G1PointType::new(assigner, "F_p4_init");
    g4p.fill_with_data(G1PointData(p4));

    let (s1, a1) = make_p(assigner, "F_p1_im".to_owned(), g1p, g1a);
    let (s2, a2) = make_p(assigner, "F_p2_im".to_owned(), g2p, p2);
    let (s3, a3) = make_p(assigner, "F_p3_im".to_owned(), g3p, p3);
    let (s4, a4) = make_p(assigner, "F_p4_im".to_owned(), g4p, p4);

    segments.extend(s1);
    segments.extend(s2);
    segments.extend(s3);
    segments.extend(s4);

    let im_var_p = vec![a1, a2, a3, a4];
    (segments, im_var_p)
}

fn make_p<T: BCAssigner>(
    assigner: &mut T,
    prefix: String,
    g1p: G1PointType,
    g1a: ark_bn254::G1Affine,
) -> (Vec<Segment>, Fq2Type) {
    let mut segments = vec![];

    let p1 = g1a;
    let (hinted_script1, hint1) = Fq::hinted_inv(p1.y);
    let (hinted_script2, hint2) = Fq::hinted_mul(1, p1.y.inverse().unwrap(), 0, p1.x.neg());

    let script_p1 = script! {
        { hinted_script1 } // Fq::inv()
        { Fq::copy(0) }
        { Fq::roll(2) }
        { Fq::neg(0) }
        { hinted_script2 } // Fq::mul()
        { Fq::roll(1) }
    };

    let mut hints_p1 = Vec::new();
    hints_p1.extend(hint1);
    hints_p1.extend(hint2);

    let mut result_p = Fq2Type::new(assigner, &format!("{}_o_a", prefix));
    result_p.fill_with_data(Fq2Data(ark_bn254::Fq2::new(
        -p1.x / p1.y,
        p1.y.inverse().unwrap(),
    )));

    segments.push(
        Segment::new_with_name(prefix, script_p1)
            .add_parameter(&g1p)
            .add_result(&result_p.clone())
            .add_hint(hints_p1),
    );

    (segments, result_p)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::msm::hinted_msm_with_constant_bases_affine;
    use crate::chunker::elements::DataType::G1PointData;
    use crate::{execute_script_with_inputs, execute_script_without_stack_limit};

    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};

    #[test]
    fn test_make_p() {
        let k = 2;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let expect = ark_bn254::G1Projective::msm(&bases, &scalars).unwrap();
        let expect = expect.into_affine();
        let (msm, hints) = hinted_msm_with_constant_bases_affine(&bases, &scalars);

        let start = start_timer!(|| "collect_script");
        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { msm.clone() }
            // { G1Affine::push(expect) }
            // { G1Affine::equalverify() }
            // OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        // assert!(exec_result.success);
        println!("exec_result {}", exec_result);

        let mut assigner = DummyAssigner::default();
        let g1a = expect;
        let mut g1p = G1PointType::new(&mut assigner, "test");
        g1p.fill_with_data(G1PointData(g1a));
        let (segments, _) = make_p(&mut assigner, "test".to_owned(), g1p, g1a);

        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }
}
