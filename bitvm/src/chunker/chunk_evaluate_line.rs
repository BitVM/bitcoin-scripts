use super::elements::{
    DataType::Fq12Data, DataType::Fq2Data, DataType::Fq6Data, ElementTrait,
    Fq12Type, Fq2Type, Fq6Type,
};
use super::{assigner::BCAssigner, segment::Segment};
use crate::bn254::{ell_coeffs::EllCoeff, fp254impl::Fp254Impl, fq::Fq, fq12::Fq12, fq2::Fq2};
use crate::treepp::*;
use ark_ff::{AdditiveGroup, Field};

#[allow(clippy::too_many_arguments)]
pub fn chunk_evaluate_line_wrapper<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Vec<Segment>, Fq12Type) {
    let mut pf = Fq12Type::new(assigner, &format!("{}{}", prefix, "f"));
    pf.fill_with_data(Fq12Data(f));
    let mut pxy = Fq2Type::new(assigner, &format!("{}{}", prefix, "xy"));
    pxy.fill_with_data(Fq2Data(ark_bn254::Fq2::new(x, y)));

    chunk_evaluate_line(assigner, prefix, pf, pxy, f, x, y, constant,None)
}

#[allow(clippy::too_many_arguments)]
pub fn chunk_evaluate_line<T: BCAssigner>(
    assigner: &mut T,
    prefix: &str,
    pf: Fq12Type,
    pxy: Fq2Type,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
    constant_4:Option<Fq6Type>,
) -> (Vec<Segment>, Fq12Type) {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);

    let (hinted_script1, hint1) = if constant_4.is_some() {
        Fq::hinted_mul(1,x,0, constant.1.c0) 
    } else {
        Fq::hinted_mul_by_constant(x, &constant.1.c0)
    };
    let (hinted_script2, hint2) =  if constant_4.is_some() {
        Fq::hinted_mul(1,x,0, constant.1.c1)  
    } else {
        Fq::hinted_mul_by_constant(x, &constant.1.c1)
    };
    let (hinted_script3, hint3) =  if constant_4.is_some() {
        Fq::hinted_mul(1,y,0, constant.2.c0) 
    } else {
        Fq::hinted_mul_by_constant(y, &constant.2.c0)
    };
    let (hinted_script4, hint4) =  if constant_4.is_some() {
        Fq::hinted_mul(1,y,0, constant.2.c1) 
    } else {
        Fq::hinted_mul_by_constant(y, &constant.2.c1)
    };

    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);

    let script_lines_0 = if constant_4.is_some() {
        vec![
            // [c0.0,c0.1, c1.0, c1.1, c2.0, c2.1, x, y]
            Fq::roll(7),
            // [c0.1, c1.0, c1.1, c2.0, c2.1, x, y,c0.0]
            Fq::roll(7),
            // [ c1.0, c1.1, c2.0, c2.1, x, y,c0.0,c0.1]
            Fq::drop(),
            Fq::drop(),
            // [c1.0, c1.1, c2.0, c2.1, x, y]
            Fq::copy(1),
            // [c1.0, c1.1, c2.0, c2.1, x, y, x]
            Fq::roll(6),
            // [c1.1, c2.0, c2.1, x, y, x, c1.0]
            hinted_script1,
            // [c1.1, c2.0, c2.1, x, y, x*c1.0]
            Fq::roll(2),
            // [c1.1, c2.0, c2.1, y, x*c1.0, x]
            Fq::roll(5),
            // [ c2.0, c2.1, y, x*c1.0, x, c1.1]
            hinted_script2,
            // [ c2.0, c2.1, y, x*c1.0, x*c1.1]
            Fq::copy(2),
            // [ c2.0, c2.1, y, x*c1.0, x*c1.1, y]
            Fq::roll(5),
            // [ c2.1, y, x*c1.0, x*c1.1, y, c2.0]
            hinted_script3,
            // [ c2.1, y, x*c1.0, x*c1.1, y*c2.0]
            Fq::roll(3),
            // [ c2.1, x*c1.0, x*c1.1, y*c2.0, y]
            Fq::roll(4),
            // [ x*c1.0, x*c1.1, y*c2.0, y, c2.1]
            hinted_script4,
            // [ x*c1.0, x*c1.1, y*c2.0, y*c2.1]
        ]
    } else {
        vec![
        // [x', y']
        // update c1, c1' = x' * c1
        Fq::copy(1),
        hinted_script1,
        // [ x', y', x' * c1.0]
        Fq::roll(2),
        hinted_script2,
        // [y', x' * c1.0, x' * c1.1]
        // [y', x' * c1]

        // update c2, c2' = -y' * c2
        Fq::copy(2),
        hinted_script3, // Fq::mul_by_constant(&constant.2.c0),
        // [y', x' * c1, y' * c2.0]
        Fq::roll(3),
        hinted_script4,
        // [x' * c1, y' * c2.0, y' * c2.1]
        // [x' * c1, y' * c2]
        // [c1', c2']
        ]
    };

    let mut script_0 = script! {};
    for script_line_0 in script_lines_0 {
        script_0 = script_0.push_script(script_line_0.compile());
    }
    let mut hints_0 = Vec::new();
    hints_0.extend(hint1);
    hints_0.extend(hint2);
    hints_0.extend(hint3);
    hints_0.extend(hint4);

    let mut tr0 = Fq6Type::new(assigner, &format!("{}{}", prefix, "c0"));
    tr0.fill_with_data(Fq6Data(ark_bn254::Fq6::new(c1, c2, ark_bn254::Fq2::ZERO)));

    let mut segment0 = Segment::new_with_name(
        format!("{}seg1", prefix),
        script! {
            {script_0}
            {Fq2::push_zero()}
        },
    );
    if constant_4.is_some() {
        segment0 = segment0.add_parameter(constant_4.as_ref().unwrap())
    }
    segment0 = segment0.add_parameter(&pxy)
    .add_result(&tr0)
    .add_hint(hints_0);

    let mut f1 = f;
    f1.mul_by_034(&constant.0, &c1, &c2);
    let c = f1;
    let mut tc = Fq12Type::new(assigner, &format!("{}{}", prefix, "c"));
    tc.fill_with_data(Fq12Data(c));

    let (script_1, hint_1) = Fq12::hinted_mul_by_34(f, c1, c2);
    //  // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
    //  script_1,
    // // [f, c1', c2']
    //  // [f]
    let segment1 = Segment::new_with_name(
        format!("{}seg2", prefix),
        script! {
            {Fq2::drop()}
            {script_1}
        },
    )
    .add_parameter(&pf)
    .add_parameter(&tr0)
    .add_result(&tc)
    .add_hint(hint_1);

    (vec![segment0, segment1], tc)
}



#[cfg(test)]
mod test {
    use super::chunk_evaluate_line_wrapper;
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq12::Fq12;
    use crate::bn254::g1::hinted_from_eval_point;
    use crate::bn254::g2::hinted_ell_by_constant_affine_and_sparse_mul;
    use crate::chunker::elements;
    use crate::chunker::{assigner::DummyAssigner, segment};
    use crate::treepp::*;

    use crate::execute_script_with_inputs;

    use ark_ff::Field;
    use ark_std::UniformRand;
    use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ell() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let f = ark_bn254::Fq12::rand(&mut prng);
        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b);
        let (from_eval_point_script, hints_eval) = hinted_from_eval_point(p);
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine_and_sparse_mul(
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            &coeffs.ell_coeffs[0],
        );
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        // affine mode as well
        let hint = {
            assert_eq!(coeffs.ell_coeffs[0].0, ark_bn254::fq2::Fq2::ONE);

            let mut f1 = f;
            let mut c1new = coeffs.ell_coeffs[0].1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));

            let mut c2new = coeffs.ell_coeffs[0].2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));

            f1.mul_by_034(&coeffs.ell_coeffs[0].0, &c1new, &c2new);
            f1
        };

        let script = script! {
            for tmp in hints_eval {
                { tmp.push() }
            }
            for tmp in hints {
                { tmp.push() }
            }

            { Fq12::push(f) }
            { Fq::push(p.y.inverse().unwrap()) }
            { Fq::push(p.x) }
            { Fq::push(p.y) }
            { from_eval_point_script }
            { ell_by_constant_affine_script.clone() }
            { Fq12::push(hint) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        println!("exec_result: {:}", exec_result);
        assert!(exec_result.success);

        //
        let mut assigner = DummyAssigner::default();
        let mut segments = Vec::new();
        let fn_name = format!("F_{}_mul_c_1p{}", 0, 0);
        let (segments_mul, _): (Vec<segment::Segment>, elements::Fq12Type) =
            chunk_evaluate_line_wrapper(
                &mut assigner,
                &fn_name,
                f,
                -p.x / p.y,
                p.y.inverse().unwrap(),
                &coeffs.ell_coeffs[0],
            );
        segments.extend(segments_mul);

        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            println!(
                "segment script size {} witness size {} total {}",
                script.len(),
                lenw,
                script.len() + lenw
            );
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            let hash1 = Sha256::hash(segment.script.clone().compile().as_bytes());
            let hash2 = Sha256::hash(script.clone().compile().as_bytes());
            println!(
                "segment {} hash {} {} ",
                segment.name,
                hash1.clone(),
                hash2.clone()
            );

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
