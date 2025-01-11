#![allow(non_snake_case)]
use super::assigner::BCAssigner;
use super::chunk_evaluate_line::*;
use super::chunk_fq12_multiplication::*;
use super::elements::DataType::Fq12Data;
use super::elements::*;
use super::elements::Fq12Type;
use super::segment::*;

use crate::bn254::ell_coeffs::EllCoeff;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::fq12::Fq12;
use crate::bn254::g2::collect_line_coeffs;
use crate::bn254::utils::*;
use crate::treepp::*;

use ark_ec::bn::BnConfig;
use ark_ff::Field;

pub fn chunk_accumulator<T: BCAssigner>(
    assigner: &mut T,
    im_var_p: Vec<Fq2Type>,
    constants: Vec<G2Prepared>,
    line_coeffs_4: &Vec<Vec<Fq6Type>>,
    c: ark_bn254::Fq12,
    c_inv: ark_bn254::Fq12,
    wi: ark_bn254::Fq12,
    p_lst: Vec<ark_bn254::G1Affine>,
) -> (Vec<Segment>, Fq12Type, ark_bn254::Fq12) {
    let mut segments = vec![];

    assert_eq!(constants.len(), 4);
    let num_line_groups = constants.len();
    let line_coeffs: Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>> = collect_line_coeffs(constants);

    let num_lines = line_coeffs.len();

    let mut f = c_inv;

    let mut param_c_inv = Fq12Type::new(assigner, "c_inv_init");
    param_c_inv.fill_with_data(Fq12Data(c_inv));
    let mut param_c = Fq12Type::new(assigner, "c_init");
    param_c.fill_with_data(Fq12Data(c));
    let mut param_wi = Fq12Type::new(assigner, "wi_init");
    param_wi.fill_with_data(Fq12Data(wi));
    let mut param_f = Fq12Type::new(assigner, "f_init");
    param_f.fill_with_data(Fq12Data(f));

    // ATE_LOOP_COUNT = 65
    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let fx = f.square();
        let (hinted_script, hint) = Fq12::hinted_square(f);
        let (s, r) = make_chunk_square(
            assigner,
            format!("F_{}_square", i),
            param_f,
            fx,
            hinted_script.clone(),
            hint.clone(),
        );
        segments.extend(s);
        param_f = r;
        f = fx;

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
            let fx = f * c_inv;
            let (s, r) = make_chunk_mul(
                assigner,
                format!("F_{}_mul_c_inv", i),
                param_f,
                param_c_inv.clone(),
                f,
                c_inv,
            );
            segments.extend(s);
            param_f = r;
            f = fx;
        } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            let fx = f * c;
            let (s, r) = make_chunk_mul(
                assigner,
                format!("F_{}_mul_c", i),
                param_f,
                param_c.clone(),
                f,
                c,
            );
            segments.extend(s);
            param_f = r;
            f = fx;
        }

        // num_line_groups = 4
        for j in 0..num_line_groups {
            let p = p_lst[j];
            let coeffs = &line_coeffs[num_lines - (i + 2)][j][0];
            assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
            let mut fx = f;
            let mut c1new = coeffs.1;
            c1new.mul_assign_by_fp(&(-p.x / p.y));
            let mut c2new = coeffs.2;
            c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
            fx.mul_by_034(&coeffs.0, &c1new, &c2new);

            let coeffs_4 = if j == num_line_groups-1 {
                Some(line_coeffs_4[num_lines - (i + 2)][0].clone())
            } else {
                None
            };

            let (s, r) =  make_chunk_ell(
                assigner,
                format!("F_{}_mul_c_1p{}", i, j),
                param_f,
                im_var_p[j].clone(),
                f,
                -p.x / p.y,
                p.y.inverse().unwrap(),
                coeffs,
                coeffs_4,
            );
            
            segments.extend(s);
            param_f = r;
            f = fx;
        }

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
            || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
        {
            for j in 0..num_line_groups {
                let p = p_lst[j];
                let coeffs = &line_coeffs[num_lines - (i + 2)][j][1];
                assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
                let mut fx = f;
                let mut c1new = coeffs.1;
                c1new.mul_assign_by_fp(&(-p.x / p.y));
                let mut c2new = coeffs.2;
                c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
                fx.mul_by_034(&coeffs.0, &c1new, &c2new);

                let coeffs_4 = if j == num_line_groups-1 {
                    Some(line_coeffs_4[num_lines - (i + 2)][1].clone())
                } else {
                    None
                };
                let (s, r) = make_chunk_ell(
                    assigner,
                    format!("F_{}_mul_c_2p{}", i, j),
                    param_f,
                    im_var_p[j].clone(),
                    f,
                    -p.x / p.y,
                    p.y.inverse().unwrap(),
                    coeffs,
                    coeffs_4,
                );

                segments.extend(s);
                param_f = r;
                f = fx;
            }
        }
    }

    let c_inv_p = c_inv.frobenius_map(1);
    let (hinted_script, hint) = Fq12::hinted_frobenius_map(1, c_inv);
    let (s, r) = make_chunk_frobenius_map(
        assigner,
        "F_with_c_inv_f_m".to_string(),
        param_c_inv.clone(),
        c_inv_p,
        hinted_script.clone(),
        hint.clone(),
    );
    segments.extend(s);
    let param_c_inv_p = r;

    let fx = f * c_inv_p;
    let (s, r) = make_chunk_mul(
        assigner,
        "F_with_c_inv_mul".to_string(),
        param_f,
        param_c_inv_p.clone(),
        f,
        c_inv_p,
    );

    segments.extend(s);
    param_f = r;
    f = fx;

    let c_p2 = c.frobenius_map(2);
    let (hinted_script, hint) = Fq12::hinted_frobenius_map(2, c);
    let (s, r) = make_chunk_frobenius_map(
        assigner,
        "F_with_c_f_m".to_string(),
        param_c.clone(),
        c_p2,
        hinted_script.clone(),
        hint.clone(),
    );

    segments.extend(s);
    let param_c_p2 = r;

    let fx = f * c_p2;
    let (s, r) = make_chunk_mul(
        assigner,
        "F_with_c_mul".to_string(),
        param_f,
        param_c_p2.clone(),
        f,
        c_p2,
    );

    segments.extend(s);
    param_f = r;
    f = fx;

    let c_inv_p3 = c_inv.frobenius_map(3);
    let (hinted_script, hint) = Fq12::hinted_frobenius_map(3, c_inv);
    let (s, r) = make_chunk_frobenius_map(
        assigner,
        "F_with_c_inv3_f_m".to_string(),
        param_c_inv.clone(),
        c_inv_p3,
        hinted_script.clone(),
        hint.clone(),
    );
    segments.extend(s);
    let param_c_inv_p3 = r;

    let fx = f * c_inv_p3;
    let (s, r) = make_chunk_mul(
        assigner,
        "F_with_c_inv3_mul".to_string(),
        param_f,
        param_c_inv_p3.clone(),
        f,
        c_inv_p3,
    );

    segments.extend(s);
    param_f = r;
    f = fx;

    let fx = f * wi;
    let (s, r) = make_chunk_mul(
        assigner,
        "F_with_wi_mul".to_string(),
        param_f,
        param_wi.clone(),
        f,
        wi,
    );

    segments.extend(s);
    param_f = r;
    f = fx;

    // num_line_groups = 4
    for j in 0..num_line_groups {
        let p = p_lst[j];
        let coeffs = &line_coeffs[num_lines - 2][j][0];
        assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
        let mut fx = f;
        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&(-p.x / p.y));
        let mut c2new = coeffs.2;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
        fx.mul_by_034(&coeffs.0, &c1new, &c2new);

        let coeffs_4 = if j == num_line_groups-1 {
            Some(line_coeffs_4[num_lines - 2][0].clone())
        } else {
            None
        };

        let (s, r) = make_chunk_ell(
                assigner,
            format!("F_final_1p{}", j),
            param_f,
            im_var_p[j].clone(),
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            coeffs,
                coeffs_4,
            );

        segments.extend(s);
        param_f = r;
        f = fx;
    }

    for j in 0..num_line_groups {
        let p = p_lst[j];
        let coeffs = &line_coeffs[num_lines - 1][j][0];
        assert_eq!(coeffs.0, ark_bn254::Fq2::ONE);
        let mut fx = f;
        let mut c1new = coeffs.1;
        c1new.mul_assign_by_fp(&(-p.x / p.y));
        let mut c2new = coeffs.2;
        c2new.mul_assign_by_fp(&(p.y.inverse().unwrap()));
        fx.mul_by_034(&coeffs.0, &c1new, &c2new);

        let coeffs_4 = if j == num_line_groups-1 {
            Some(line_coeffs_4[num_lines - 1][0].clone())
        } else {
            None
        };

        let (s, r) = make_chunk_ell(
                assigner,
            format!("F_final_2p{}", j),
            param_f,
            im_var_p[j].clone(),
            f,
            -p.x / p.y,
            p.y.inverse().unwrap(),
            coeffs,
                coeffs_4,
            );

        segments.extend(s);
        param_f = r;
        f = fx;
    }

    // evaluate L3
    (segments, param_f, f)
}

#[allow(clippy::too_many_arguments)]
pub fn make_chunk_mul<T: BCAssigner>(
    assigner: &mut T,
    fn_name: String,
    param_a: Fq12Type,
    param_b: Fq12Type,
    a: ark_bn254::Fq12,
    b: ark_bn254::Fq12,
) -> (Vec<Segment>, Fq12Type) {
    let mut segments = vec![];

    let (segments_mul, c) = fq12_mul_wrapper(assigner, &fn_name, param_a, param_b, a, b);
    segments.extend(segments_mul);

    (segments, c)
}

#[allow(clippy::too_many_arguments)]
pub fn make_chunk_square<T: BCAssigner>(
    assigner: &mut T,
    fn_name: String,
    param_f: Fq12Type,
    fx: ark_bn254::Fq12,
    script: Script,
    hint: Vec<Hint>,
) -> (Vec<Segment>, Fq12Type) {
    let mut segments = vec![];
    let mut c = Fq12Type::new(assigner, &format!("{}_o_a", fn_name));
    c.fill_with_data(Fq12Data(fx));
    segments.push(
        Segment::new_with_name(fn_name, script)
            .add_parameter(&param_f)
            .add_result(&c)
            .add_hint(hint),
    );

    (segments, c)
}

#[allow(clippy::too_many_arguments)]
pub fn make_chunk_ell<T: BCAssigner>(
    assigner: &mut T,
    fn_name: String,
    pf: Fq12Type,
    pxy: Fq2Type,
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
    constant_4:Option<Fq6Type>,
) -> (Vec<Segment>, Fq12Type) {
    let mut segments = vec![];
    let (segments_mul, c) = chunk_evaluate_line(assigner, &fn_name, pf, pxy, f, x, y, constant,constant_4);
    segments.extend(segments_mul);
    (segments, c)
}


pub fn make_chunk_frobenius_map<T: BCAssigner>(
    assigner: &mut T,
    fn_name: String,
    a: Fq12Type,
    fx: ark_bn254::Fq12,
    script: Script,
    hint: Vec<Hint>,
) -> (Vec<Segment>, Fq12Type) {
    let mut segments = vec![];

    let mut c = Fq12Type::new(assigner, &format!("{}_o_a", fn_name));
    c.fill_with_data(Fq12Data(fx));
    segments.push(
        Segment::new_with_name(fn_name, script)
            .add_parameter(&a)
            .add_result(&c)
            .add_hint(hint),
    );

    (segments, c)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::fq12::Fq12;
    use crate::chunker::assigner::DummyAssigner;
    use crate::execute_script_with_inputs;

    use ark_ff::Field;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_make_chunk_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut max_stack = 0;

        let a = ark_bn254::Fq12::rand(&mut prng);
        let b = a.square();

        let (hinted_square, hints) = Fq12::hinted_square(a);

        let script = script! {
            for hint in hints.clone() {
                { hint.push() }
            }
            { Fq12::push(a) }
            { hinted_square.clone() }
            { Fq12::push(b) }
            { Fq12::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        // assert!(exec_result.success);

        max_stack = max_stack.max(exec_result.stats.max_nb_stack_items);
        println!(
            "Fq12::hinted_square: {} @ {} stack",
            hinted_square.len(),
            max_stack
        );

        println!("chunk:");
        let mut assigner = DummyAssigner::default();
        let mut pa = Fq12Type::new(&mut assigner, &format!("i_a"));
        pa.fill_with_data(Fq12Data(b));
        let (segments, _) = make_chunk_square(
            &mut assigner,
            "test".to_owned(),
            pa,
            b,
            hinted_square.clone(),
            hints.clone(),
        );
        {
            let script0 = segments[0].script(&mut assigner);
            let witness0 = segments[0].witness(&mut assigner);
            // Check the consistency between script and witness
            println!("witness0 len {}", witness0.len());
            println!("script0 len {}", script0.len());
            let res0 = execute_script_with_inputs(script0, witness0);
            println!("res0: {:}", res0);
        }
    }
}
