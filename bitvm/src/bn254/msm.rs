use super::utils::Hint;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::{g1::G1Affine, fr::Fr};
use crate::treepp::*;
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};

pub fn affine_double_line_coeff(
    t: &mut ark_bn254::G1Affine,
) -> (ark_bn254::Fq, ark_bn254::Fq) {
    // alpha = 3 * t.x ^ 2 / 2 * t.y ^ 2
    // bias = t.y - alpha * t.x
    let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
    let bias = t.y - alpha * t.x;

    // update T
    // T.x = alpha^2 - 2 * t.x
    // T.y = -bias - alpha * T.x
    let tx = alpha.square() - t.x - t.x;
    t.y = -bias - alpha * tx;
    t.x = tx;

    (alpha, -bias)
}

pub fn affine_add_line_coeff(
    t: &mut ark_bn254::G1Affine,
    p: ark_bn254::G1Affine,
) -> (ark_bn254::Fq, ark_bn254::Fq) {
    // alpha = (t.y - q.y) / (t.x - q.x)
    // bias = t.y - alpha * t.x
    let alpha = (t.y - p.y) / (t.x - p.x);
    let bias = t.y - alpha * t.x;

    // update T
    // T.x = alpha^2 - t.x - q.x
    // T.y = -bias - alpha * T.x
    let tx = alpha.square() - t.x - p.x;
    t.y = -bias - alpha * tx;
    t.x = tx;

    (alpha, -bias)
}

pub fn collect_scalar_mul_coeff(
    base: ark_bn254::G1Affine,
    scalar: ark_bn254::Fr,
    i_step: u32,
) -> (
    Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
    Vec<ark_bn254::G1Affine>,
    Vec<ark_bn254::G1Affine>,
) {
    if scalar == ark_bn254::Fr::ONE {
        (vec![], vec![], vec![])
    } else {
        // precomputed lookup table (affine)
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << i_step) {
            p_mul.push((*p_mul.last().unwrap() + base).into_affine());
        }

        // split into chunks
        let chunks = scalar
            .into_bigint()
            .to_bits_be()
            .iter()
            .map(|b| if *b { 1_u8 } else { 0_u8 })
            .skip(256 - crate::bn254::fr::Fr::N_BITS as usize)
            .collect::<Vec<_>>()
            .chunks(i_step as usize)
            .map(|slice| slice.iter().fold(0, |acc, &b| (acc << 1) + b as u32))
            .collect::<Vec<u32>>();
        assert!(!chunks.is_empty());

        // query lookup table, then double/add based on that
        let mut line_coeff = vec![];
        let mut step_points = vec![];
        let mut trace = vec![];
        let mut t = p_mul[chunks[0] as usize];
        // for check variables
        let mut acc = ark_bn254::G1Projective::from(p_mul[chunks[0] as usize]);
        let mut s = ark_ff::BigInt::<4>::from(chunks[0]);
        trace.push(p_mul[chunks[0] as usize]);
        chunks.iter().skip(1).enumerate().for_each(|(idx, query)| {
            let depth = if (idx == chunks.len() - 2)
                && (crate::bn254::fr::Fr::N_BITS % i_step != 0)
            {
                crate::bn254::fr::Fr::N_BITS % i_step
            } else {
                i_step
            };
            for _ in 0..depth {
                let tmp = t;
                let double_coeff = if t.is_zero() {(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)} else {affine_double_line_coeff(&mut t)};
                line_coeff.push(double_coeff);
                step_points.push(tmp);
                assert_eq!(
                    tmp.y().unwrap_or(ark_bn254::Fq::ZERO) - double_coeff.0 * tmp.x().unwrap_or(ark_bn254::Fq::ZERO) + double_coeff.1,
                    ark_bn254::Fq::ZERO
                );
                acc.double_in_place();
                trace.push(acc.into_affine());
                s <<= 1;
            }

            let add_coeffs = if p_mul[*query as usize].is_zero() {
                (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
            } else if t.is_zero() {
                t = p_mul[*query as usize];
                (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
            } else {
                affine_add_line_coeff(&mut t, p_mul[*query as usize])
            };
            line_coeff.push(add_coeffs);
            // FOR DEBUG
            acc += ark_bn254::G1Projective::from(p_mul[*query as usize]);
            trace.push(acc.into_affine());
            // TODO: zero point can be ignored
            // if p_mul[*query as usize] != ark_bn254::G1Projective::ZERO {
            //     line_coeff.push(affine_add_line_coeff(&mut t, p_mul[*query as usize]));
            //     // FOR DEBUG
            //     acc += ark_bn254::G1Projective::from(p_mul[*query as usize]);
            // }

            // FOR DEBUG
            s.add_with_carry(&ark_ff::BigInt::<4>::from(*query));
        });
        assert_eq!(s, scalar.into_bigint());
        assert_eq!(acc.into_affine(), (base * scalar).into_affine());

        // return line coefficients of single scalar mul
        (line_coeff, step_points, trace)
    }
}

// line coefficients, denoted as tuple (alpha, bias), for the purpose of affine mode of MSM
#[allow(clippy::type_complexity)]
pub fn prepare_msm_input(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
    i_step: u32,
) -> (
    Vec<(
        Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
        Vec<ark_bn254::G1Affine>,
        Vec<ark_bn254::G1Affine>,
    )>,
    Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
) {
    let groups = bases
        .iter()
        .zip(scalars)
        .collect::<Vec<_>>();

    // inner part
    let inner_coeffs = groups
        .clone()
        .into_iter()
        .map(|(&base, &scalar)| collect_scalar_mul_coeff(base, scalar, i_step))
        .collect::<Vec<_>>();

    // outer part
    let mut acc = (*groups[0].0 * *groups[0].1).into_affine();
    let outer_coeffs = groups
        .into_iter()
        .skip(1)
        .map(|(&base, &scalar)| affine_add_line_coeff(&mut acc, (base * scalar).into_affine()))
        .collect::<Vec<_>>();

    (inner_coeffs, outer_coeffs)
}

pub fn hinted_msm_with_constant_bases_affine(
    bases: &[ark_bn254::G1Affine],
    scalars: &[ark_bn254::Fr],
) -> (Script, Vec<Hint>) {
    println!("use hinted_msm_with_constant_bases_affine");
    assert_eq!(bases.len(), scalars.len());

    let mut hints = Vec::new();

    let mut trivial_bases = vec![];
    let mut msm_bases = vec![];
    let mut msm_scalars = vec![];
    let mut msm_acc = ark_bn254::G1Affine::identity();
    for (itr, s) in scalars.iter().enumerate() {
        if *s == ark_bn254::Fr::ONE {
            trivial_bases.push(bases[itr]);
        } else {
            msm_bases.push(bases[itr]);
            msm_scalars.push(*s);
            msm_acc = (msm_acc + (bases[itr] * *s).into_affine()).into_affine();
        }
    }    

    // parameters
    let mut window = 4;
    if msm_scalars.len() == 1 {
        window = 7;
    } else if msm_scalars.len() == 2 {
        window = 5;
    }

    // MSM
    let mut acc = ark_bn254::G1Affine::zero();
    let msm_chunks = G1Affine::hinted_scalar_mul_by_constant_g1(
        msm_scalars.clone(),
        msm_bases.clone(),
        window,
    );
    let msm_chunk_hints: Vec<Hint> = msm_chunks.iter().flat_map(|f| f.2.clone()).collect();
    let msm_chunk_scripts: Vec<Script> = msm_chunks.iter().map(|f| f.1.clone()).collect();
    let msm_chunk_results: Vec<ark_bn254::G1Affine> = msm_chunks.iter().map(|f| f.0).collect();
    hints.extend_from_slice(&msm_chunk_hints);

    acc = (acc + msm_acc).into_affine();

    // Additions
    let mut add_scripts = Vec::new();
    for i in 0..trivial_bases.len() {
        // check coeffs before using
        let (add_script, hint) =
            G1Affine::hinted_check_add(acc, trivial_bases[i]); // outer_coeffs[i - 1].1
        add_scripts.push(add_script);
        hints.extend(hint);
        acc = (acc + trivial_bases[i]).into_affine();
    }

    // Gather scripts
    let script = script! {
        for i in 0..msm_chunk_scripts.len() {
            // G1Acc preimage
            if i == 0 {
                {G1Affine::push( ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO))}
            } else {
                {G1Affine::push(msm_chunk_results[i-1])}
            }

            // Scalar_i: groth16 public inputs bitcommited input irl
            for msm_scalar in &msm_scalars {
                {Fr::push(*msm_scalar)}
            }
            // [ScalarDecomposition_0, ScalarDecomposition_1,.., ScalarDecomposition_i,    G1Acc, Scalar_0, Scalar_1,..Scalar_i, ]
            {msm_chunk_scripts[i].clone()}

            {G1Affine::push(msm_chunk_results[i])}
            {G1Affine::equalverify()}
        }
        {G1Affine::push(msm_chunk_results[msm_chunk_results.len()-1])}
        // tx, ty
        for i in 0..add_scripts.len() {
            {G1Affine::push(trivial_bases[i])}
            {add_scripts[i].clone()}
        }
    };
    //println!("msm is divided into {} chunks ", msm_scripts.len() + add_scripts.len());

    (script, hints)
    // into_affine involving extreem expensive field inversion, X/Z^2 and Y/Z^3, fortunately there's no need to do into_affine any more here
}



#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::g1::G1Affine;
    use crate::execute_script_without_stack_limit;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};

    #[test]
    fn test_hinted_msm_with_constant_bases_affine_script() {
        let n = 2;
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
            { G1Affine::push(expect) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        end_timer!(start);

        println!("hinted_msm_with_constant_bases: = {} bytes", msm.len());
        let start = start_timer!(|| "execute_msm_script");
        let exec_result = execute_script_without_stack_limit(script);
        end_timer!(start);
        assert!(exec_result.success);
    }
}
