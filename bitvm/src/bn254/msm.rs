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
    let len = bases.len();
    let i_step = 12_u32;
    let (inner_coeffs, outer_coeffs) = prepare_msm_input(bases, scalars, i_step);

    let mut hints = Vec::new();
    let mut hinted_scripts = Vec::new();

    // 1. init the sum=0;
    // let mut p = ark_bn254::G1Affine::zero();
    let mut p = (bases[0] * scalars[0]).into_affine();
    for i in 0..len {
        let mut c = bases[i];
        if scalars[i] != ark_bn254::Fr::ONE {
            let (hinted_script, hint) = G1Affine::hinted_scalar_mul_by_constant_g1(
                scalars[i],
                &mut c,
                inner_coeffs[i].0.clone(),
                inner_coeffs[i].1.clone(),
                inner_coeffs[i].2.clone(),
            );
            println!("scalar mul {}: {}", i, hinted_script.len());
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
        }

        // check coeffs before using
        if i > 0 {
            let (hinted_script, hint) =
                G1Affine::hinted_check_add(p, c, outer_coeffs[i - 1].0); // outer_coeffs[i - 1].1
            hinted_scripts.push(hinted_script);
            hints.extend(hint);
            p = (p + c).into_affine();
        }
    }

    let mut hinted_scripts_iter = hinted_scripts.into_iter();
    let mut script_lines = Vec::new();

    // 1. init the sum = base[0] * scalars[0];
    // script_lines.push(G1Affine::push((bases[0] * scalars[0]).into_affine()));
    for i in 0..len {
        // 2. scalar mul
        if scalars[i] != ark_bn254::Fr::ONE {
            script_lines.push(Fr::push(scalars[i]));
            script_lines.push(hinted_scripts_iter.next().unwrap());
        } else {
            script_lines.push(G1Affine::push(bases[i]));
        }
        // 3. sum the base
        if i > 0 {
            script_lines.push(hinted_scripts_iter.next().unwrap());
        }
    }

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }

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
