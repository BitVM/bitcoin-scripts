use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField};
use num_bigint::{BigInt, BigUint, Sign};
use std::cmp::min;
use std::ops::{AddAssign, Div, Neg, Rem};
use std::str::FromStr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::utils::Hint;
use crate::treepp::{script, Script};
use num_traits::Signed;

use super::fq2::Fq2;
use super::fr;

pub struct G1Affine;

impl G1Affine {
    /// check line through one point, that is:
    ///     y - alpha * x - bias = 0
    ///
    /// input on stack:
    ///     x (1 elements)
    ///     y (1 elements)
    ///
    /// input of parameters:
    ///     c3: alpha
    ///     c4: -bias
    ///
    /// output:
    ///     true or false (consumed on stack)
    pub fn hinted_check_line_through_point(
        x: ark_bn254::Fq,
        c3: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        let (hinted_script1, hint1) = Fq::hinted_mul(1, x, 3, c3);
        let script = script! {          //c3 c4 x y
            {hinted_script1}                              //c4 y x*c3
            {Fq::sub(1, 0)}                               //c4 y-x*c3
            {Fq::add(1, 0)}                               //c4+y-x*c3
            {Fq::push_zero()}
            {Fq::equal(1, 0)}
        };

        let mut hints = vec![];
        hints.extend(hint1);
        (script, hints)
    }

    /// check whether a tuple coefficient (alpha, -bias) of a chord line is satisfied with expected points T and Q (both are affine cooordinates)
    /// two aspects:
    ///     1. T.y - alpha * T.x - bias = 0
    ///     2. Q.y - alpha * Q.x - bias = 0, make sure the alpha/-bias are the right ONEs
    ///
    /// input on stack:
    ///     T.x (1 elements)
    ///     T.y (1 elements)
    ///     Q.x (1 elements)
    ///     Q.y (1 elements)
    ///
    /// input of parameters:
    ///     c3: alpha
    ///     c4: -bias
    /// output:
    ///     true or false (consumed on stack)
    pub fn hinted_check_chord_line(
        t: ark_bn254::G1Affine,
        q: ark_bn254::G1Affine,
        c3: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let (hinted_script1, hint1) = Self::hinted_check_line_through_point(q.x, c3);
        let (hinted_script2, hint2) = Self::hinted_check_line_through_point(t.x, c3);
        let script = script! {  //c3 c4 tx ty qx qy
            {Fq::copy(5)}                       //c3 c4 tx ty qx qy c3
            {Fq::copy(5)}                       //c3 c4 tx ty qx qy c3 c4
            {Fq::roll(3)}                       //c3 c4 tx ty qy c3 c4 qx
            {Fq::roll(3)}                       //c3 c4 tx ty c3 c4 qx qy
            {hinted_script1}                    //c3 c4 tx ty (0/1)
            OP_TOALTSTACK                       //c3 c4 tx ty | (0/1)
            {hinted_script2}                    //(0/1)| (0/1)
            OP_FROMALTSTACK                     //(0/1) (0/1)
            OP_BOOLAND                          //(0/1)
        };
        hints.extend(hint1);
        hints.extend(hint2);

        (script, hints)
    }

    /// check whether a tuple coefficient (alpha, -bias) of a tangent line is satisfied with expected point T (affine)
    /// two aspects:
    ///     1. alpha * (2 * T.y) = 3 * T.x^2, make sure the alpha is the right ONE
    ///     2. T.y - alpha * T.x - bias = 0, make sure the -bias is the right ONE
    ///
    /// input on stack:
    ///     T.x (1 element)
    ///     T.y (1 element)
    ///
    /// input of parameters:
    ///     c3: alpha
    ///     c4: -bias
    ///
    /// output:
    ///     true or false (consumed on stack)
    pub fn hinted_check_tangent_line(
        t: ark_bn254::G1Affine,
        c3: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        let mut hints = vec![];

        let (hinted_script1, hint1) = Fq::hinted_mul(1, t.y + t.y, 0, c3);
        let (hinted_script2, hint2) = Fq::hinted_square(t.x);
        let (hinted_script3, hint3) = Self::hinted_check_line_through_point(t.x, c3);

        let script = script! {                    // rest of hints..., c3 (alpha), c4 (-bias), t.x t.y
            { Fq::copy(0) }                                         // alpha, -bias, x, y, y
            { Fq::double(0) }                                       // alpha, -bias, x, y, 2y
            { Fq::copy(4) }                                         // alpha, -bias, x, y, 2y, alpha
            { hinted_script1 }                                      // alpha, -bias, x, y, alpha * (2 * y)
            { Fq::copy(2) }                                         // alpha, -bias, x, y, alpha * (2 * y), x
            { hinted_script2 }                                      // alpha, -bias, x, y, alpha * (2 * y), x^2
            { Fq::copy(0) }                                         // alpha, -bias, x, y, alpha * (2 * y), x^2, x^2
            { Fq::double(0) }                                       // alpha, -bias, x, y, alpha * (2 * y), x^2, 2x^2
            { Fq::add(1, 0) }                                       // alpha, -bias, x, y, alpha * (2 * y), 3 * x^2
            { Fq::sub(1, 0) }                                       // alpha, -bias, x, y, alpha * (2 * y) - 3 * x^2
            { Fq::is_zero(0) }                                      // alpha, -bias, x, y, condition_one
            OP_TOALTSTACK                                           // alpha, -bias, x, y  alt: condition_one
            { hinted_script3 }                                      // conditon_two  alt: condition_one
            OP_FROMALTSTACK OP_BOOLAND                              // result
        };
        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);

        (script, hints)
    }

    pub fn push_zero() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn push(element: ark_bn254::G1Affine) -> Script {
        script! {
            { Fq::push_u32_le(&BigUint::from(element.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(element.y).to_u32_digits()) }
        }
    }

    pub fn read_from_stack(witness: Vec<Vec<u8>>) -> ark_bn254::G1Affine {
        assert_eq!(witness.len() as u32, Fq::N_LIMBS * 2);
        let x = Fq::read_u32_le(witness[0..Fq::N_LIMBS as usize].to_vec());
        let y = Fq::read_u32_le(
            witness[Fq::N_LIMBS as usize..2 * Fq::N_LIMBS as usize].to_vec(),
        );
        ark_bn254::G1Affine {
            x: BigUint::from_slice(&x).into(),
            y: BigUint::from_slice(&y).into(),
            infinity: false,
        }
    }

    pub fn dfs_with_constant_mul(
        index: u32,
        depth: u32,
        mask: u32,
        p_mul: &Vec<ark_bn254::G1Affine>,
    ) -> Script {
        if depth == 0 {
            return script! {
                OP_IF
                    { G1Affine::push(p_mul[(mask + (1 << index)) as usize]) }
                OP_ELSE
                    if mask == 0 {
                        { G1Affine::push_zero() }
                    } else {
                        { G1Affine::push(p_mul[mask as usize]) }
                    }
                OP_ENDIF
            };
        }

        script! {
            OP_IF
                { G1Affine::dfs_with_constant_mul(index + 1, depth - 1, mask + (1 << index), p_mul) }
            OP_ELSE
                { G1Affine::dfs_with_constant_mul(index + 1, depth - 1, mask, p_mul) }
            OP_ENDIF
        }
    }

    /// Decomposes a scalar s into k1, k2, s.t. s = k1 + lambda k2,
    pub(crate) fn calculate_scalar_decomposition(
        k: ark_bn254::Fr,
    ) -> ((u8, ark_bn254::Fr), (u8, ark_bn254::Fr)) {
        let scalar: BigInt = k.into_bigint().into();

        let scalar_decomp_coeffs: [(bool, BigUint); 4] = [
            (false, BigUint::from_str("147946756881789319000765030803803410728").unwrap()),
            (true, BigUint::from_str("9931322734385697763").unwrap()),
            (false, BigUint::from_str("9931322734385697763").unwrap()),
            (false, BigUint::from_str("147946756881789319010696353538189108491").unwrap()),
        ];
        
        let coeff_bigints: [BigInt; 4] = scalar_decomp_coeffs.map(|x| {
            BigInt::from_biguint(if x.0 { Sign::Plus } else { Sign::Minus }, x.1)
        });

        let [n11, n12, n21, n22] = coeff_bigints;

        let r = BigInt::from_biguint(Sign::Plus, BigUint::from(ark_bn254::Fr::MODULUS));

        // beta = vector([k,0]) * self.curve.N_inv
        // The inverse of N is 1/r * Matrix([[n22, -n12], [-n21, n11]]).
        // so β = (k*n22, -k*n12)/r

        let beta_1 = {
            let mut div = (&scalar * &n22).div(&r);
            let rem = (&scalar * &n22).rem(&r);
            if (&rem + &rem) > r {
                div.add_assign(BigInt::one());
            }
            div
        };
        let beta_2 = {
            let mut div = (&scalar * &n12.clone().neg()).div(&r);
            let rem = (&scalar * &n12.clone().neg()).rem(&r);
            if (&rem + &rem) > r {
                div.add_assign(BigInt::one());
            }
            div
        };

        // b = vector([int(beta[0]), int(beta[1])]) * self.curve.N
        // b = (β1N11 + β2N21, β1N12 + β2N22) with the signs!
        //   = (b11   + b12  , b21   + b22)   with the signs!

        // b1
        let b11 = &beta_1 * &n11;
        let b12 = &beta_2 * &n21;
        let b1 = b11 + b12;

        // b2
        let b21 = &beta_1 * &n12;
        let b22 = &beta_2 * &n22;
        let b2 = b21 + b22;

        let k1 = &scalar - b1;
        let k1_abs = BigUint::try_from(k1.abs()).unwrap();

        // k2
        let k2 = -b2;
        let k2_abs = BigUint::try_from(k2.abs()).unwrap();

        let k1signr = k1.sign();
        let k2signr = k2.sign();


        let mut k1sign: u8 = 0;
        if k1signr == Sign::Plus {
            k1sign = 1;
        } else if k1signr == Sign::Minus {
            k1sign = 2;
        } else {
            k1sign = 0;
        }

        let mut k2sign: u8 = 0;
        if k2signr == Sign::Plus {
            k2sign = 1;
        } else if k2signr == Sign::Minus {
            k2sign = 2;
        } else {
            k2sign = 0;
        }

        (
            (k1sign , ark_bn254::Fr::from(k1_abs)),
            (k2sign , ark_bn254::Fr::from(k2_abs)),
        )
    }

    fn hinted_fr_mul_by_constant(a: ark_bn254::Fr, constant: &ark_bn254::Fr) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let x = BigInt::from_str(&a.to_string()).unwrap();
        let y = BigInt::from_str(&constant.to_string()).unwrap();
        let modulus = &Fr::modulus_as_bigint();
        let q = (x * y) / modulus;

        let script = script! {
            for _ in 0..fr::Fr::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL // hints
            }
            { Fr::roll(1) }
            { Fr::push(*constant) }
            { Fr::tmul() }
        };
        hints.push(Hint::BigIntegerTmulLC1(q));
        (script, hints)
    }

    
    fn hinted_scalar_decomposition(k: ark_bn254::Fr) -> (Script, Vec<Hint>) {
        let lambda: ark_bn254::Fr = ark_bn254::Fr::from(BigUint::from_str("21888242871839275217838484774961031246154997185409878258781734729429964517155").unwrap());
        let (_, (_, k1)) = Self::calculate_scalar_decomposition(k);
        let (mul_scr, mul_hints) = Self::hinted_fr_mul_by_constant(k1, &lambda);
        let scr = script!{
            // [s0, k0, s1, k1, k]
            {Fr::toaltstack()}
            // [s0, k0, s1, k1]
            {Fr::N_LIMBS} OP_ROLL
            // [s0, k0, k1, s1]
            OP_TOALTSTACK
            // [s0, k0, k1]
            {mul_scr}
            // [s0, s1, k0, k1 * lambda]
            OP_FROMALTSTACK
            // [s0, k0, k1 * lambda, s1]
            {2} OP_EQUAL
            OP_IF
                {Fr::neg(0)}
            OP_ENDIF
            {Fr::toaltstack()}
    
            // [k, s0, k0]
            {Fr::N_LIMBS} OP_ROLL
            // [k, k0, s0]
            {2} OP_EQUAL
            OP_IF
                {Fr::neg(0)}
            OP_ENDIF
            {Fr::fromaltstack()}
            // [k0, k1]
            {Fr::add(1, 0)}
            {Fr::fromaltstack()}
            // [k', k]
            {Fr::equal(1, 0)} OP_VERIFY
        };
        (scr, mul_hints)
    }

    // Hint: [G1Acc, ScalarDecomposition_0, ScalarDecomposition_1,.., ScalarDecomposition_i, ]
    // Stack: [Hint, ...., Scalar_0, Scalar_1,..Scalar_i]
    // where 
    // G1Acc is initial value of accumulator 
    // Scalar_i is groth16 public input, Scalar_i < |F_r|
    // ScalarDecomposition_i is glv decomposition of scalar, => [s0, k0, s1, k1]
    // k0 and k1 are scalar elements of size < |F_r/2|
    // s0 and s1 are u32 elements which indicate sign of scalar
    // Scalar_0 = s0 * k0 + s1 * k1
    pub fn hinted_scalar_mul_by_constant_g1(
        g16_scalars: Vec<ark_bn254::Fr>,
        g16_bases: Vec<ark_bn254::G1Affine>,
        window: u32,
    ) -> Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> {
        assert_eq!(g16_scalars.len(), g16_bases.len());
        let mut all_loop_info: Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> = Vec::new();

        let mut g1acc: ark_bn254::G1Affine = ark_bn254::G1Affine::zero();
        let mut i = 0;
        let num_bits = (Fr::N_BITS + 1)/2;
        while i < num_bits {
            let (loop_result, loop_scripts, loop_hints)= Self::hinted_scalar_mul_by_constant_g1_ith_step(&mut g1acc, g16_scalars.clone(), g16_bases.clone(), window, i/window);
            i += window;
            all_loop_info.push((loop_result, loop_scripts, loop_hints.clone()));
        }
        all_loop_info
    }

    pub fn hinted_scalar_mul_by_constant_g1_ith_step(
        g1acc: &mut ark_bn254::G1Affine,
        g16_scalars: Vec<ark_bn254::Fr>,
        g16_bases: Vec<ark_bn254::G1Affine>,
        window: u32,
        ith_step: u32,
    ) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
        let mut tmp_g1acc = *g1acc;
        assert_eq!(g16_scalars.len(), g16_bases.len());

        let mut loop_scripts = script!();
        let mut loop_hints = vec![];

        // Given: g16_bases = [p0, p1]
        // Extend bases to include point endomorphism => [p0, phi(p0)..]
        // precomputed lookup table belonging to this extended list of bases
        // later msm [k0, k1..] with [p0, phi(p0)] such that product = (s0).k0 * p0 + (s1).k1 * phi(p1) = (s0.k0 + s1.k1.lambda) p = k.p
        let mut p_muls: Vec<Vec<ark_bn254::G1Affine>> = Vec::new();
        for p in g16_bases {
            let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
            p_mul.push(ark_bn254::G1Affine::zero());
            for _ in 1..(1 << window) {
                let new_v= (*p_mul.last().unwrap() + p).into_affine();
                p_mul.push(new_v);
            }
            p_muls.push(p_mul);

            // precompute phi(p)
            let endo_coeffs = BigUint::from_str(
                "21888242871839275220042445260109153167277707414472061641714758635765020556616"
            ).unwrap();
            let endo_coeffs = ark_bn254::Fq::from(endo_coeffs);
            let p = ark_bn254::G1Affine::new_unchecked(p.x * endo_coeffs, p.y);
            let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
            p_mul.push(ark_bn254::G1Affine::zero());
            for _ in 1..(1 << window) {
                let new_v= (*p_mul.last().unwrap() + p).into_affine();
                p_mul.push(new_v);
            }
            p_muls.push(p_mul);
        }    

        let mut glv_scalars: Vec<ark_bn254::Fr> = vec![];
        g16_scalars.iter().for_each(|s| {
            let ((s0, k0), (s1, k1)) = Self::calculate_scalar_decomposition(*s);
            glv_scalars.push(k0);
            glv_scalars.push(k1);

            loop_hints.push(Hint::U32(s0 as u32));
            loop_hints.push(Hint::Fr(k0));
            loop_hints.push(Hint::U32(s1 as u32));
            loop_hints.push(Hint::Fr(k1));
        });


        let segment_len = 2 * Fr::N_LIMBS as usize + 2; // [s0, k0, s1, k1]
        // prepare stack order by moving hints from top of stack
        loop_scripts = script!(
            {loop_scripts}
             // [SD0, SD1, G1Acc, K0, K1]
            for _ in 0..g16_scalars.len() {
                for _ in 0..segment_len { // bring acc from top of stack
                    OP_DEPTH OP_1SUB OP_ROLL 
                }
            }
            // [G1Acc, K0, K1, SD0, SD1]
        );
        // [G1Acc, K0, K1, 0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1]

        // Verify scalar decomposition and send verified segments to altstack
        // here segment refers to scalar decomposition [is0, sk0, 0s1, 0k1] 
        // [K0, K1,   0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1]
        let mut validate_scalar_dec_scripts: Vec<Script> = vec![];
        let mut validate_scalar_dec_hints: Vec<Hint> = vec![];
        g16_scalars.iter().rev().for_each(|s| { // reverse because we process g16_scalars from msb in double & add algorithm
            let (dec_scr, hints) = Self::hinted_scalar_decomposition(*s);
            validate_scalar_dec_hints.extend_from_slice(&hints);
            validate_scalar_dec_scripts.push(dec_scr);
        });
        loop_scripts = script!(
            {loop_scripts}
            for sitr in 0..g16_scalars.len() {
                // bring K_i to the top of stack
                for _ in 0..Fr::N_LIMBS {
                    { ((g16_scalars.len()-sitr) * segment_len) as u32 + Fr::N_LIMBS -1} OP_ROLL
                }
                // [K0, 0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1,  K1]
                {Fr::toaltstack()}
                // [K0, 0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1]
                // copy segment
                for _ in 0..segment_len {
                    {segment_len -1} OP_PICK
                }
                // [K0, 0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1, 1s0, 1k0, 1s1, 1k1]
                {Fr::fromaltstack()}
                // [K0, 0s0, 0k0, 0s1, 0k1,    1s0, 1k0, 1s1, 1k1,   1s0, 1k0, 1s1, 1k1, K1]
                // verify decomposition of K[g16_scalars.len()-sitr]
                {validate_scalar_dec_scripts[sitr].clone()}
                // Send valid segment to altstack
                for _ in 0..segment_len {
                    OP_TOALTSTACK
                }
                // [K0, 0s0, 0k0, 0s1, 0k1]
                // repeat for other batch
            }
        );
        loop_hints.extend_from_slice(&validate_scalar_dec_hints);

        
        let i = ith_step * window;
        let num_bits = (Fr::N_BITS + 1)/2; // glv scalar has half of total bits 
        let depth = min(num_bits - i, window);

        // double(step-size) point
        if i > 0 {
            for _ in 0..depth {
                let (double_loop_script, double_hints) = G1Affine::hinted_check_double(tmp_g1acc);
                loop_scripts = script!(
                    {loop_scripts}
                    {double_loop_script}
                );
                loop_hints.extend(double_hints);
                tmp_g1acc = (tmp_g1acc + tmp_g1acc).into_affine();
            }
        }
        
        for (itr, scalar) in glv_scalars.iter().enumerate() {
            // squeeze a bucket scalar
            loop_scripts = script!(
                {loop_scripts}
                OP_FROMALTSTACK // s0
                {Fr::fromaltstack()} // k0
                {fr::Fr::convert_to_le_bits_toaltstack()}
                for _ in 0..(fr::Fr::N_BITS - num_bits) { // skip zeros in msbs because k0 < |Fr/2|
                    OP_FROMALTSTACK OP_DROP
                }
                for j in 0..num_bits { 
                    OP_FROMALTSTACK
                    if j / window != i/window { // keep only bits corresponding to this window
                        OP_DROP
                    }
                }
            );

            let mut mask = 0;
            let scalar_bigint = scalar.into_bigint();
            for j in 0..depth {
                mask *= 2;
                mask += scalar_bigint.get_bit((num_bits - i - j - 1) as usize) as u32;
            }

            // lookup q:
            // here we negate Q with the sign of scalar:
            // i.e. (s0)k0 * P = k0 * (s0) P = k0 * -P is s0 indicates negative
            // s0 = {0, 1, 2} => {ZERO, POSITIVE, NEGATIVE}
            let lookup_scr = script!{
                // [s0, k0]
                {G1Affine::dfs_with_constant_mul(0, depth - 1, 0, &p_muls[itr])}
                // lookup: p_muls(k0) => G1Affine::P
                // [s0, Px0, Py0]
                {Fq::toaltstack()} {Fq::toaltstack()}
                // [s0]
                {2} OP_NUMEQUAL
                // if s0 is negative, negate P
                OP_IF 
                    {Fr::fromaltstack()} 
                    {Fr::fromaltstack()}
                    {Fr::neg(0)}
                OP_ELSE
                    {Fr::fromaltstack()} {Fr::fromaltstack()}
                OP_ENDIF
            };
            loop_scripts = script!(
                {loop_scripts}
                {lookup_scr}
            );
            // add point
            let (add_script, add_hints) =
            G1Affine::hinted_check_add(tmp_g1acc, p_muls[itr][mask as usize]);
            let add_loop = script! {
                // query bucket point through lookup table
                // check before usage
                { add_script }
            };
            loop_scripts = script!(
                {loop_scripts}
                {add_loop}
            );
            loop_hints.extend(add_hints);
            tmp_g1acc = (tmp_g1acc + p_muls[itr][mask as usize]).into_affine();
        }

        *g1acc = tmp_g1acc;
        (tmp_g1acc, loop_scripts, loop_hints)
    }



    pub fn hinted_check_add(
        t: ark_bn254::G1Affine,
        q: ark_bn254::G1Affine,
    ) -> (Script, Vec<Hint>) {
        let mut hints = vec![];

        let (alpha, bias) = if !t.is_zero() && !q.is_zero() {
            let alpha = (t.y - q.y) / (t.x - q.x);
            let bias = t.y - alpha * t.x;
            (alpha, bias)
        } else {
            (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
        };

        let (hinted_script1, hint1) = Self::hinted_check_chord_line(t, q, alpha);
        let (hinted_script2, hint2) = Self::hinted_add(t.x, q.x, alpha);

        let script = script! {        // tx ty qx qy
            { G1Affine::is_zero_keep_element() }
            OP_IF
                { G1Affine::drop() }
            OP_ELSE
                { G1Affine::roll(1) }
                { G1Affine::is_zero_keep_element() }
                OP_IF
                    { G1Affine::drop() }
                OP_ELSE                                // qx qy tx ty
                    for _ in 0..Fq::N_LIMBS {
                        OP_DEPTH OP_1SUB OP_ROLL
                    }
                    for _ in 0..Fq::N_LIMBS {
                        OP_DEPTH OP_1SUB OP_ROLL
                    }                                  // qx qy tx ty c3 c4
                    { Fq::copy(1) }
                    { Fq::copy(1) }                    // qx qy tx ty c3 c4 c3 c4
                    { Fq::copy(5) }
                    { Fq::roll(5) }                    // qx qy tx c3 c4 c3 c4 tx ty
                    { Fq::copy(8) }
                    { Fq::roll(8) }                    // qx tx c3 c4 c3 c4 tx ty qx qy
                    { hinted_script1 }                 // qx tx c3 c4 0/1
                    OP_VERIFY
                    { Fq::roll(2) }
                    { Fq::roll(3) }                    // c3 c4 tx qx
                    { hinted_script2 }                 // x' y'
                OP_ENDIF
            OP_ENDIF
        };

        if !t.is_zero() && !q.is_zero() {
            hints.push(Hint::Fq(alpha));
            hints.push(Hint::Fq(-bias));
            hints.extend(hint1);
            hints.extend(hint2);
        }

        (script, hints)
    }

    /// add two points T and Q
    ///     x' = alpha^2 - T.x - Q.x
    ///     y' = -bias - alpha * x'
    ///
    /// input on stack:
    ///     T.x (1 elements)
    ///     Q.x (1 elements)
    ///
    /// input of parameters:
    ///     c3: alpha - line slope
    ///     c4: -bias - line intercept
    ///
    /// output on stack:
    ///     T'.x (1 elements)
    ///     T'.y (1 elements)
    pub fn hinted_add(
        tx: ark_bn254::Fq,
        qx: ark_bn254::Fq,
        c3: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();
        let var1 = c3.square(); //alpha^2
        let var2 = var1 - qx - tx; // calculate x' = alpha^2 - T.x - Q.x
                                   //let var3 = var2 * c3; //  alpha * x'

        let (hinted_script1, hint1) = Fq::hinted_square(c3);
        let (hinted_script2, hint2) = Fq::hinted_mul(2, c3, 0, var2);
        hints.extend(hint1);
        hints.extend(hint2);

        let script = script! {        //c3 c4 tx qx
            {Fq::add(1, 0)}                             //c3 c4 (tx+qx)
            {Fq::roll(2)}                               //c4 (qx+tx) c3
            {Fq::copy(0)}                               //c4 (qx+tx) c3 c3
            {hinted_script1}                            //c4 (qx+tx) c3 c3^2
            {Fq::sub(0, 2)}                             //c4 c3 c3^2-(qx+tx)
            {Fq::copy(0)}                               //c4 c3 var2 var2
            {hinted_script2}                            //c4 var2 var2*c3
            {Fq::sub(2, 0)}                             //var2 -var2*c3+c4
        };

        (script, hints)
    }

    /// double a point T:
    ///     x' = alpha^2 - 2 * T.x
    ///     y' = -bias - alpha* x'
    ///
    /// input on stack:
    ///     T.x (1 elements)
    ///
    /// output on stack:
    ///     T'.x (1 elements)
    ///     T'.y (1 elements)
    pub fn hinted_double(t: ark_bn254::G1Affine, c3: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let mut hints = Vec::new();

        let var1 = c3.square(); //alpha^2
        let var2 = var1 - t.x - t.x; // calculate x' = alpha^2 - 2 * T.x

        let (hinted_script1, hint1) = Fq::hinted_square(c3);
        let (hinted_script2, hint2) = Fq::hinted_mul(2, c3, 0, var2);
        hints.extend(hint1);
        hints.extend(hint2);

        let script = script! {  // c3 (alpha), c4 (-bias), x
            { Fq::double(0) }                     // alpha, -bias, 2x
            { Fq::roll(2) }                       // -bias, 2x, alpha
            { Fq::copy(0) }                       // -bias, 2x, alpha, alpha
            { hinted_script1 }                    // -bias, 2x, alpha, alpha^2
            { Fq::sub(0, 2) }                     // -bias, alpha, alpha^2-2x = x'
            { Fq::copy(0) }                       // -bias, alpha, x', x'
            { hinted_script2 }                    // -bias, x', alpha * x'
            { Fq::sub(2, 0) }                     // x', -alpha * x' - bias = y'
        };

        (script, hints)
    }

    pub fn hinted_check_double(t: ark_bn254::G1Affine) -> (Script, Vec<Hint>) {
        let mut hints = vec![];

        let (alpha, bias) = if t.is_zero() {
            (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
        } else {
            let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
            let bias = t.y - alpha * t.x;
            (alpha, bias)
        };

        let (hinted_script1, hint1) = Self::hinted_check_tangent_line(t, alpha);
        let (hinted_script2, hint2) = Self::hinted_double(t, alpha);

        if !t.is_zero() {
            hints.push(Hint::Fq(alpha));
            hints.push(Hint::Fq(-bias));
            hints.extend(hint1);
            hints.extend(hint2);
        }
        let script = script! {
            { G1Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
            OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
                for _ in 0..Fq::N_LIMBS {
                    OP_DEPTH OP_1SUB OP_ROLL
                }                                        // -bias, ...,  x, y, alpha
                for _ in 0..Fq::N_LIMBS {
                    OP_DEPTH OP_1SUB OP_ROLL
                }                                        // x, y, alpha, -bias
                { Fq::copy(1) }                          // x, y, alpha, -bias, alpha
                { Fq::copy(1) }                          // x, y, alpha, -bias, alpha, -bias
                { Fq::copy(5) }                          // x, y, alpha, -bias, alpha, -bias, x
                { Fq::roll(5) }                          // x, alpha, -bias, alpha, -bias, x, y
                { hinted_script1 }                       // x, alpha, -bias, is_tangent_line_correct
                OP_VERIFY                                // x, alpha, -bias
                { Fq::roll(2) }                          // alpha, -bias, x
                { hinted_script2 }                       // x', y'
            OP_ENDIF
        };
        (script, hints)
    }

    pub fn identity() -> Script {
        script! {
            { Fq::push_zero() }
            { Fq::push_zero() }
        }
    }

    pub fn hinted_is_on_curve(x: ark_bn254::Fq, y: ark_bn254::Fq) -> (Script, Vec<Hint>) {
        let (x_sq, x_sq_hint) = Fq::hinted_square(x);
        let (x_cu, x_cu_hint) = Fq::hinted_mul(0, x, 1, x*x);
        let (y_sq, y_sq_hint) = Fq::hinted_square(y);

        let mut hints = Vec::new();
        hints.extend(x_sq_hint);
        hints.extend(x_cu_hint);
        hints.extend(y_sq_hint);
        let scr = script! {
            { Fq::copy(1) }
            { x_sq }
            { Fq::roll(2) }
            { x_cu }
            { Fq::push_hex("3") }
            { Fq::add(1, 0) }
            { Fq::roll(1) }
            { y_sq }
            { Fq::equal(1, 0) }
        };
        (scr, hints)
    }

    // Init stack: [x1,y1,x2,y2)
    pub fn equalverify() -> Script {
        script! {
            { Fq::roll(2) }
            { Fq::equalverify(1, 0) }
            { Fq::equalverify(1, 0) }
        }
    }

    pub fn is_zero() -> Script {
        script! {
            { Fq::is_zero(0) }
            OP_TOALTSTACK
            { Fq::is_zero(0) }
            OP_FROMALTSTACK
            OP_BOOLAND
        }
    }

    pub fn is_zero_keep_element() -> Script {
        script! {
            { Fq::is_zero_keep_element(0) }
            OP_TOALTSTACK
            { Fq::is_zero_keep_element(1) }
            OP_FROMALTSTACK
            OP_BOOLAND
        }
    }

    pub fn drop() -> Script {
        script! {
            { Fq::drop() }
            { Fq::drop() }
        }
    }

    pub fn roll(mut a: u32) -> Script {
        a *= 2;
        script! {
            { Fq::roll(a + 1) }
            { Fq::roll(a + 1) }
        }
    }
}

/// input of func (params):
///      p.x, p.y
/// Input Hints On Stack
///      tmul hints, p.y_inverse
/// output on stack:
///      x' = -p.x / p.y
pub fn hinted_x_from_eval_point(p: ark_bn254::G1Affine, py_inv: ark_bn254::Fq) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq::hinted_mul(1, p.y, 0, py_inv);
    let (hinted_script2, hint2) = Fq::hinted_mul(1, py_inv, 0, -p.x);
    let script = script!{   // Stack: [hints, pyd, px, py] 
        {Fq::copy(2)}                        // Stack: [hints, pyd, px, py, pyd] 
        {hinted_script1}
        {Fq::push_one()}
        {Fq::equalverify(1, 0)}              // Stack: [hints, pyd, px]
        {Fq::neg(0)}                        // Stack: [hints, pyd, -px]
        {hinted_script2}
    };
    hints.extend(hint1);
    hints.extend(hint2);
    (script, hints)
}

/// input of func (params):
///      p.y
/// Input Hints On Stack
///      tmul hints, p.y_inverse
/// output on stack:
///      []
pub fn hinted_y_from_eval_point(py: ark_bn254::Fq, py_inv: ark_bn254::Fq) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();


    let (hinted_script1, hint1) = Fq::hinted_mul(1, py_inv, 0, py);
    let script = script!{// [hints,..., pyd_calc, py]
        {hinted_script1}
        {Fq::push_one()}
        {Fq::equalverify(1,0)}
    };
    hints.extend(hint1);

    (script, hints)
}

/// input of func (params):
///      p.x, p.y
/// Input Hints On Stack
///      tmul hints, p.y_inverse
/// output on stack:
///      x' = -p.x / p.y
///      y' = 1 / p.y
pub fn hinted_from_eval_point(p: ark_bn254::G1Affine) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let py_inv = p.y().unwrap().inverse().unwrap();

    let (hinted_script1, hint1) = hinted_y_from_eval_point(p.y, py_inv);
    let (hinted_script2, hint2) = hinted_x_from_eval_point(p, py_inv);
    let script = script! {

        // [hints, yinv, x, y]
        {Fq::copy(2)}
        {Fq::copy(1)}

        {hinted_script1}

        // [hints, yinv, x, y]
        {Fq::copy(2)}
        {Fq::toaltstack()}
        {hinted_script2}
        {Fq::fromaltstack()}
    };
    hints.extend(hint1);
    hints.extend(hint2);

    (script, hints)
}

pub fn hinted_from_eval_points(p: ark_bn254::G1Affine) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let py_inv = p.y().unwrap().inverse().unwrap();

    let (hinted_script1, hint1) = hinted_y_from_eval_point(p.y, py_inv);
    let (hinted_script2, hint2) = hinted_x_from_eval_point(p, py_inv);

    let script = script!{
        // [yinv, hints,.., x, y]
        {Fq2::toaltstack()}
        for _ in 0..Fq::N_LIMBS {
            OP_DEPTH OP_1SUB OP_ROLL 
        }
        {Fq2::fromaltstack()}
        // [hints, yinv, x, y]
        {Fq::copy(2)}
        {Fq::copy(1)}
        {hinted_script1}
        // [hints, yinv, x, y]
        {Fq::copy(2)}
        {Fq::toaltstack()}
        {hinted_script2}
        {Fq::fromaltstack()}
    };


    hints.push(Hint::Fq(py_inv));
    hints.extend(hint1);
    hints.extend(hint2);

    (script, hints)
}

#[cfg(test)]
mod test {
    use crate::bn254::fq2::Fq2;
    use crate::bn254::g1::G1Affine;
    use crate::bn254::g2::G2Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fr::Fr;
    
    use crate::chunker::common::extract_witness_from_stack;
    use crate::{execute_script_without_stack_limit, treepp::*};
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use core::ops::Mul;
    use num_bigint::BigUint;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_read_from_stack() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let a = ark_bn254::G1Affine::rand(&mut prng);
        let script = script! {
            {G1Affine::push(a)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_a = G1Affine::read_from_stack(witness);

        assert_eq!(a, recovered_a);

        let b = ark_bn254::G2Affine::rand(&mut prng);
        let script = script! {
            {G2Affine::push(b)}
        };

        let res = execute_script(script);
        let witness = extract_witness_from_stack(res);
        let recovered_b = G2Affine::read_from_stack(witness);

        assert_eq!(b, recovered_b);
    }

    #[test]
    fn test_affine_identity() {
        let equalverify = G1Affine::equalverify();
        println!("G1Affine.equalverify: {} bytes", equalverify.len());

        for _ in 0..1 {
            let expect = ark_bn254::G1Affine::identity();

            let script = script! {
                { G1Affine::identity() }
                { G1Affine::push(expect) }
                { equalverify.clone() }
                OP_TRUE
            };
            println!("curves::test_affine_identity = {} bytes", script.len());
            run(script);
        }
    }

    #[test]
    fn test_g1_affine_hinted_check_line_through_point() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let (hinted_check_line_through_point, hints) =
            G1Affine::hinted_check_line_through_point(t.x, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push(alpha) }
            { Fq::push(bias_minus) }
            { Fq::push(t.x) }
            { Fq::push(t.y) }
            { hinted_check_line_through_point.clone()}
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line_through_point: {} @ {} stack",
            hinted_check_line_through_point.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_g1_affine_hinted_check_chord_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let (hinted_check_chord_line, hints) = G1Affine::hinted_check_chord_line(t, q, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push(alpha) }
            { Fq::push(bias_minus) }
            { Fq::push(t.x) }
            { Fq::push(t.y) }
            { Fq::push(q.x) }
            { Fq::push(q.y) }
            { hinted_check_chord_line.clone()}
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_chord_line: {} @ {} stack",
            hinted_check_chord_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_g1_affine_hinted_add() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add, hints) = G1Affine::hinted_add(t.x, q.x, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push(alpha) }
            { Fq::push(bias_minus) }
            { Fq::push(t.x) }
            { Fq::push(q.x) }
            { hinted_add.clone() }
            // [x']
            { Fq::push(y) }
            // [x', y', y]
            { Fq::equalverify(1,0) }
            // [x']
            { Fq::push(x) }
            // [x', x]
            { Fq::equalverify(1,0) }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_g1_affine_hinted_check_add() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_add, hints) = G1Affine::hinted_check_add(t, q);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push(t.x) }
            { Fq::push(t.y) }
            { Fq::push(q.x) }
            { Fq::push(q.y) }
            { hinted_check_add.clone() }
            // [x']
            { Fq::push(y) }
            // [x', y', y]
            { Fq::equalverify(1,0) }
            // [x']
            { Fq::push(x) }
            // [x', x]
            { Fq::equalverify(1,0) }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_g1_affine_hinted_check_double() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - t.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_double, hints) = G1Affine::hinted_check_double(t);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq::push(t.x) }
            { Fq::push(t.y) }
            { hinted_check_double.clone() }
            { Fq::push(y) }
            { Fq::equalverify(1,0) }
            { Fq::push(x) }
            { Fq::equalverify(1,0) }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_double: {} @ {} stack",
            hinted_check_double.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_hinted_scalar_decomposition() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let lambda: ark_bn254::Fr = ark_bn254::Fr::from(BigUint::from_str("21888242871839275217838484774961031246154997185409878258781734729429964517155").unwrap());
        let k = ark_bn254::Fr::rand(&mut prng);

        let dec = G1Affine::calculate_scalar_decomposition(k);
        let  ((is_k1_positive, k1), (is_k2_positive, k2)) = dec;
        let (is_k1_positive, is_k2_positive) = (is_k1_positive != 2, is_k2_positive != 2);

        if is_k1_positive && is_k2_positive {
            assert_eq!(k1 + k2 * lambda, k);
        }
        if is_k1_positive && !is_k2_positive {
            assert_eq!(k1 - k2 * lambda, k);
        }
        if !is_k1_positive && is_k2_positive {
            assert_eq!(-k1 + k2 * lambda, k);
        }
        if !is_k1_positive && !is_k2_positive {
            assert_eq!(-k1 - k2 * lambda, k);
        }
        // check if k1 and k2 are indeed small.
        let expected_max_bits = (ark_bn254::Fr::MODULUS_BIT_SIZE + 1) / 2;
        assert!(
            k1.into_bigint().num_bits() <= expected_max_bits,
            "k1 has {} bits",
            k1.into_bigint().num_bits()
        );
        assert!(
            k2.into_bigint().num_bits() <= expected_max_bits,
            "k2 has {} bits",
            k2.into_bigint().num_bits()
        );

        let (dec_scr, hints) = G1Affine::hinted_scalar_decomposition(k);
        let scr = script!{
            for hint in hints {
                {hint.push()}
            }
            {is_k1_positive as u32}
            {Fr::push(k1)}
            {is_k2_positive as u32}
            {Fr::push(k2)}
            {Fr::push(k)}
            {dec_scr}
            OP_TRUE
        };

        let res = execute_script(scr);
        println!("max stack {:?}", res.stats.max_nb_stack_items);
        assert!(res.final_stack.len() == 1);
        assert!(res.success);
    }


    #[test]
    fn test_hinted_scalar_mul_by_constant_g1_affine() {
        let n = 1;
        let window = 7;

        let rng = &mut test_rng();
        let g16_scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();
        let g16_bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
 
        let all_loop_info =
            G1Affine::hinted_scalar_mul_by_constant_g1(
                g16_scalars.clone(),
                g16_bases.clone(),
                window as u32,
            );

        let mut prev_acc = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO);
        for (itr, (output_acc, scalar_mul_affine_script, hints)) in all_loop_info.iter().enumerate() {
            
            let script = script! {
                for hint in hints { // tmul + aux hints
                    { hint.push() }
                }
                // G1Acc preimage
                {G1Affine::push(prev_acc)}
                for scalar in g16_scalars.iter() {
                    { Fr::push(*scalar) } // scalar bit committed
                }
                { scalar_mul_affine_script.clone() }
                {Fq::push(output_acc.x)}
                {Fq::push(output_acc.y)}
                { G1Affine::equalverify() }
                OP_TRUE
            };
            prev_acc = *output_acc;
            let exec_result = execute_script_without_stack_limit(script);
            println!(
                "chunk {} script size: {} max_stack {}",
                itr, scalar_mul_affine_script.len(), exec_result.stats.max_nb_stack_items
            );
            assert!(exec_result.success && exec_result.final_stack.len() == 1);
        }
    }

    
    #[test]
    fn test_affine_equalverify() {
        let equalverify = G1Affine::equalverify();
        println!("G1Affine.equalverify: {} bytes", equalverify.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = ark_bn254::Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            let q = p.into_affine();

            let script = script! {
                { G1Affine::push(p.into_affine()) }
                { G1Affine::push(q) }
                { equalverify.clone() }
                OP_TRUE
            };
            println!("curves::test_equalverify = {} bytes", script.len());
            run(script);
        }
    }

    #[test]
    fn test_hinted_affine_is_on_curve() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let p = ark_bn254::G1Affine::rand(&mut prng);
            let (affine_is_on_curve, hints) = G1Affine::hinted_is_on_curve(p.x, p.y);

            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq::push(p.x) }
                { Fq::push(p.y) }
                { affine_is_on_curve.clone() }
            };
            let res = execute_script(script);
            assert!(res.success);

            let (affine_is_on_curve, hints) = G1Affine::hinted_is_on_curve(p.x, p.y + p.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq::push(p.x) }
                { Fq::push(p.y) }
                { Fq::double(0) }
                { affine_is_on_curve.clone() }
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);
        }
    }

    #[test]
    fn test_hinted_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (eval_scr, hints) = hinted_from_eval_point(p);
        let pyinv = p.y.inverse().unwrap();

        let script = script! {
            for tmp in hints {
                { tmp.push() }
            }
            { Fq::push_u32_le(&BigUint::from(pyinv).to_u32_digits()) } // aux hint

            { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) } // input
            { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
            { eval_scr }
            { Fq::push_u32_le(&BigUint::from(-p.x / p.y).to_u32_digits()) } // expected output
            { Fq::push_u32_le(&BigUint::from(pyinv).to_u32_digits()) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
    

    #[test]
    fn test_hintedx_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (ell_by_constant_affine_script, hints) = hinted_x_from_eval_point(p, p.y.inverse().unwrap());
        let script = script! {
            for tmp in hints { 
                { tmp.push() }
            }
            { Fq::push_u32_le(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
            { ell_by_constant_affine_script.clone() }
            { Fq::push_u32_le(&BigUint::from(-p.x / p.y).to_u32_digits()) }
            {Fq::equalverify(1,0)}
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }

    #[test]
    fn test_hintedy_from_eval_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (ell_by_constant_affine_script, hints) = hinted_y_from_eval_point(p.y, p.y.inverse().unwrap());
        let script = script! {
            for tmp in hints { 
                { tmp.push() }
            }
            { Fq::push_u32_le(&BigUint::from(p.y.inverse().unwrap()).to_u32_digits()) }
            { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
            { ell_by_constant_affine_script.clone() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
    }
}
