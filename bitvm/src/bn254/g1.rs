use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use std::cmp::min;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::treepp::{script, Script};
use super::utils::Hint;

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

    pub fn hinted_scalar_mul_by_constant_g1(
        scalar: ark_bn254::Fr,
        p: &mut ark_bn254::G1Affine,
        coeff: Vec<(ark_bn254::Fq, ark_bn254::Fq)>,
        step_p: Vec<ark_bn254::G1Affine>,
        trace: Vec<ark_bn254::G1Affine>,
    ) -> (Script, Vec<Hint>) {
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
                for _ in 0..depth {
                    let _double_coeff = coeff_iter.next().unwrap();
                    let _step = step_p_iter.next().unwrap();
                    let _point_after_double = trace_iter.next().unwrap();
                    let (double_loop_script, double_hints) = G1Affine::hinted_check_double(c);
                    loop_scripts.push(double_loop_script);
                    hints.extend(double_hints);
                    c = (c + c).into_affine();
                }
            }

            // squeeze a bucket scalar
            loop_scripts.push(script! {
                for _ in 0..depth {
                    OP_FROMALTSTACK
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
                    G1Affine::hinted_check_add(c, p_mul[mask as usize], add_coeff.0);
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

            i += i_step;
        }
        assert!(coeff_iter.next().is_none());
        assert!(step_p_iter.next().is_none());
        assert!(trace_iter.next().is_none());

        println!("debug: c:{:?}", c);
        *p = c;

        let mut script = script! {
            { Fr::convert_to_le_bits_toaltstack() }

        };

        for script_line in loop_scripts {
            script = script.push_script(script_line.compile());
        }

        (script, hints)
    }

    pub fn hinted_check_add(
        t: ark_bn254::G1Affine,
        q: ark_bn254::G1Affine,
        c3: ark_bn254::Fq,
    ) -> (Script, Vec<Hint>) {
        let mut hints = vec![];

        let (alpha, bias) = if !t.is_zero() && !q.is_zero() {
            let alpha = (t.y - q.y) / (t.x - q.x);
            let bias = t.y - alpha * t.x;
            (alpha, bias)
        } else {
            (ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO)
        };

        let (hinted_script1, hint1) = Self::hinted_check_chord_line(t, q, c3);
        let (hinted_script2, hint2) = Self::hinted_add(t.x, q.x, c3);

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
    let script_lines = vec! [
        // Stack: [hints, pyd, px, py] 
        Fq::copy(2),
        // Stack: [hints, pyd, px, py, pyd] 
        hinted_script1,
        Fq::push_one(),
        Fq::equalverify(1, 0),
        // Stack: [hints, pyd, px]
        Fq::neg(0),
        // Stack: [hints, pyd, -px]
        hinted_script2
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
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
    let script_lines = vec! [
        // [hints,..., pyd_calc, py]
        hinted_script1,
        {Fq::push_one()},
        {Fq::equalverify(1,0)}
    ];
    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
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

    let script_lines = vec![
        // [hints, yinv, x, y]
        Fq::copy(2),
        Fq::copy(1),
        hinted_script1,

        // [hints, yinv, x, y]
        Fq::copy(2),
        Fq::toaltstack(),
        hinted_script2,
        Fq::fromaltstack(),
    ];

    let mut script = script! {};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
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
    use crate::bn254::msm::prepare_msm_input;
    use crate::chunker::common::extract_witness_from_stack;
    use crate::{execute_script, execute_script_without_stack_limit, run, treepp::*};
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

        let (hinted_check_add, hints) = G1Affine::hinted_check_add(t, q, alpha);

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
    fn test_hinted_scalar_mul_by_constant_g1_affine() {
        let k = 0;
        let n = 1 << k;
        let rng = &mut test_rng();

        let scalars = (0..n).map(|_| ark_bn254::Fr::rand(rng)).collect::<Vec<_>>();

        let mut bases = (0..n)
            .map(|_| ark_bn254::G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();

        let q = bases[0].mul(scalars[0]).into_affine();
        println!("debug: expected res:{:?}", q);
        let (inner_coeffs, _) = prepare_msm_input(&bases, &scalars, 12);

        let (scalar_mul_affine_script, hints) =
            G1Affine::hinted_scalar_mul_by_constant_g1(
                scalars[0],
                &mut bases[0],
                inner_coeffs[0].0.clone(),
                inner_coeffs[0].1.clone(),
                inner_coeffs[0].2.clone(),
            );
        assert_eq!(bases[0], q);
        println!("assert success");

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fr::push(scalars[0]) }
            { scalar_mul_affine_script.clone() }
            // { Fq::push(q.y) }
            // { Fq::equalverify(1, 0) }
            // { Fq::push(q.x) }
            // { Fq::equalverify(1, 0) }
            { G1Affine::push(q) }
            { G1Affine::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script_without_stack_limit(script);
        println!("{}", exec_result.final_stack);
        assert!(exec_result.success);

        println!(
            "script size of scalar_mul_affine: {}",
            scalar_mul_affine_script.len()
        );
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

