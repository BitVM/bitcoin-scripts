use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq12::Fq12;
use crate::bn254::ell_coeffs::EllCoeff;
use crate::bn254::ell_coeffs::G2Prepared;
use crate::treepp::{script, Script};
use super::utils::Hint;
use ark_ff::{AdditiveGroup, Field};
use num_bigint::BigUint;
use std::str::FromStr;
use ark_ec::bn::BnConfig;

pub struct G2Affine;

//B = Fq2(19485874751759354771024239261021720505790618469301721065564631296452457478373,
//266929791119991161246907387137283842545076965332900288569378510910307636690)
impl G2Affine {

    pub fn is_zero_keep_element() -> Script {
        // [px0, px1, qx0, qx1]
        script! (
            for i in 0..4 {
                {Fq::copy(i)}
                {Fq::is_zero(0)}
                OP_TOALTSTACK
            }
            {1}
            for _ in 0..4 {
                OP_FROMALTSTACK
                OP_BOOLAND
            }
        )
    }

    pub fn drop() -> Script {
        script! {
            { Fq2::drop() }
            { Fq2::drop() }
        }
    }

    pub fn roll(mut a: u32) -> Script {
        a *= 4;
        script! {
            { Fq::roll(a + 3) }
            { Fq::roll(a + 3) }
            { Fq::roll(a + 3) }
            { Fq::roll(a + 3) }
        }
    }

    // [ax, ay, bx, by]
    pub fn copy(mut a: u32) -> Script {
        a *= 4;
        script! {
            { Fq::copy(a + 3) }
            { Fq::copy(a + 3) }
            { Fq::copy(a + 3) }
            { Fq::copy(a + 3) }
        }
    }

    // [ax, ay, bx, by, a'x, a'y, b'x, b'y]
    pub fn equal() -> Script {
        script! {
            {Fq2::roll(4)}
            {Fq2::equal()}
            OP_TOALTSTACK
            {Fq2::equal()}
            OP_FROMALTSTACK
            OP_BOOLAND
        }
    }

    pub fn toaltstack() -> Script {
        script! {
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}
        }
    }

    pub fn fromaltstack() -> Script {
        script! {
            {Fq2::fromaltstack()}
            {Fq2::fromaltstack()}
        }
    }

    pub fn hinted_is_on_curve(x: ark_bn254::Fq2, y: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
        let (x_sq, x_sq_hint) = Fq2::hinted_square(x);
        let (x_cu, x_cu_hint) = Fq2::hinted_mul(0, x, 2, x*x);
        let (y_sq, y_sq_hint) = Fq2::hinted_square(y);

        let mut hints = Vec::new();
        hints.extend(x_sq_hint);
        hints.extend(x_cu_hint);
        hints.extend(y_sq_hint);

        let scr = script! {
            { Fq2::copy(2) }
            { x_sq }
            { Fq2::roll(4) }
            { x_cu }
            { Fq::push_dec("19485874751759354771024239261021720505790618469301721065564631296452457478373") }
            { Fq::push_dec("266929791119991161246907387137283842545076965332900288569378510910307636690") }
            { Fq2::add(2, 0) }
            { Fq2::roll(2) }
            { y_sq }
            { Fq2::equal() }
        };
        (scr, hints)
    }

    pub fn push(element: ark_bn254::G2Affine) -> Script {
        script! {
            { Fq2::push(element.x) }
            { Fq2::push(element.y) }
        }
    }

    pub fn read_from_stack(witness: Vec<Vec<u8>>) -> ark_bn254::G2Affine {
        assert_eq!(witness.len() as u32, Fq::N_LIMBS * 4);
        let x = Fq2::read_from_stack(witness[0..2 * Fq::N_LIMBS as usize].to_vec());
        let y = Fq2::read_from_stack(
            witness[2 * Fq::N_LIMBS as usize..4 * Fq::N_LIMBS as usize].to_vec(),
        );
        ark_bn254::G2Affine {
            x,
            y,
            infinity: false,
        }
    }
}

        // Stack: [q] q /in G2Affine
    // compute q' = (q.x*beta_22, q.y) 
    pub fn hinted_mul_by_char_on_phi_q(q: ark_bn254::G2Affine) -> (ark_bn254::G2Affine, Script, Vec<Hint>) {
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
    
        let mut qq = q;
        let (beta22_mul, hints) = Fq2::hinted_mul(2, q.x, 0, beta_22);
        qq.x *= beta_22;

        let scr = script!{
            // [q.x, q.y]
            {Fq2::toaltstack()}
            {Fq2::push(beta_22)} // beta_22
            {beta22_mul}
            {Fq2::fromaltstack()}
        };
        (qq, scr, hints)
    }

    // Stack: [q] q /in G2Affine
    // compute q' = (q.x.conjugate()*beta_12, q.y.conjugate() * beta_13)
    pub fn hinted_mul_by_char_on_q(q: ark_bn254::G2Affine) -> (ark_bn254::G2Affine, Script, Vec<Hint>) {
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

        let mut qq = q;
        qq.x.conjugate_in_place();
        let (beta12_mul_scr, hint_beta12_mul) = Fq2::hinted_mul(2, qq.x, 0, beta_12);
        qq.x *= beta_12;

        qq.y.conjugate_in_place();
        let (beta13_mul_scr, hint_beta13_mul) = Fq2::hinted_mul(2, qq.y, 0, beta_13);
        qq.y *= beta_13;

        let mut frob_hint: Vec<Hint> = vec![];
        for hint in hint_beta13_mul {
            frob_hint.push(hint);
        }
        for hint in hint_beta12_mul {
            frob_hint.push(hint);
        }

        let scr = script!{
            // [q.x, q.y]
            {Fq::neg(0)}
            {Fq2::push(beta_13)} // beta_13
            {beta13_mul_scr}
            {Fq2::toaltstack()}
            {Fq::neg(0)}
            {Fq2::push(beta_12)} // beta_12
            {beta12_mul_scr}
            {Fq2::fromaltstack()}
        };
        (qq, scr, frob_hint)
    }

    

pub fn hinted_ell_by_constant_affine_and_sparse_mul(
    f: ark_bn254::Fq12,
    x: ark_bn254::Fq,
    y: ark_bn254::Fq,
    constant: &EllCoeff,
) -> (Script, Vec<Hint>) {
    assert_eq!(constant.0, ark_bn254::Fq2::ONE);
    let mut hints = Vec::new();

    let (hinted_script_ell, hint_ell) = hinted_ell_by_constant_affine(x, y, constant.1, constant.2);

    let mut c1 = constant.1;
    c1.mul_assign_by_fp(&x);
    let mut c2 = constant.2;
    c2.mul_assign_by_fp(&y);
    let (hinted_script5, hint5) = Fq12::hinted_mul_by_34(f, c1, c2);

    let hinted_script_constant = script! {
        for _ in 0..4 {
            for _ in 0..Fq::N_LIMBS {
                OP_DEPTH OP_1SUB OP_ROLL 
            }  
        }
     };
    let script = script! {
        {hinted_script_constant}
         // // [slope, bias, f,  x', y']
         // {Fq2::roll(16)}, {Fq2::roll(16)},
         // [f, x', y', slope, bias]
         {Fq2::roll(4)}
         // [f, slope, bias, x', y']
         {hinted_script_ell}
         // [f, c1', c2']
         // compute the new f with c1'(c3) and c2'(c4), where c1 is trival value 1
         {hinted_script5}
         // [f]
    };

    hints.extend_from_slice(&[Hint::Fq(constant.1.c0),
        Hint::Fq(constant.1.c1),
        Hint::Fq(constant.2.c0),
        Hint::Fq(constant.2.c1)]);

    hints.extend(hint_ell);
    hints.extend(hint5);


    (script, hints)
}

// input:
//  f            12 elements
//  p.x          1 element
//  p.y          1 element
//
// output:
//  new f        12 elements
pub fn hinted_ell_by_constant_affine(x: ark_bn254::Fq, y: ark_bn254::Fq, slope: ark_bn254::Fq2, bias: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script1, hint1) = Fq::hinted_mul(1, x, 0, slope.c0);
    let (hinted_script2, hint2) = Fq::hinted_mul(1, x, 0, slope.c1);
    let (hinted_script3, hint3) = Fq::hinted_mul(1, y, 0, bias.c0);
    let (hinted_script4, hint4) = Fq::hinted_mul(1, y, 0, bias.c1);

    let script = script!{
        // [slope, bias, x', y']
        // update c1, c1' = x' * c1
        {Fq::copy(1)}
        // [slope0, slope1, bias0, bias1, x', y', x']
        {Fq::roll(6)}
        // [slope1, bias0, bias1, x', y', x', slope0]
        {hinted_script1}
        // [slope1, bias0, bias1, x', y', x'* slope0]

        {Fq::roll(2)}
        // [slope1, bias0, bias1, y', x'* slope0, x']
        {Fq::roll(5)}
        // [bias0, bias1, y', x'* slope0, x', slope1]
        {hinted_script2}
        // [bias0, bias1, y', x'* slope0, x'* slope1]

        // update c2, c2' = -y' * c2
        {Fq::copy(2)}
        // [bias0, bias1, y', x'* slope0, x'* slope1, y']
        {Fq::roll(5)}
        // [bias1, y', x'* slope0, x'* slope1, y', bias0]
        {hinted_script3}  
        // [bias1, y', x'* slope0, x'* slope1, y'*bias0]
        {Fq::roll(3)}
        // [bias1, x'* slope0, x'* slope1, y'*bias0, y']
        {Fq::roll(4)}
        // [x'* slope0, x'* slope1, y'*bias0, y', bias1]
        {hinted_script4}
        // [x'* slope0, x'* slope1, y'*bias0, y'* bias1]
    };
 
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);
    hints.extend(hint4);
    
    (script, hints)

}

pub fn collect_line_coeffs(
    constants: Vec<G2Prepared>,
) -> Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>> {
    let mut constant_iters = constants
        .iter()
        .map(|item| item.ell_coeffs.iter())
        .collect::<Vec<_>>();
    let mut all_line_coeffs = vec![];

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        let mut line_coeffs = vec![];
        for constant in &mut constant_iters {
            // double line coeff
            let mut line_coeff = vec![];
            line_coeff.push(*constant.next().unwrap());
            // add line coeff
            if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1
                || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1
            {
                line_coeff.push(*constant.next().unwrap());
            }
            // line coeff for single point
            line_coeffs.push(line_coeff);
        }
        // line coeffs for all points
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for constant in &mut constant_iters {
            // add line coeff
            line_coeffs.push(vec![*constant.next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    {
        let mut line_coeffs = vec![];
        for constant in &mut constant_iters {
            // add line coeff
            line_coeffs.push(vec![*constant.next().unwrap()]);
        }
        all_line_coeffs.push(line_coeffs);
    }
    for constant in &mut constant_iters {
        assert_eq!(constant.next(), None);
    }
    assert_eq!(
        all_line_coeffs.len(),
        ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 + 2
    );
    all_line_coeffs
}

/// add two points T and Q
///     x' = alpha^2 - T.x - Q.x
///     y' = -bias - alpha * x'
///
/// input on stack:
///     T.x (2 elements)
///     Q.x (2 elements)
///
/// input of parameters:
///     c3: alpha - line slope
///     c4: -bias - line intercept
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn hinted_affine_add_line(
    tx: ark_bn254::Fq2,
    qx: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hinted_script0, hint0) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square() - tx - qx);

    let script = script! {
        // [c3, c4, T.x, Q.x]
        {Fq2::neg(0)}
        // [c3, c4,T.x, -Q.x]
        {Fq2::roll(2)}
        // [c3, c4,-Q.x, T.x]
        {Fq2::neg(0)}
        // [c3, c4, -Q.x. -T.x]
        {Fq2::add(2, 0)}
        // [c3, c4, -T.x - Q.x]
       {Fq2::copy(4)} // Fq2::push(c3),
        // [c3, c4, -T.x - Q.x, alpha]
        {Fq2::copy(0)}
        {hinted_script0} // Fq2::push(c3.square()),
        // [c3, c4, -T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        {Fq2::add(4, 0)}
        // [c3, c4, alpha, x']
        {Fq2::copy(0)}
        // [c3, c4, alpha, x', x']
        {hinted_script1}
        // [c3, c4, x', alpha * x']
       {Fq2::neg(0)}
        // [c3, c4, x', -alpha * x']
        {Fq2::copy(4)}// Fq2::push(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        {Fq2::add(2, 0)}
        // [c3, c4, x', y']




    };
    hints.extend(hint0);
    hints.extend(hint1);

    (script, hints)
}


pub fn hinted_affine_add_line_empty_elements(tx: ark_bn254::Fq2, qx: ark_bn254::Fq2, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();
    let (hsc, hts) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square()-tx-qx);

    let script_lines = vec! [
        // [alpha, bias, tx, qx]
        Fq2::toaltstack(),
        Fq2::toaltstack(),
        Fq2::roll(2),
        Fq2::fromaltstack(),
        Fq2::fromaltstack(),
        // [bias, alpha, tx, qx]

        // [T.x, Q.x]
        Fq2::neg(0),
        // [T.x, -Q.x]
        Fq2::roll(2),
        // [-Q.x, T.x]
        Fq2::neg(0),
        // [-T.x - Q.x]
        Fq2::add(2, 0),
        // [-T.x - Q.x]
        Fq2::roll(2),
        Fq2::copy(0),
        hsc,
        // [-T.x - Q.x, alpha, alpha^2]
        // calculate x' = alpha^2 - T.x - Q.x
        Fq2::add(4, 0),
        // [alpha, x']
        Fq2::copy(0),
        // [alpha, x', x']
        hinted_script1,
        // [x', alpha * x']
        Fq2::neg(0),
        // [x', -alpha * x']
        // fq2_push_not_montgomery(c4),
        // [x', -alpha * x', -bias]
        // compute y' = -bias - alpha * x'
        Fq2::add(4, 0),
        // [x', y']
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hts);
    hints.extend(hint1);

    (script, hints)
}

/// double a point T:
///     x' = alpha^2 - 2 * T.x
///     y' = -bias - alpha* x'
///
/// input on stack:
///     T.x (2 elements)
///
/// output on stack:
///     T'.x (2 elements)
///     T'.y (2 elements)
pub fn hinted_affine_double_line(
    tx: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script0, hint0) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square() - tx - tx);

    let script = script! {//[c3(2), c4(2), t.x(2)]
        {Fq2::double(0)}
        {Fq2::neg(0)}                           // [c3(2), c4(2), - 2 * T.x(2)]
        {Fq2::copy(4)}                          // Fq2::push(c3),
        {Fq2::copy(0)}
        {hinted_script0}                        // [c3(2), c4(2), - 2 * T.x, alpha, alpha^2]
        {Fq2::add(4, 0)}
        {Fq2::copy(0)}                          // [c3(2), c4(2), alpha, x', x']
        {hinted_script1}
        {Fq2::neg(0)}                           // [c3(2), c4(2), x', -alpha * x']
        {Fq2::copy(4)}                          // [c3(2), c4(2), x', -alpha * x', c4(2)]
        {Fq2::add(2, 0)}                        // [c3(2), c4(2), x', y']
    };

    hints.extend(hint0);
    hints.extend(hint1);

    (script, hints)
}

pub fn hinted_affine_double_line_keep_elements(tx: ark_bn254::Fq2, c3: ark_bn254::Fq2, c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hsc, hts) = Fq2::hinted_square(c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(4, c3, 0, c3.square()-tx-tx);

    let scr = script!(
        // [alpha, bias, tx]
        {Fq2::toaltstack()}
        {Fq2::roll(2)}
        {Fq2::fromaltstack()}
        // [bias, alpha, tx]

        {Fq2::double(0)}
        {Fq2::neg(0)}
        // [alpha, - 2 * T.x]
        {Fq2::roll(2)}
        {Fq2::copy(0)}
        {hsc}
        // fq2_push_not_montgomery(c3.square()),
        // [- 2 * T.x, alpha, alpha^2]
        {Fq2::add(4, 0)}
        {Fq2::copy(0)}
        // [alpha, x', x']
        {hinted_script1}
        {Fq2::neg(0)}
        // [x', -alpha * x']

        {Fq2::add(4, 0)}
        // [x', y']
    );

    hints.extend(hts);
    hints.extend(hint1);

    (scr, hints)
}


/// check whether a tuple coefficient (alpha, -bias) of a tangent line is satisfied with expected point T (affine)
/// two aspects:
///     1. alpha * (2 * T.y) = 3 * T.x^2, make sure the alpha is the right ONE
///     2. T.y - alpha * T.x - bias = 0, make sure the -bias is the right ONE
///
/// input on stack:
///     T.x (2 element)
///     T.y (2 element)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn hinted_check_tangent_line(
    t: ark_bn254::G2Affine,
    c3: ark_bn254::Fq2,
    c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    // let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(t.y.double(), &c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, t.y.double(), 0, c3);
    let (hinted_script2, hint2) = Fq2::hinted_square(t.x);
    let (hinted_script3, hint3) = hinted_check_line_through_point(t.x, c3, c4);
    
    // [c3(2),c4(2),t(4) ]
    let script = script!{
        // alpha * (2 * T.y) = 3 * T.x^2
        { Fq2::copy(0) }
        { Fq2::double(0) }
        // [c3(2),c4(2),t(4),t.y*2 (2)]
        { Fq2::copy(8) }
        // [c3(2),c4(2),t(4),t.y*2 (2), c3(2)]
        { hinted_script1 }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2)]
        { Fq2::copy(4) }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x(2)]
        { hinted_script2 }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2)]
        { Fq2::copy(0) }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2), T.x^2(2) ]
        { Fq2::double(0) }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y (2), T.x^2(2), 2 * T.x^2(2) ]
        { Fq2::add(2, 0) }
        // [c3(2),c4(2), T.x(2), T.y(2), alpha * 2 * T.y(2), 3 * T.x^2(2)]
        { Fq2::neg(0) }
        { Fq2::add(2, 0) }
        { Fq2::push_zero() }
        { Fq2::equalverify() }
        // [c3(2),c4(2), T.x(2), T.y(2)]

        // check: T.y - alpha * T.x - bias = 0
        { hinted_script3 }
        // [c3(2),c4(2)]
    };
    hints.extend(hint1);
    hints.extend(hint2);
    hints.extend(hint3);

    (script, hints)
}

pub fn hinted_check_tangent_line_keep_elements(
    t: ark_bn254::G2Affine,
    c3: ark_bn254::Fq2,
    c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (hinted_script3, hint3) = hinted_check_line_through_point_keep_elements(t.x, c3, c4);
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, t.y.double(), 0, c3);
    let (hinted_script2, hint2) = Fq2::hinted_square(t.x);


    // [a, b, x, y]
    let scr = script!(
        {hinted_script3}
        // alpha * (2 * T.y) = 3 * T.x^2
        {Fq2::copy(0)}
        {Fq2::double(0)}
        {// [a, b, x, y, 2y]
        Fq2::copy(8)}
        {// [a, b, x, y, 2y, a]
        hinted_script1}
        {// [T.x, T.y, alpha * (2 * T.y)]
        Fq2::copy(4)}
        {hinted_script2}
        {Fq2::copy(0)}
        {Fq2::double(0)}
        {Fq2::add(2, 0)}
        {// [T.x, T.y, alpha * (2 * T.y), 3 * T.x^2]
        Fq2::neg(0)}
        {Fq2::add(2, 0)}
        {Fq2::push_zero()}
        {Fq2::equalverify()}
        // [T.x, T.y]

        // check: T.y - alpha * T.x - bias = 0
        // hinted_script3}
        // []
    );

    hints.extend(hint3);
    hints.extend(hint1);
    hints.extend(hint2);

    (scr, hints)
}


/// check line through one point, that is:
///     y - alpha * x - bias = 0
///
/// input on stack:
///     x (2 elements)
///     y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
///
/// output:
///     true or false (consumed on stack)
pub fn hinted_check_line_through_point(
    x: ark_bn254::Fq2,
    c3: ark_bn254::Fq2,
    _c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();

    // let (hinted_script1, hint1) = Fq2::hinted_mul_by_constant(x, &c3);
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, x, 0, c3);

    let script = script! {

           // [c3, c4, x, y]
           {Fq2::roll(2)}
           // [c3, c4, y, x]
           {Fq2::copy(6)}
           // [c3, c4, y, x,c3]
           {hinted_script1}
           // [c3, c4, y, alpha * x]
           {Fq2::neg(0)}
           // [c3, c4, y, -alpha * x]
           {Fq2::add(2, 0)}
           // [c3, c4, y - alpha * x]
           {Fq2::copy(2)} // Fq2::push(c4),
           // [c3, c4, y - alpha * x, -bias]
           {Fq2::add(2, 0)}
           // [c3, c4, y - alpha * x - bias]
           {Fq2::push_zero()}
           // [c3, c4, y - alpha * x - bias, 0]
           {Fq2::equalverify()}
           // [c3, c4]
    };
    hints.extend(hint1);

    (script, hints)
}

pub fn hinted_check_line_through_point_empty_elements(x: ark_bn254::Fq2, c3: ark_bn254::Fq2, _c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();
    
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, x,0, c3);

    let script_lines = vec![
        // [alpha, bias, x, y ]
        Fq2::roll(2),
        // [alpha, bias, y, x ]
        Fq2::roll(6),
        hinted_script1,
        // [bias, y, alpha * x]
        Fq2::neg(0),
        // [bias, y, -alpha * x]
        Fq2::add(2, 0),
        // [bias, y - alpha * x]
        Fq2::add(2, 0),
        // [y - alpha * x - bias]

        Fq2::push_zero(),
        // [y - alpha * x - bias, 0]
        Fq2::equalverify(),
    ];

    let mut script = script!{};
    for script_line in script_lines {
        script = script.push_script(script_line.compile());
    }
    hints.extend(hint1);

    (script, hints)
}


pub(crate) fn hinted_check_line_through_point_keep_elements(x: ark_bn254::Fq2, c3: ark_bn254::Fq2, _c4: ark_bn254::Fq2) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = Vec::new();
    
    let (hinted_script1, hint1) = Fq2::hinted_mul(2, x,0, c3);

    let scr = script!(
        // [alpha, bias, x, y ]
        {Fq2::copy(2)}
        // [alpha, bias, x, y, x ]
        {Fq2::copy(8)}
        // [alpha, bias, x, y, x, alpha]
        {hinted_script1}
        // [alpha, bias, x, y, alpha * x]
        {Fq2::neg(0)}
        // [alpha, bias, x, y, -alpha * x]
        {Fq2::copy(2)}
        {Fq2::add(2, 0)}
        // [alpha, bias, x, y, y - alpha * x]
        {Fq2::copy(6)}
        // [alpha, bias, x, y, y - alpha * x, bias]
        {Fq2::add(2, 0)}
        // [alpha, bias, x, y, y - alpha * x - bias]
        {Fq2::push_zero()}
        // [y - alpha * x - bias, 0]
        {Fq2::equalverify()}
    );

    hints.extend(hint1);

    (scr, hints)
}



/// check whether a tuple coefficient (alpha, -bias) of a chord line is satisfied with expected points T and Q (both are affine cooordinates)
/// two aspects:
///     1. T.y - alpha * T.x - bias = 0
///     2. Q.y - alpha * Q.x - bias = 0, make sure the alpha/-bias are the right ONEs
///
/// input on stack:
///     T.x (2 elements)
///     T.y (2 elements)
///     Q.x (2 elements)
///     Q.y (2 elements)
///
/// input of parameters:
///     c3: alpha
///     c4: -bias
/// output:
///     true or false (consumed on stack)
pub fn hinted_check_chord_line(
    t: ark_bn254::G2Affine,
    q: ark_bn254::G2Affine,
    c3: ark_bn254::Fq2,
    c4: ark_bn254::Fq2,
) -> (Script, Vec<Hint>) {
    let mut hints = Vec::new();

    let (script1, hint1) = hinted_check_line_through_point(q.x, c3, c4);
    let (script2, hint2) = hinted_check_line_through_point(t.x, c3, c4);

    let script = script! {//[c3(2),c4(2),t(4),q(4)]
        {Fq2::copy(10)}                         // [c3(2),c4(2),t(4),q(4),c3(2)]
        {Fq2::copy(10)}                         // [c3(2),c4(2),t(4),q(4),c3(2),c4(2)]
        {Fq2::roll(6)}
        {Fq2::roll(6)}                          //[c3(2),c4(2),t(4),c3(2),c4(2),q(4)]
        {script1}                               //[c3(2),c4(2),t4(4),c3(2),c4(2)]
        {Fq2::roll(6)}
        {Fq2::roll(6)}                          // [c3(2),c4(2),c3(2),c4(2),t4(4)]
        {script2}                               // [c3(2),c4(2),c3(2),c4(2)]
        {Fq2::drop()}
        {Fq2::drop()}                           // [c3(2),c4(2)]
    };

    hints.extend(hint1);
    hints.extend(hint2);

    (script, hints)
}

#[cfg(test)]
mod test {
    use crate::bn254::g1::{hinted_from_eval_point, G1Affine};
    use crate::bn254::g2::G2Affine;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    use crate::chunker::common::extract_witness_from_stack;
    use crate::treepp::*;
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use ark_ff::AdditiveGroup;
    use num_traits::One;

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
    fn test_hinted_g2_affine_is_on_curve() {

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..3 {
            let point = ark_bn254::G2Affine::rand(&mut prng);
            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                { scr}
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);

            let (scr, hints) = G2Affine::hinted_is_on_curve(point.x, point.y + point.y);
            let script = script! {
                for hint in hints { 
                    { hint.push() }
                }
                { Fq2::push(point.x) }
                { Fq2::push(point.y) }
                {Fq2::double(0)}
                { scr}
                OP_NOT
            };
            println!("curves::test_affine_is_on_curve = {} bytes", script.len());
            let res = execute_script(script);
            assert!(res.success);
        }
    }

    #[test]
    fn test_hinted_ell_by_constant_affine() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let b = ark_bn254::g2::G2Affine::rand(&mut prng);
        let p = ark_bn254::g1::G1Affine::rand(&mut prng);

        // affine mode
        let coeffs = G2Prepared::from_affine(b).ell_coeffs[0];
        let (ell_by_constant_affine_script, hints) = hinted_ell_by_constant_affine(
            p.x,
            p.y,
            coeffs.1,
            coeffs.2,
        );
        println!(
            "Pairing.ell_by_constant_affine: {} bytes",
            ell_by_constant_affine_script.len()
        );

        let script = script! {
            for tmp in hints {
                { tmp.push() }
            }
            // aux hints: Ellcoeffs: [slope, biasminus]
            { Fq2::push(coeffs.1) } // slope
            { Fq2::push(coeffs.2) } // biasminus

            // runtime input: P
            { Fq::push(p.x) }
            { Fq::push(p.y) }
            { ell_by_constant_affine_script }

            // validate output
            {Fq::push(coeffs.2.c0 * p.y)}
            {Fq::push(coeffs.2.c1 * p.y)}
            { Fq2::equalverify() }

            {Fq::push(coeffs.1.c0 * p.x)}
            {Fq::push(coeffs.1.c1 * p.x)}
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);        
    }

    #[test]
    fn test_hinted_ell_by_constant_affine_and_sparse_mul() {
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
        assert!(exec_result.success);
    }

    #[test]
    fn test_hinted_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add_line, hints) = hinted_affine_add_line(t.x, q.x, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            { Fq2::push(t.x) }
            { Fq2::push(q.x) }
            { hinted_add_line.clone() }
            // [c3(2),c4(2),add(4)]
            { Fq2::roll(6) }
            { Fq2::roll(6) }
            { Fq2::drop() }
            { Fq2::drop() }
            // [x']
            { Fq2::push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_add_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinted_check_line_through_point() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let (scr, hints) = hinted_check_line_through_point(t.x, alpha, bias_minus);
        println!("hinted_check_line_through_point: {}", scr.len());

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            {scr}
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        assert!(execute_script(script).success);


    }

    #[test]
    fn test_hinted_affine_double_line() {
        // slope: alpha = 3 * x^2 / 2 * y
        // intercept: bias = y - alpha * x
        // x' = alpha^2 - 2 * x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x.double();
        let y = bias_minus - alpha * x;
        let (hinted_double_line, hints) = hinted_affine_double_line(t.x, alpha, bias_minus);
        println!("hinted_affine_double_line: {}", hinted_double_line.len());

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            { Fq2::push(t.x) }
            { hinted_double_line }
            // [c3(2),c4(2),add(4)]
            { Fq2::roll(6) }
            { Fq2::roll(6) }
            { Fq2::drop() }
            { Fq2::drop() }
            // [x']
            { Fq2::push(y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push(x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        assert!(execute_script(script).success);
    }

    #[test]
    fn test_hinted_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let (hinted_check_line, hints) = hinted_check_tangent_line(t, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { hinted_check_line.clone() }
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinted_check_tangent_line_keep_elements() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::one().double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::one().double() + ark_bn254::Fq::one()) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha.mul_assign_by_fp(&three_div_two);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let (hinted_check_line, hints) = hinted_check_tangent_line_keep_elements(t, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { hinted_check_line.clone() }
            for v in vec![t.y, t.x, bias_minus, alpha] {
                {Fq2::push(v)}
                {Fq2::equalverify()}
            }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        for i in 0..exec_result.final_stack.len() {
            println!("{i:3}: {:?}", exec_result.final_stack.get(i));
        }
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinted_check_chord_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);
        let (hinted_check_line, hints) = hinted_check_chord_line(t, q, alpha, bias_minus);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(alpha) }
            { Fq2::push(bias_minus) }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            { hinted_check_line.clone() }
            { Fq2::drop() }
            { Fq2::drop() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn test_hinted_mul_by_char_on_q() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (qdash, scr_endo, hints) = hinted_mul_by_char_on_q(q);

        let script_len = scr_endo.len();
        let script = script!(
            for hint in hints {
                {hint.push()}
            }
            {G2Affine::push(q)}
            {scr_endo}
            {Fq2::push(qdash.y)}
            {Fq2::equalverify()}
            {Fq2::push(qdash.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let exec_result = execute_script(script);
        println!("hinted_p_power_endomorphism script {} and stack {}", script_len, exec_result.stats.max_nb_stack_items);
        assert!(exec_result.success);
    }

    #[test]
    fn test_hinted_mul_by_char_on_phi_q() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (qdash, scr_endo, hints) = hinted_mul_by_char_on_phi_q(q);

        let script_len = scr_endo.len();
        let script = script!(
            for hint in hints {
                {hint.push()}
            }
            {G2Affine::push(q)}
            {scr_endo}
            {Fq2::push(qdash.y)}
            {Fq2::equalverify()}
            {Fq2::push(qdash.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let exec_result = execute_script(script);
        println!("hinted_endomorphism_affine script {} and stack {}", script_len, exec_result.stats.max_nb_stack_items);
        assert!(exec_result.success);
    }
}

