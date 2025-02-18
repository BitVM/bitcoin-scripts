use crate::bigint::U256;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq6::Fq6;
use crate::bn254::g2::{hinted_affine_add_line_empty_elements, hinted_affine_double_line_keep_elements, hinted_check_line_through_point_empty_elements, hinted_check_line_through_point_keep_elements, hinted_check_tangent_line_keep_elements, hinted_ell_by_constant_affine, hinted_mul_by_char_on_phi_q, hinted_mul_by_char_on_q, G2Affine};
use crate::bn254::{utils::*};
use crate::bn254::{fq2::Fq2};
use crate::chunk::taps_mul::{utils_fq6_sd_mul, utils_fq6_ss_mul};
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup}; 
use ark_ff::{AdditiveGroup, Field, Fp12Config, PrimeField};
use std::ops::Neg;

use super::wrap_hasher::hash_messages;
use super::elements::{ElemG2Eval, ElementType};
use super::primitives::extern_nibbles_to_limbs;
use super::taps_mul::utils_multiply_by_line_eval;


pub(crate) fn get_hint_for_add_with_frob(q: ark_bn254::G2Affine, t: ark_bn254::G2Affine, ate: i8) -> ark_bn254::G2Affine {
    let mut qq = q;
    if ate == 1 {
        let (qdash, _, _) = hinted_mul_by_char_on_q(qq);
        qq = qdash;
    } else if ate == -1 {
        let (qdash, _, _) = hinted_mul_by_char_on_phi_q(qq);
        qq = qdash;
    }
    
    (t + qq).into_affine()

}

fn utils_point_double_eval(t: ark_bn254::G2Affine, p: ark_bn254::G1Affine) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let (alpha, bias) = if t_is_zero {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    } else {
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    };

    let (hinted_script1, hint1) = hinted_check_tangent_line_keep_elements(t,alpha, -bias);
    let (hinted_script2, hint2) = hinted_affine_double_line_keep_elements(t.x,alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut dbl_le0 = alpha;
    dbl_le0.mul_assign_by_fp(&p.x);
    let mut dbl_le1 = -bias;
    dbl_le1.mul_assign_by_fp(&p.y);
    
    let result = ((t + t).into_affine(), (dbl_le0, dbl_le1));
    if !t_is_zero { 
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
        hints.extend(hint3);
    }
 
    let script = script! {    
        // a, b, tx, ty, px, py
        { Fq2::toaltstack()}
        { G2Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
        OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // -bias, ...,  x, y, alpha
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // x, y, alpha, -bias
            {Fq2::roll(6)} {Fq2::roll(6)}          // alpha, -bias, x, y
            { hinted_script1 }                       // x, y, alpha, -bias, is_tangent_line_correct 
            {Fq2::roll(6)} {Fq2::roll(6)}
            { Fq2::copy(2) } {Fq2::copy(2)}           // x, y alpha, -bias, alpha, -bias
            { Fq2::copy(10) }                          // x, y alpha, -bias, alpha, -bias, x
            { hinted_script2 }                       // x, y, alpha, -bias, x', y'
            {Fq2::fromaltstack()}                   // x, y, alpha, -bias, x', y', px, py
            {Fq2::roll(4)} {Fq2::roll(4)}           // x, y, alpha, -bias, px, py,  x', y'
            {Fq2::toaltstack()} {Fq2::toaltstack()}
            { hinted_script3 }                                     // x, y, le,
            {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // x, y, le0, le1, x', y'
            {Fq2::roll(6)} {Fq2::roll(6)}                            // x, y, x', y', le

        OP_ENDIF
    };
    (result, script, hints)
}


fn utils_point_add_eval(t: ark_bn254::G2Affine, q4: ark_bn254::G2Affine, p: ark_bn254::G1Affine, is_frob:bool, ate_bit: i8) -> ((ark_bn254::G2Affine, (ark_bn254::Fq2, ark_bn254::Fq2)), Script, Vec<Hint>) {
    let mut hints = vec![];

    let temp_q = q4;
    let (qq, precomp_q_scr, precomp_q_hint) =
    if is_frob {
        if ate_bit == 1 {
            hinted_mul_by_char_on_q(temp_q)
        } else {
            hinted_mul_by_char_on_phi_q(temp_q)
        }
    } else if ate_bit == -1 {
        (temp_q.neg(), script!(
            // [q4]
            {Fq::toaltstack()}
            {Fq::neg(0)}
            {Fq::fromaltstack()}
            {Fq::neg(0)}
            // [-q4]
        ), vec![])                
    } else {
        (temp_q, script!(), vec![])
    };

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let q_is_zero = qq.is_zero() || (qq == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // q is none or Some(0)

    let (alpha, bias) = if !t_is_zero && !q_is_zero && t != -qq { // todo: add if t==q and if t == -q
        let alpha = (t.y - qq.y) / (t.x - qq.x);
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    } else {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    };

    let (hinted_script11, hint11) = hinted_check_line_through_point_keep_elements(t.x, alpha, -bias); // todo: remove unused arg: bias
    let (hinted_script12, hint12) = hinted_check_line_through_point_empty_elements(qq.x, alpha, -bias); // todo: remove unused arg: bias
    let (hinted_script2, hint2) = hinted_affine_add_line_empty_elements(t.x, qq.x, alpha, -bias);
    let (hinted_script3, hint3) = hinted_ell_by_constant_affine(p.x, p.y,alpha, -bias);

    let mut add_le0 = alpha;
    add_le0.mul_assign_by_fp(&p.x);
    let mut add_le1 = -bias;
    add_le1.mul_assign_by_fp(&p.y);

    let result = ((t + qq).into_affine(), (add_le0, add_le1));

    if !t.is_zero() && !qq.is_zero() && t != -qq {
        hints.extend(precomp_q_hint);
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint11);
        hints.extend(hint12);
        hints.extend(hint2);
        hints.extend(hint3);
    }

    let script = script! {        // tx ty qx qy
        // a, b, tx, ty, qx, qy, px, py
        {Fq2::toaltstack()}
        // [qx qy]
        {precomp_q_scr}
        // [qx qy]
        { G2Affine::is_zero_keep_element() }
        OP_IF
            { G2Affine::drop() }
        OP_ELSE
            { G2Affine::roll(1) }
            { G2Affine::is_zero_keep_element() }
            OP_IF
                { G2Affine::drop() }
            OP_ELSE                                // qx qy tx ty
                {G2Affine::copy(1)}
                // qx qy tx ty qx qy
                { Fq2::neg(0)}
                // qx qy tx ty qx -qy
                {G2Affine::copy(1)}
                // qx qy tx ty qx -qy tx ty
                {G2Affine::equal()} 
                // qx qy tx ty 0/1
                OP_IF // qx == tx
                    {G2Affine::drop()}
                    {G2Affine::drop()}
                    {Fq2::push(ark_bn254::Fq2::ZERO)}
                    {Fq2::push(ark_bn254::Fq2::ZERO)}
                OP_ELSE
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }
                    for _ in 0..Fq::N_LIMBS * 2 {
                        OP_DEPTH OP_1SUB OP_ROLL 
                    }                                  
                    {Fq2::roll(6)} {Fq2::roll(6)}
                    {hinted_script11}
                    {Fq2::roll(6)} {Fq2::roll(6)}
                    { Fq2::copy(2) } { Fq2::copy(2) }    // qx qy tx ty c3 c4, c3, c4
                    { Fq2::copy(14) }
                    { Fq2::roll(14) }                    // qx tx ty c3 c4 c3 c4 qx qy
                    { hinted_script12 }                 // qx tx ty c3 c4 0/1
                    {Fq2::copy(2)} {Fq2::copy(2)}     // qx tx ty c3 c4, c3 c4
                    { Fq2::copy(10) }                    // qx tx ty c3 c4, c3 c4, tx
                    { Fq2::roll(14) }                    // c3 c4 tx qx
                    { hinted_script2 }                 // tx, ty, c3, c4, x' y'
                    {Fq2::fromaltstack()}             // tx, ty, c3, c4, x' y', px, py
                    {Fq2::roll(4)} {Fq2::roll(4)}           // tx, ty, alpha, -bias, px, py,  x', y'
                    {Fq2::toaltstack()} {Fq2::toaltstack()}
                    { hinted_script3 }                         // tx, ty, le,
                    {Fq2::fromaltstack()} {Fq2::fromaltstack()}  // tx, ty, le0, le1, x', y'
                    {Fq2::roll(6)} {Fq2::roll(6)}                            // tx, ty, x', y', le
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    };
    (result, script, hints)
}


fn point_ops_and_multiply_line_evals_step_1(
    is_dbl: bool, is_frob: Option<bool>, ate_bit: Option<i8>,
    t4: ark_bn254::G2Affine, p4: ark_bn254::G1Affine, 
    q4: Option<ark_bn254::G2Affine>,

    p3: ark_bn254::G1Affine,
    t3: ark_bn254::G2Affine, q3: Option<ark_bn254::G2Affine>,
    p2: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine, q2: Option<ark_bn254::G2Affine>,
) -> (ElemG2Eval, bool, Script, Vec<Hint> ) {
    // a, b, tx, ty, px, py
    let ((nt, (le4_0, le4_1)), nt_scr, nt_hints) = if is_dbl {
        //[a, b, tx, ty, px, py]
        utils_point_double_eval(t4, p4)
    } else {
        // a, b, tx, ty, qx, qy, px, py
        assert!(q4.is_some());
        utils_point_add_eval(t4, q4.unwrap(), p4, is_frob.unwrap(), ate_bit.unwrap())
    };
    let le4 = ark_bn254::Fq6::new(le4_0, le4_1, ark_bn254::Fq2::ZERO);


    let (alpha_t3, neg_bias_t3) = if is_dbl {
        let alpha_t3 = (t3.x.square() + t3.x.square() + t3.x.square()) / (t3.y + t3.y); 
        let neg_bias_t3 = alpha_t3 * t3.x - t3.y;
        (alpha_t3, neg_bias_t3)
    } else {
        let ate_bit = ate_bit.unwrap();
        let is_frob = is_frob.unwrap();
        let temp_q = q3.unwrap();
        let q3 = if is_frob {
            if ate_bit == 1 {
                hinted_mul_by_char_on_q(temp_q).0
            } else {
                hinted_mul_by_char_on_phi_q(temp_q).0
            }
        } else if ate_bit == -1 {
            temp_q.neg()
        } else {
            temp_q
        };

        let alpha_t3 = (t3.y - q3.y) / (t3.x - q3.x); 
        let neg_bias_t3 = alpha_t3 * t3.x - t3.y;
        (alpha_t3, neg_bias_t3)
    };

    let (alpha_t2, neg_bias_t2) = if is_dbl {
        let alpha_t2 = (t2.x.square() + t2.x.square() + t2.x.square()) / (t2.y + t2.y); 
        let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
        (alpha_t2, neg_bias_t2)
    } else {
        let ate_bit = ate_bit.unwrap();
        let is_frob = is_frob.unwrap();
        let temp_q = q2.unwrap();
        let q2 = if is_frob {
            if ate_bit == 1 {
                hinted_mul_by_char_on_q(temp_q).0
            } else {
                hinted_mul_by_char_on_phi_q(temp_q).0
            }
        } else if ate_bit == -1 {
            temp_q.neg()
        } else {
            temp_q
        };

        let alpha_t2 = (t2.y - q2.y) / (t2.x - q2.x); 
        let neg_bias_t2 = alpha_t2 * t2.x - t2.y;
        (alpha_t2, neg_bias_t2)
    };

    let (g, fg_scr, fg_hints) = utils_multiply_by_line_eval(le4, alpha_t3, neg_bias_t3, p3);
    let one_plus_fg_j_sq = (le4 * g * ark_bn254::Fq12Config::NONRESIDUE) + ark_bn254::Fq6::ONE;
    let fpg = le4 + g;


    let (hinted_ell_t2, hints_ell_t2) = hinted_ell_by_constant_affine(p2.x, p2.y, alpha_t2, neg_bias_t2);
    let mut t2le_a = alpha_t2;
    t2le_a.mul_assign_by_fp(&p2.x);
    let mut t2le_b = neg_bias_t2;
    t2le_b.mul_assign_by_fp(&p2.y);

    let mut t3le_a = alpha_t3;
    t3le_a.mul_assign_by_fp(&p3.x);
    let mut t3le_b = neg_bias_t3;
    t3le_b.mul_assign_by_fp(&p3.y);

    let mut hints = vec![];
    hints.extend_from_slice(&nt_hints);
    hints.extend_from_slice(&fg_hints);
    hints.extend_from_slice(&hints_ell_t2);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let ops_scr = script!(
        // [hints, t4, (q4), p4, p3, p2]
        {Fq2::toaltstack()}
        {Fq2::copy(2)} {Fq2::toaltstack()}
        {Fq2::toaltstack()}
        // [hints, t4, (q4), p4] [p2, p4, p3]
        {nt_scr}
        // [hints, t4, nt4, le0, le1] [p2, p4, p3]
        // [hints, t4, nt4, le] [p2, p4, p3]
        {Fq2::fromaltstack()}
        // [hints, t4, nt4, le, p3] [p2, p4]
        {fg_scr}
        // [t4, nt4, p3, g, f, fg] [p2, p4]
        {mul_by_beta_sq_scr}
        // [t4, nt4, p3, g, f, fg_beta_sq] [p2, p4]
        {Fq6::push(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [t4, nt4, p3, g, f, fg_beta_sq+1] [p2, p4]
        // [t4, nt4, p3, g, f, fg'] [p2, p4]
        {Fq6::toaltstack()}
        // [t4, nt4, p3, g0, g1, f0, f1] [p2, p4, fg']
        {Fq2::add(6, 2)}
        {Fq2::add(4, 2)} 
        {Fq6::fromaltstack()}
        // [t4, nt4, p3, g+f, fg'] [p2, p4]
        {Fq2::fromaltstack()}
        // [t4, nt4, p3, g+f, fg', p4] [p2]
        {Fq2::fromaltstack()}
        {Fq2::copy(0)}
        {Fq2::push(alpha_t2)}
        {Fq2::push(neg_bias_t2)}
        // [t4, nt4, p3, g+f, fg', p4, p2, p2, a, b] []
        {Fq2::roll(4)}
        {hinted_ell_t2}
        // [t4, nt4, p3, g+f, fg', p4, p2, p2le] []
    );

    // rearrange elements order
    let rearrange_scr = script!(
        // [t4, nt4, p3, g+f, fg', p4, p2, p2le] 
        {Fq6::toaltstack()}
        {Fq2::roll(12)}
        {Fq2::fromaltstack()}
        // [t4, nt4, g+f, fg', p4, p3, p2] [p2le]
        {Fq2::roll(18)} {Fq2::roll(18)}
         // [t4, g+f, fg', p4, p3, p2, nt4] [p2le]

        for _ in 0..5 {
            {Fq2::roll(18)}
        }
         // [t4, p4, p3, p2, nt4, g+f, fg'] [p2le]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        // [t4, p4, p3, p2, nt4, g+f, fg', p2le]
    );

    // check if g+f == 0 || fg' == 0 
    let input_validity_scr = script!(
        // [t4, p4, p3, p2, nt4, g+f, fg', p2le]
        {Fq6::copy(4)} 
        // [t4, p4, p3, p2, nt4, g+f, fg', p2le, fg']
        {Fq6::is_zero()} OP_NOT OP_TOALTSTACK // fg'_is_zero()
        // [t4, p4, p3, p2, nt4, g+f, fg', p2le]
        {Fq2::copy(12)} {Fq2::copy(12)} 
         // [t4, p4, p3, p2, nt4, g+f, fg', p2le, g+f]
        {Fq2::push(ark_bn254::Fq2::ZERO)}
        {Fq6::is_zero()} // g+f.is_zero()
        OP_NOT
        OP_FROMALTSTACK 
        // [g+f.is_not_zero() fg'_is_not_zero()]
        OP_BOOLAND
        OP_IF
            // g+f.is_not_zero() && fg'.is_not_zero()
            {1}
            // [t4, p4, p3, p2, nt4, g+f, fg', p2le, {1}]
        OP_ELSE  
            // g+f.is_zero() || fg'.is_zero() 
            {0}
            // [t4, p4, p3, p2, nt4, g+f, fg', p2le, {0}]
        OP_ENDIF
        // [t4, p4, p3, p2, nt4, g+f, fg', p2le, 0/1]
    );

    let scr = script!(
        {ops_scr}
        {rearrange_scr}
        {input_validity_scr}
    );

    let hout = ElemG2Eval{
        t: nt,
        p2le: [t2le_a, t2le_b],
        one_plus_ab_j_sq: one_plus_fg_j_sq, 
        a_plus_b: [fpg.c0, fpg.c1],
        // res_hint: res_hint.c1/res_hint.c0,
    };
    
    let input_is_valid = one_plus_fg_j_sq != ark_bn254::Fq6::ZERO && fpg.c0 != ark_bn254::Fq2::ZERO && fpg.c1 != ark_bn254::Fq2::ZERO;

    (hout, input_is_valid, scr, hints)

}


pub(crate) fn chunk_point_ops_and_multiply_line_evals_step_1(
    is_dbl: bool, is_frob: Option<bool>, ate_bit: Option<i8>,
    t4: ElemG2Eval, p4: ark_bn254::G1Affine, 
    q4: Option<ark_bn254::G2Affine>,
    p3: ark_bn254::G1Affine,
    t3: ark_bn254::G2Affine, q3: Option<ark_bn254::G2Affine>,
    p2: ark_bn254::G1Affine,
    t2: ark_bn254::G2Affine, q2: Option<ark_bn254::G2Affine>,
) -> (ElemG2Eval, bool, Script, Vec<Hint> ) {
    let (hint_out, is_valid, ops_scr, hints) = point_ops_and_multiply_line_evals_step_1(is_dbl, is_frob, ate_bit, t4.t, p4, q4, p3, t3, q3, p2, t2, q2);
    let pre_hash_scr = script!(
        // [t4, p4, p3, p2, nt4, F, 0/1] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {Fq::fromaltstack()}
        {9} OP_ROLL OP_TOALTSTACK
        // [t4, p4, p3, p2, nt4, F, ht4_le] [outhash, p3hash, p4hash, in_t4hash,  0/1]
        for _ in 0..(2+2+2+4+14) {
            {Fq::roll(24)}
        }
        // [t4, ht4_le, p4, p3, p2, nt4, F] [outhash, p3hash, p4hash, in_t4hash, 0/1]
        OP_FROMALTSTACK
        // [t4, ht4_le, p4, p3, p2, nt4, F, 0/1] [outhash, p3hash, p4hash, in_t4hash]
    );
    let _hash_scr = script!(
        // [t4, ht4_le, p4, p3, nt4, fg] [outhash, p3hash, p4hash, in_t4hash]
        {hash_messages(vec![ElementType::G2EvalPoint, ElementType::G1, ElementType::G1, ElementType::G1, ElementType::G2Eval])}
    );

    let pre_ops_scr = script!(
        // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash (q4)]
        if !is_dbl {
            // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash q4]
            for _ in 0..4 {
                {Fq::fromaltstack()} // q
            }
            // [hints, {t4, ht4_le}, p4, p3, p2, q4] [outhash, p2hash, p3hash, p4hash, in_t4hash]
            {Fq::roll(10)} {Fq::toaltstack()}
            // [hints, t4, p4, p3, p2, q4] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
            {Fq6::roll(4)}
            // [hints, t4, q4, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        } else {
            // [hints, {t4, ht4_le}, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
            {Fq::roll(6)} {Fq::toaltstack()}
            // [hints, t4, p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        }
    );

    let scr = script!(
        {pre_ops_scr}
        // [hints, t4, (q4), p4, p3, p2] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {ops_scr}
        // [t4, p4, p3, p2, nt4, F, 0/1] [outhash, p2hash, p3hash, p4hash, in_t4hash, ht4_le]
        {pre_hash_scr}
        // [t4, in_t4hash, p4, p3, p2, nt4, F, 0/1] [outhash, p3hash, p4hash, in_t4hash]
        // {hash_scr}
    );

    (hint_out, is_valid, scr, hints)
}

pub(crate) fn chunk_point_ops_and_multiply_line_evals_step_2(f: ElemG2Eval) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    let (ops_res, is_valid_input, ops_scr, ops_hints) = point_ops_and_multiply_line_evals_step_2(f);
    let scr = script!(
        // [hints, apb, Ab, c, Haux_in, h] [hash_h, hash_in]
        {Fq::roll(6)} {Fq::toaltstack()}
        // [hints, {apb, Ab, c}, h] [hash_h, hash_in, Haux_in]
        {ops_scr}

        // [{apb, Ab, c}, h, 0/1] [hash_h, hash_in, Haux_in]
        {Fq::fromaltstack()} 
        // [{apb, Ab, c}, h, 0/1 Haux_in] [hash_h, hash_in]
        {9} OP_ROLL OP_TOALTSTACK
        // [{apb, Ab, c}, h, Haux_in] [hash_h, hash_in, 0/1]
        {Fq6::roll(1)} OP_FROMALTSTACK
        // [{apb, Ab, c, Haux_in}, h, 0/1] [hash_h, hash_in]
    );

    let _hash_scr = script!(
        // [t4, ht4_le, p4, p3, nt4, fg] [outhash, p3hash, p4hash, in_t4hash]
        {hash_messages(vec![ElementType::G2EvalMul, ElementType::Fp6])}
        OP_TRUE
    );

    (ops_res, is_valid_input, scr, ops_hints)
}

pub(crate) fn point_ops_and_multiply_line_evals_step_2(
    f: ElemG2Eval,
) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {

    let ab = f.one_plus_ab_j_sq;
    let apb = ark_bn254::Fq6::new( f.a_plus_b[0],  f.a_plus_b[1], ark_bn254::Fq2::ZERO);
    assert_ne!(apb, ark_bn254::Fq6::ZERO);
    assert_ne!(ab, ark_bn254::Fq6::ZERO);
    let le2_c1 = ark_bn254::Fq6::new( f.p2le[0],  f.p2le[1], ark_bn254::Fq2::ZERO);
    let le2 = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, le2_c1);
    let le4_mul_le3 = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, apb/ab);
    let le4_mul_le3_mul_le2 = le4_mul_le3 * le2;

    let abc = ab * le2_c1;
    let numerator = apb + abc;
    
    let apb_mul_c = le2_c1 * apb;
    let denom = ab + apb_mul_c * ark_bn254::Fq12Config::NONRESIDUE;

    let (abc_out, abc_scr, abc_hints) = utils_fq6_sd_mul(ab, le2_c1);
    assert_eq!(abc_out, ab*le2_c1);
    
    let (apb_mul_c_out, apb_mul_c_scr, apb_mul_c_hints) = utils_fq6_ss_mul(apb, le2_c1);
    assert_eq!(apb_mul_c, apb_mul_c_out);

    let mut hints = vec![];
    hints.extend_from_slice(&abc_hints);
    hints.extend_from_slice(&apb_mul_c_hints);

    let mock_output = ark_bn254::Fq6::ONE;
    let mut g = mock_output;
    let den_mul_h_scr= Fq6::hinted_mul_keep_elements(6, ark_bn254::Fq6::ONE, 0, ark_bn254::Fq6::ONE).0;
    let is_valid_input = numerator != ark_bn254::Fq6::ZERO && denom != ark_bn254::Fq6::ZERO;
    if is_valid_input {
        g = le4_mul_le3_mul_le2.c1/le4_mul_le3_mul_le2.c0;
        assert_eq!(g * denom, numerator);
        let den_mul_h_hints = Fq6::hinted_mul_keep_elements(6, denom, 0, g).1;
        hints.extend_from_slice(&den_mul_h_hints);
    }

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        {Fq6::toaltstack()}
        // [hints, apb, Ab, c] [h]
        {abc_scr}
        // [hints, apb, Ab, c, Abc] [h]
        // [hints, apb, Ab, c, Abc] [h]
        {Fq2::copy(18)} {Fq2::copy(18)}
        // [hints, apb, Ab, c, Abc, apb] [h]
        {Fq2::copy(12)} {Fq2::copy(12)}
        // [hints, apb, Ab, c, Abc, apb, c] [h]
        {apb_mul_c_scr}        
        // [hints, apb, Ab, c, Abc, apb, c, Apb_mul_C] [h]
        {mul_by_beta_sq_scr}
        // [hints, apb, Ab, c, Abc, apb, c, Apb_mul_C_beta_sq] [h]
        {Fq6::copy(24)}
        // [hints, apb, Ab, c, Abc, apb, c, Apb_mul_C_beta_sq, Ab] [h]
        {Fq6::add(6, 0)}
        // [hints, apb, Ab, c, Abc, apb, c, denom] [h]
        {Fq6::toaltstack()}
        // [hints, apb, Ab, c, Abc, apb, c] [h, denom]
        {Fq2::drop()} {Fq2::drop()}
        // [hints, apb, Ab, c, Abc, apb] [h, denom]
        {Fq2::push(ark_bn254::Fq2::ZERO)}
        {Fq6::add(6, 0)}
        // [hints, apb, Ab, c, numerator] [h, denom]
        {Fq6::fromaltstack()}
        // [hints, apb, Ab, c, numerator, denom] [h]

        {Fq6::copy(0)} {Fq6::is_zero()} OP_NOT OP_TOALTSTACK // denom_is_zero
        {Fq6::copy(6)} {Fq6::is_zero()}  // numerator_is_zero
        OP_NOT
        OP_FROMALTSTACK // [.., 0/1, 0/1]
        OP_BOOLAND // [..., 0/1/2]        
        OP_IF
            // [hints, apb, Ab, c, numerator, denom] [h]
            {Fq6::fromaltstack()}
            // [hints, apb, Ab, c, numerator, denom, h]
            {den_mul_h_scr}
            // [hints, apb, Ab, c, numerator, denom, h, denom_mul_h]
            {Fq12::roll(12)}
            // [hints, apb, Ab, c, h, denom_mul_h, numerator, denom]
            {Fq6::drop()}
            // [apb, Ab, c, h, denom_mul_h, numerator]
            {Fq6::equalverify()}
            // [ apb, Ab, c, h ]
            {1} // input was valid
            // [ apb, Ab, c, h, 1]
        OP_ELSE
            // any of the inputs was invalid
            // [ apb, Ab, c, numerator, denom] [h]
            {Fq6::drop()} {Fq6::drop()} {Fq6::fromaltstack()}
            // [apb, Ab, c, h]
            {Fq6::drop()}
            {Fq6::push(mock_output)}
            // [apb, Ab, c, mock_h]
            {0} // input was invalid

        OP_ENDIF
        // [ apb, Ab, c, h, 0/1]
    );
    (g, is_valid_input, scr, hints)
}


pub(crate) fn chunk_init_t4(ts: [ark_ff::BigInt<4>; 4]) -> (ElemG2Eval, bool, Script, Vec<Hint>) {
    let mut hints = vec![];

    let mock_t = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ONE, ark_bn254::Fq2::ONE);

    let are_valid_fps = ts.iter().filter(|f| **f < ark_bn254::Fq::MODULUS).count() == ts.len();

    let mut t4: ElemG2Eval =  ElemG2Eval {
        t: mock_t,
        p2le: [ark_bn254::Fq2::ZERO; 2],
        one_plus_ab_j_sq: ark_bn254::Fq6::ZERO,
        a_plus_b: [ark_bn254::Fq2::ZERO; 2],
    };
    if are_valid_fps {
        t4.t = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(ts[0].into(), ts[1].into()), ark_bn254::Fq2::new(ts[2].into(), ts[3].into()));
    }
    
    let (on_curve_scr, on_curve_hints) = G2Affine::hinted_is_on_curve(t4.t.x, t4.t.y);
    if are_valid_fps {
        hints.extend_from_slice(&on_curve_hints);
    }
    let is_valid_input = are_valid_fps && t4.t.is_on_curve(); 

    let aux_hash_le = t4.hash_le(); // aux_hash_le doesn't include t4.t, is constant, so hash_le can be hardcoded

    let ops_scr = script! {
        // [hints] [f_hash_claim, y1, y0, x1, x0]
        for _ in 0..4 {
            {Fq::fromaltstack()}
        }

        {Fq2::copy(2)} {Fq2::copy(2)}
        for _ in 0..4 {
            { Fq::push_hex(Fq::MODULUS) }
            { U256::lessthan(1, 0) } // a < p
            OP_TOALTSTACK
        }
        {1}
        for _ in 0..4 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }

        OP_IF 
            // [hints, x0, x1, y0, y1] [f_hash_claim]
            {Fq2::copy(2)} {Fq2::copy(2)}
            // [hints, x0, x1, y0, y1, x0, x1, y0, y1] [f_hash_claim]
            {on_curve_scr}
            OP_IF
                // [x0, x1, y0, y1] [f_hash_claim]
                for le in extern_nibbles_to_limbs(aux_hash_le) {
                    {le}
                }
                // [x0, x1, y0, y1, aux_hash_le] [f_hash_claim]
                {1}
            OP_ELSE
                for _ in 0..4 {
                    {Fq::drop()}
                }
                {G2Affine::push(mock_t)}
                // [mock_t] [f_hash_claim]
                for le in extern_nibbles_to_limbs(aux_hash_le) {
                    {le}
                }
                // [mock_t, aux_hash_le] [f_hash_claim]
                {0}
            OP_ENDIF
            // [T4, HashT4Aux, {0/1}] [NT4_hash_claim]
        OP_ELSE
            // [x0, x1, y0, y1] [f_hash_claim]
            for _ in 0..4 {
                {Fq::drop()}
            }
            {G2Affine::push(mock_t)}
            for le in extern_nibbles_to_limbs(aux_hash_le) {
                {le}
            }
            // [mock_t, aux_hash_le] [f_hash_claim]
            {0}
        OP_ENDIF

    };
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::G2EvalPoint])}
        OP_TRUE
    );
    (t4, is_valid_input, ops_scr, hints)
}



#[cfg(test)]
mod test {
    use ark_ff::{AdditiveGroup, BigInt, Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6, g1::G1Affine, g2::G2Affine, utils::Hint}, chunk::{wrap_hasher::hash_messages, elements::{DataType, ElemG2Eval, ElementType}, taps_point_ops::{chunk_point_ops_and_multiply_line_evals_step_2, chunk_init_t4, chunk_point_ops_and_multiply_line_evals_step_1, point_ops_and_multiply_line_evals_step_2, point_ops_and_multiply_line_evals_step_1, utils_point_add_eval}}, execute_script};

    use super::utils_point_double_eval;


    #[test]
    fn test_point_double_eval() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        
        let ((r, le), scr, hints) = utils_point_double_eval(t, p);
        // a, b, tx, ty, px, py

        let script = script!(
            for h in hints {
                {h.push()}
            }
            {G2Affine::push(t)}
            {G1Affine::push(p)}
            // [hints, tx, ty, px, py]
            {scr}
            // t, R, dbl_le
            {Fq2::push(le.1)}
            {Fq2::equalverify()}
            {Fq2::push(le.0)}
            {Fq2::equalverify()}

            {Fq2::push(r.y)}
            {Fq2::equalverify()}
            {Fq2::push(r.x)}
            {Fq2::equalverify()}


            {Fq2::push(t.y)}
            {Fq2::equalverify()}


            {Fq2::push(t.x)}
            {Fq2::equalverify()}

            
            OP_TRUE
        );
        let res = execute_script(script);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success);
        assert!(res.final_stack.len() == 1);    
        println!("utils_point_double_eval disprovable(false) max_stack {:?}", res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_point_add_eval() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let ((r, le), hinted_check_add, hints) = utils_point_add_eval(t, q, p, true, 1);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }

            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            { G1Affine::push(p) }
            { hinted_check_add.clone() }
            // [x']


            {Fq2::push(le.1)}
            {Fq2::equalverify()}
            {Fq2::push(le.0)}
            {Fq2::equalverify()}

            {Fq2::push(r.y)}
            {Fq2::equalverify()}
            {Fq2::push(r.x)}
            {Fq2::equalverify()}
            
            
            {Fq2::push(t.y)}
            {Fq2::equalverify()}

            {Fq2::push(t.x)}
            {Fq2::equalverify()}
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script(script);
        if exec_result.final_stack.len() > 1 {
            for i in 0..exec_result.final_stack.len() {
                println!("{i:} {:?}", exec_result.final_stack.get(i));
            }
        }
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "utils_point_add_eval disprovable(false) {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }

    

    #[test]
    fn test_tap_init_t4() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let temp_q1 = ark_bn254::G2Affine::rand(&mut prng);
        let q1: [BigInt::<4>; 4] = [temp_q1.x.c0.into(), temp_q1.x.c1.into(), temp_q1.y.c0.into(), temp_q1.y.c1.into()];
        let q2 = [ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::zero()];
        let q3 = [ark_ff::BigInt::<4>::one() << 255, ark_ff::BigInt::<4>::one() << 255, ark_ff::BigInt::<4>::one() << 255, ark_ff::BigInt::<4>::one() << 255];
        let q4 = [ark_ff::BigInt::<4>::one(), ark_ff::BigInt::<4>::one(), ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::zero()];

        let test_set = vec![(q1, false), (q2, true), (q3, true), (q4, true)];
        for (q, is_disprovable) in test_set {
            let (hint_out, is_valid_input, init_t4_tap,  hint_script) = chunk_init_t4(q);
            assert_eq!(is_valid_input, !is_disprovable);

            let hint_out = DataType::G2EvalData(hint_out);
    
            let bitcom_script = script!{
                {hint_out.to_hash().as_hint_type().push()}
                {Fq::toaltstack()}
    
                for temp in q.into_iter().rev() {
                    {Hint::U256(temp.into()).push()}
                    {Fq::toaltstack()}
                }
            };
            let hash_scr = script!(
                {hash_messages(vec![ElementType::G2EvalPoint])}
                OP_TRUE
            );
    
            let tap_len = init_t4_tap.len() + hash_scr.len();
            let script = script! {
                for h in hint_script {
                    { h.push() }
                }
                {bitcom_script}
                {init_t4_tap}
                {hash_scr}
            };
    
            let res = execute_script(script);
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(res.success, is_disprovable); 
            assert!(res.final_stack.len() == 1);
            println!("chunk_init_t4: disprovable({}) script {} stack {}", is_disprovable, tap_len, res.stats.max_nb_stack_items);
        }
    }

    #[test]
    fn test_point_ops_and_multiply_line_evals_step_1_valid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let is_dbl = false;
        let is_frob: Option<bool> = Some(true);
        let ate_bit: Option<i8> = Some(1);

        assert_eq!(is_dbl, is_frob.is_none() && ate_bit.is_none());
        assert_eq!(!is_dbl, is_frob.is_some() && ate_bit.is_some());

        let (hint_out,is_valid_input, ops_scr, ops_hints) = point_ops_and_multiply_line_evals_step_1(is_dbl, is_frob, ate_bit, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(is_valid_input);

        let mut preimage_hints = vec![];
        preimage_hints.extend_from_slice(&[Hint::Fq(t4.x.c0),
            Hint::Fq(t4.x.c1),
            Hint::Fq(t4.y.c0),
            Hint::Fq(t4.y.c1)]);

        if !is_dbl {
            preimage_hints.extend_from_slice(&[Hint::Fq(q4.x.c0),
                Hint::Fq(q4.x.c1),
                Hint::Fq(q4.y.c0),
                Hint::Fq(q4.y.c1)]);
        }


        preimage_hints.extend_from_slice(&[Hint::Fq(p4.x),
            Hint::Fq(p4.y)]);
        preimage_hints.extend_from_slice(&[Hint::Fq(p3.x),
            Hint::Fq(p3.y)]);
        preimage_hints.extend_from_slice(&[Hint::Fq(p2.x),
            Hint::Fq(p2.y)]);

        let tap_len = ops_scr.len();
        // [hints, t4, (q2), p4, p3, p2]
        let scr = script!(
            for h in &ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
            OP_VERIFY // valid input
             // [t4, p4, p3, p2, nt4, gpf, fg, p2le]
            {Fq2::push(hint_out.p2le[1])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.p2le[0])}
            {Fq2::equalverify()}
            {Fq6::push(hint_out.one_plus_ab_j_sq)}
            {Fq6::equalverify()}
            {Fq2::push(hint_out.a_plus_b[1])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.a_plus_b[0])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.t.y)}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.t.x)}
            {Fq2::equalverify()}
            {G1Affine::push(p2)}
            {Fq2::equalverify()}
            {G1Affine::push(p3)}
            {Fq2::equalverify()}
            {G1Affine::push(p4)}
            {Fq2::equalverify()}
            {Fq2::push(t4.y)}
            {Fq2::equalverify()}
            {Fq2::push(t4.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("point_ops_and_multiply_line_evals_step_1 disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_point_ops_and_multiply_line_evals_step_1_invalid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        
        let t3 = t4; // ark_bn254::G2Affine::rand(&mut prng);
        let q3 = q4; //ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::new_unchecked(-p4.x, -p4.y); //ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let is_dbl = false;
        let is_frob: Option<bool> = Some(true);
        let ate_bit: Option<i8> = Some(1);

        assert_eq!(is_dbl, is_frob.is_none() && ate_bit.is_none());
        assert_eq!(!is_dbl, is_frob.is_some() && ate_bit.is_some());

        let (hint_out, is_valid_input, ops_scr, ops_hints) = point_ops_and_multiply_line_evals_step_1(is_dbl, is_frob, ate_bit, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(!is_valid_input);

        let mut preimage_hints = vec![];
        preimage_hints.extend_from_slice(&[Hint::Fq(t4.x.c0),
            Hint::Fq(t4.x.c1),
            Hint::Fq(t4.y.c0),
            Hint::Fq(t4.y.c1)]);

        if !is_dbl {
            preimage_hints.extend_from_slice(&[Hint::Fq(q4.x.c0),
                Hint::Fq(q4.x.c1),
                Hint::Fq(q4.y.c0),
                Hint::Fq(q4.y.c1)]);
        }


        preimage_hints.extend_from_slice(&[Hint::Fq(p4.x),
            Hint::Fq(p4.y)]);
        preimage_hints.extend_from_slice(&[Hint::Fq(p3.x),
            Hint::Fq(p3.y)]);
        preimage_hints.extend_from_slice(&[Hint::Fq(p2.x),
            Hint::Fq(p2.y)]);

        let tap_len = ops_scr.len();
        // [hints, t4, (q2), p4, p3, p2]
        let scr = script!(
            for h in &ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
            OP_NOT OP_VERIFY // valid input
             // [t4, p4, p3, p2, nt4, gpf, fg, p2le]
            {Fq2::push(hint_out.p2le[1])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.p2le[0])}
            {Fq2::equalverify()}
            {Fq6::push(hint_out.one_plus_ab_j_sq)}
            {Fq6::equalverify()}
            {Fq2::push(hint_out.a_plus_b[1])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.a_plus_b[0])}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.t.y)}
            {Fq2::equalverify()}
            {Fq2::push(hint_out.t.x)}
            {Fq2::equalverify()}
            {G1Affine::push(p2)}
            {Fq2::equalverify()}
            {G1Affine::push(p3)}
            {Fq2::equalverify()}
            {G1Affine::push(p4)}
            {Fq2::equalverify()}
            {Fq2::push(t4.y)}
            {Fq2::equalverify()}
            {Fq2::push(t4.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("point_ops_and_multiply_line_evals_step_1 disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }


        
    #[test]
    fn test_point_ops_and_multiply_line_evals_step_2_invalid_input() {
        let is_dbl = true;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        
        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], one_plus_ab_j_sq: ark_bn254::Fq6::ONE, a_plus_b: [ark_bn254::Fq2::ONE; 2]};
        let (mut inp, is_valid_input, _, _) = chunk_point_ops_and_multiply_line_evals_step_1(is_dbl, None, None, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(is_valid_input);

        let apb = ark_bn254::Fq6::new(inp.a_plus_b[0], inp.a_plus_b[1], ark_bn254::Fq2::ZERO);
        let le2 = ark_bn254::Fq6::new(inp.p2le[0], inp.p2le[1], ark_bn254::Fq2::ZERO);
        // apb/ab + le2 = 0 => apb/ab = -le2 => ab = ab = -apb/le2
        let new_ab = -apb/le2;
        inp.one_plus_ab_j_sq = new_ab;

        let (hout, is_valid_input, ops_scr, ops_hints) = point_ops_and_multiply_line_evals_step_2(inp);
        assert!(!is_valid_input);
        
        let mut preimage_hints = vec![];
        let hint_apb: Vec<Hint> = vec![inp.a_plus_b[0].c0, inp.a_plus_b[0].c1, inp.a_plus_b[1].c0, inp.a_plus_b[1].c1].into_iter().map(Hint::Fq).collect();
        let hint_ab: Vec<Hint> = inp.one_plus_ab_j_sq.to_base_prime_field_elements().map(Hint::Fq).collect();
        let hint_p2le: Vec<Hint> = vec![inp.p2le[0].c0, inp.p2le[0].c1, inp.p2le[1].c0, inp.p2le[1].c1].into_iter().map(Hint::Fq).collect();
        let hint_result: Vec<Hint> = hout.to_base_prime_field_elements().map(Hint::Fq).collect();

        preimage_hints.extend_from_slice(&hint_apb);
        preimage_hints.extend_from_slice(&hint_ab);
        preimage_hints.extend_from_slice(&hint_p2le);
        preimage_hints.extend_from_slice(&hint_result);


        // [hints, apb, ab, c] [h]
        let tap_len= ops_scr.len();
        let scr = script!(
            for h in ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
            OP_NOT OP_VERIFY
            for h in preimage_hints.iter().rev() {
                {h.push()}
                {Fq::equalverify(1, 0)}
            }
            OP_TRUE
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("point_ops_and_multiply_line_evals_step_2 disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);


    }



    #[test]
    fn test_point_ops_and_multiply_line_evals_step_2() {
        let is_dbl = true;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], one_plus_ab_j_sq: ark_bn254::Fq6::ONE, a_plus_b: [ark_bn254::Fq2::ONE; 2]};
        let (inp, is_valid_input, _, _) = chunk_point_ops_and_multiply_line_evals_step_1(is_dbl, None, None, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(is_valid_input);

        let (hout, is_valid_input, ops_scr, ops_hints) = point_ops_and_multiply_line_evals_step_2(inp);
        assert!(is_valid_input);
        
        let mut preimage_hints = vec![];
        let hint_apb: Vec<Hint> = vec![inp.a_plus_b[0].c0, inp.a_plus_b[0].c1, inp.a_plus_b[1].c0, inp.a_plus_b[1].c1].into_iter().map(Hint::Fq).collect();
        let hint_ab: Vec<Hint> = inp.one_plus_ab_j_sq.to_base_prime_field_elements().map(Hint::Fq).collect();
        let hint_p2le: Vec<Hint> = vec![inp.p2le[0].c0, inp.p2le[0].c1, inp.p2le[1].c0, inp.p2le[1].c1].into_iter().map(Hint::Fq).collect();
        let hint_result: Vec<Hint> = hout.to_base_prime_field_elements().map(Hint::Fq).collect();

        preimage_hints.extend_from_slice(&hint_apb);
        preimage_hints.extend_from_slice(&hint_ab);
        preimage_hints.extend_from_slice(&hint_p2le);
        preimage_hints.extend_from_slice(&hint_result);


        // [hints, apb, ab, c] [h]
        let tap_len= ops_scr.len();
        let scr = script!(
            for h in ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {ops_scr}
            OP_VERIFY
            for h in preimage_hints.iter().rev() {
                {h.push()}
                {Fq::equalverify(1, 0)}
            }
            OP_TRUE
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("point_ops_and_multiply_line_evals_step_2 disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);


    }

    #[test]
    fn test_chunk_point_ops_and_multiply_line_evals_step_2() {
        let is_dbl = true;

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], one_plus_ab_j_sq: ark_bn254::Fq6::ONE, a_plus_b: [ark_bn254::Fq2::ONE; 2]};
        let (inp, is_valid_input,_, _) = chunk_point_ops_and_multiply_line_evals_step_1(is_dbl, None, None, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(is_valid_input);

        let (hint_out, is_valid_input, ops_scr, ops_hints) = chunk_point_ops_and_multiply_line_evals_step_2(inp);
        assert!(is_valid_input);

        let inp = DataType::G2EvalData(inp);
        let hint_out = DataType::Fp6Data(hint_out);
        let mut preimage_hints =  inp.to_witness(ElementType::G2EvalMul);
        preimage_hints.extend_from_slice(&hint_out.to_witness(ElementType::Fp6)); 

        let bitcom_scr = script!(
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {inp.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::G2EvalMul, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len= ops_scr.len() + hash_scr.len();
        let scr = script!(
            for h in ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {ops_scr}
            {hash_scr}
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("chunk_point_ops_and_multiply_line_evals_step_2 disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);


    }
    
    #[test]
    fn test_chunk_point_ops_and_multiply_line_evals_step_1() {
        let is_dbl = false;
        let is_frob: Option<bool> = Some(true);
        let ate_bit: Option<i8> = Some(-1);

        assert_eq!(is_dbl, is_frob.is_none() && ate_bit.is_none());
        assert_eq!(!is_dbl, is_frob.is_some() && ate_bit.is_some());


        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let t4 = ark_bn254::G2Affine::rand(&mut prng);
        let q4 = ark_bn254::G2Affine::rand(&mut prng);
        let p4 = ark_bn254::G1Affine::rand(&mut prng);
        let t3 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);

        let t2 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);

        let t4 = ElemG2Eval {t: t4, p2le:[ark_bn254::Fq2::ONE; 2], one_plus_ab_j_sq: ark_bn254::Fq6::ONE, a_plus_b: [ark_bn254::Fq2::ONE; 2]};
        let (hint_out, is_valid_input, ops_scr, ops_hints) = chunk_point_ops_and_multiply_line_evals_step_1(is_dbl, is_frob, ate_bit, t4, p4, Some(q4), p3, t3, Some(q3), p2, t2, Some(q2));
        assert!(is_valid_input);

        let t4 = DataType::G2EvalData(t4);
        let hint_out = DataType::G2EvalData(hint_out);
        let p4 = DataType::G1Data(p4);
        let p3 = DataType::G1Data(p3);
        let p2 = DataType::G1Data(p2);
     
        let mut preimage_hints = vec![];
        preimage_hints.extend_from_slice(&t4.to_witness(ElementType::G2EvalPoint));
        preimage_hints.extend_from_slice(&p4.to_witness(ElementType::G1));
        preimage_hints.extend_from_slice(&p3.to_witness(ElementType::G1));
        preimage_hints.extend_from_slice(&p2.to_witness(ElementType::G1));

        // chunk_point_eval_and_mul(hint_out);

        let bitcom_scr = script!(
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {p2.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {p3.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {p4.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {t4.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}

            if !is_dbl {
                {Fq::push(q4.y.c1)}
                {Fq::toaltstack()}
                {Fq::push(q4.y.c0)}
                {Fq::toaltstack()}
                {Fq::push(q4.x.c1)}
                {Fq::toaltstack()}
                {Fq::push(q4.x.c0)} 
                {Fq::toaltstack()}
            }
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::G2EvalPoint, ElementType::G1, ElementType::G1, ElementType::G1, ElementType::G2Eval])}
            OP_TRUE
        );

        let tap_len = ops_scr.len() + hash_scr.len();
        // [hints, t4, (q2), p4, p3]
        let scr = script!(
            for h in &ops_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {ops_scr}
            {hash_scr}
        );

        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("chunk_point_ops_and_multiply_line_evals_step_1 disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

}