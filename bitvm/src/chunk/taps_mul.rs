use ark_ff::{AdditiveGroup, Field};
use crate::bn254::fq6::Fq6;
use crate::bn254::g2::{hinted_ell_by_constant_affine};
use crate::bn254::utils::{Hint};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::wrap_hasher::hash_messages;
use crate::treepp::*;
use ark_ff::{ Fp12Config, Fp6Config};

use super::elements::{ElementType};

/// Input two sparse Fq6 elements where the third coefficient is Fq2::ZERO
/// Multiply these elements and return result.
/// Given m = (a, b, 0) n = (d, e, 0).
/// Compute mxn = (ad, bd + ae, be)
pub(crate) fn utils_fq6_ss_mul(m: ark_bn254::Fq6, n: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let d = n.c0;
    let e = n.c1;

    let g = a * d;
    let h = b * d + a * e;
    let i = b * e;
    let result = ark_bn254::Fq6::new(g, h, i);

    let (g_scr, g_hints) = Fq2::hinted_mul(2, d, 0, a);
    // We use lc4 to compute h as it requires lesser number of tmul hints compared to doing the same thing with two LC2s
    let (h_scr, h_hints) = Fq2::hinted_mul_lc4_keep_elements(b, d, e, a);
    let (i_scr, i_hints) = Fq2::hinted_mul(2, e, 0, b);

    let mut hints = vec![];
    for hint in [i_hints, g_hints, h_hints] {
        hints.extend_from_slice(&hint);
    }

    let scr = script!(
        // [a, b, d, e]
        {Fq2::copy(0)} {Fq2::copy(6)}
        // [a, b, d, e, e, b]
        {i_scr}
        // [a, b, d, e, i]
        {Fq2::toaltstack()}
        // [a, b, d, e]
        {Fq2::toaltstack()}
        {Fq2::copy(0)} {Fq2::copy(6)}
        // [a, b, d, d, a] [i, e]
        {g_scr}
        // [a, b, d, g] [i, e]
        {Fq2::fromaltstack()} {Fq2::roll(2)}
        {Fq2::toaltstack()}
        // [a, b, d, e] [i, g]
        {Fq2::roll(6)}
        // [b, d, e, a] [i, g]
        {h_scr} {Fq2::toaltstack()}
        // [b, d, e, a] [i, g, h]
        {Fq6::roll(2)}
        // [a, b, d, e] [i, g, h]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()}
        {Fq2::roll(2)} {Fq2::fromaltstack()}
        // [a, b, d, e, g, h, i] 
    );
    (result, scr, hints)
}

/// Input a dense Fq6 element m <- (a, b, c) and a sparse Fq6 element n <- (d, e, 0)
/// Multiply these elements and return result.
/// Compute mxn = (ad + ce J^2, bd + ae, cd + be)
pub(crate) fn utils_fq6_sd_mul(m: ark_bn254::Fq6, n: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let c = m.c2;
    let d = n.c0;
    let e = n.c1;
    assert_eq!(n.c2, ark_bn254::Fq2::ZERO);

    let g = a*d + c * e * ark_bn254::Fq6Config::NONRESIDUE;
    let h = (b*d ) + (a * e);
    let i = c * d + b * e;
    let result = ark_bn254::Fq6::new(g, h, i);

    let mut hints = vec![];
    let (i_scr, i_hints) = Fq2::hinted_mul_lc4_keep_elements(c, d, e, b);
    let (h_scr, h_hints) = Fq2::hinted_mul_lc4_keep_elements(d, b, e, a); 
    let (g_scr, g_hints) = Fq2::hinted_mul_lc4_keep_elements(e * ark_bn254::Fq6Config::NONRESIDUE, c, d, a);


    for hint in [i_hints, h_hints, g_hints] {
        hints.extend_from_slice(&hint);
    }

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
    );

    let scr = script!(
        // [a, b, c, d, e]
        {Fq2::roll(6)}
         // [a, c, d, e, b]
        {i_scr}
        // [a, c, d, e, b, i]
        {Fq2::toaltstack()}

        // [a, c, d, e, b]
        {Fq2::roll(2)}  {Fq2::roll(8)}
        // [c, d, b, e, a]
        {h_scr} 
        {Fq2::toaltstack()}
        // [c, d, b, e, a] [i, h]
        {Fq2::copy(2)} {Fq2::toaltstack()}
        // [c, d, b, e, a] [i, h, e]
        {Fq2::toaltstack()}
        {mul_by_beta_sq_scr}
        // [c, d, b, ebeta] [i, h, e, a]
        {Fq2::roll(6)}
        // [d, b, ebeta, c] [i, h, e, a]
        {Fq2::roll(6)}
        // [b, ebeta, c, d] [i, h, e, a]
        {Fq2::fromaltstack()}
        // [b, ebeta, c, d, a] [i, h, e]
        {g_scr}
        // [b, ebeta, c, d, a, g] [i, h , e]
        {Fq2::toaltstack()}
        // [b, ebeta, c, d, a] [i, h, e, g]
        {Fq2::roll(6)} {Fq2::drop()}
         // [b, c, d, a] [i, h, e g]
        {Fq6::roll(2)}
         // [a,b, c, d,] [i, h, e, g]
        {Fq2::fromaltstack()} {Fq2::fromaltstack()} 
         // [a,b, c, d, g, e] [i, h]
         {Fq2::roll(2)} {Fq2::toaltstack()}
        //  {Fq2::push(ark_bn254::Fq2::ZERO)}
        // [a,b, c, d, e, _f] [i, h, g]
        {Fq6::fromaltstack()}
        // [a, b, c, d, e, _f, g, h, i]
    );
    (result, scr, hints)
}


/// Given line evaluation f, line coeff (alpha_t3, neg_bias_t3) and point P3,
/// Compute line evaluation 'g' at P3 and multiply it with f.
/// Return Script and Hints for the computation and return the line evaluation g.
/// Compute g = le_{t3} (P3); h = f * g;
/// Return (g, Script(Compute), Hints(Compute))
pub(crate) fn utils_multiply_by_line_eval(
    f: ark_bn254::Fq6,
    alpha_t3: ark_bn254::Fq2,
    neg_bias_t3: ark_bn254::Fq2,
    p3: ark_bn254::G1Affine,
) -> (ark_bn254::Fq6, Script, Vec<Hint>) {

    assert_eq!(f.c2, ark_bn254::Fq2::ZERO);

    let mut l0_t3 = alpha_t3;
    l0_t3.mul_assign_by_fp(&p3.x);
    let mut l1_t3 = neg_bias_t3;
    l1_t3.mul_assign_by_fp(&p3.y);

    let (hinted_ell_t3, hints_ell_t3) = hinted_ell_by_constant_affine(p3.x, p3.y, alpha_t3, neg_bias_t3);

    let g = ark_bn254::Fq6::new(l0_t3, l1_t3, ark_bn254::Fq2::ZERO);
    let (_, fg_scr, fg_hints) = utils_fq6_ss_mul(g, f);
    
    let scr = script!(
        // [f, p3]
        {Fq2::copy(0)}
        // [f, p3, p3]
        {Fq2::push(alpha_t3)}
        {Fq2::push(neg_bias_t3)}
        // [f, p3, p3, a, b]
        {Fq2::roll(4)}
        // [f, p3, a, b, p3]
        {hinted_ell_t3}
        // [f, p3, le0, le1]
        // [f, p3, g]
        {Fq2::roll(8)} {Fq2::roll(8)}
        // [p3, g, f]
        {fg_scr}
        // [p3, g, f, fg]
    );

    let mut hints = vec![];
    hints.extend_from_slice(&hints_ell_t3);
    hints.extend_from_slice(&fg_hints);

    (g, scr, hints)

}


/// Compute product of two Fq12 elements in normalized form (1 + c J) <- (1 + a J) x (1 + b J).
/// Input a, b and output c.
// In this form (1 + c J) <- 1 + {(a+b)/(1 + ab J^2)}
// => c . (1 + ab J^2) =?= (a + b)
// a, b and c are passed as input to the script and the above equation is validated to show that c is the correct output
// For invalid input i.e (a + b) == 0 OR (1 + ab J ^2) == 0, return [a, b, c]
pub(crate) fn utils_fq12_dd_mul(a: ark_bn254::Fq6, b: ark_bn254::Fq6) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    let mut hints = vec![];

    let mock_value = ark_bn254::Fq6::ONE;
    let mut c = mock_value;

    let fq6_mul_script = Fq6::hinted_mul(6, ark_bn254::Fq6::ONE, 0, ark_bn254::Fq6::ONE).0;
    let (ab_scr, denom_mul_c_scr) = (fq6_mul_script.clone(), fq6_mul_script); // script to Fq6::mul is same indifferent to value
    
    let mut input_is_valid = false;
    if a + b != ark_bn254::Fq6::ZERO {
        let res = Fq6::hinted_mul(6, a, 0, b);
        hints.extend_from_slice(&res.1);

        let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
        let denom = ark_bn254::Fq6::ONE + a * b * beta_sq;
        if denom != ark_bn254::Fq6::ZERO {
            c = (a + b) / denom;
            input_is_valid = true;
            let res = Fq6::hinted_mul(6, denom, 0, c);
            hints.extend_from_slice(&res.1);
        }
    } 

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, b, c] []
        {Fq6::toaltstack()}
        // [a b] [c]
        {Fq12::copy(0)}
        // [hints a, b, a, b] [c]
        {Fq6::add(6, 0)}
        // [hints a, b, apb] [c]
        {Fq6::is_zero()} // apb =?= 0
        OP_IF 
            // [a, b] [c]
            {Fq6::fromaltstack()}
            {Fq6::drop()}
            {Fq6::push(mock_value)}
            {0}
            // [a, b mock_c, 0] []
        OP_ELSE
            // [hints a, b] [c]
            {Fq12::copy(0)}
            // [hints a, b, a, b] [c]
            {ab_scr}
            // [hints, a, b, ab]
            {mul_by_beta_sq_scr}
            // [hints, a, b, ab*beta_sq]
            {Fq6::push(ark_bn254::Fq6::ONE)}
            {Fq6::add(6, 0)}
            // [hints, a, b, denom] [c]
            {Fq6::copy(0)}
            {Fq6::is_zero()} // denom =?= 0
            OP_IF 
                // [a, b, denom] [c]
                {Fq6::drop()}
                {Fq6::fromaltstack()}
                // [a, b c] []
                {Fq6::drop()}
                {Fq6::push(mock_value)}
                {0}
                // [a, b mock_c, 0] []
            OP_ELSE
                {Fq6::fromaltstack()}
                // [hints, a, b, denom, c]
                {Fq6::copy(0)}
                // [hints, a, b, denom, c, c]
                {Fq12::roll(6)}
                // [hints, a, b, c, denom, c]

                {denom_mul_c_scr}

                // [a, b c, denom_c]
                {Fq12::copy(12)}
                // [a, b c, denom_c, a b]
                {Fq6::add(6, 0)}
                // [a, b c, denom_c, a+b]
                {Fq6::equalverify()}
                // [a, b, c] []
                {1}
                // {a, b, c, 1}
            OP_ENDIF
        OP_ENDIF
        // [a, b, c, 0/1] []
    );

    (c, input_is_valid, scr, hints)
}

/// Compute square of an Fq12 elements in normalized form (1 + c J) <- (1 + a J) x (1 + a J).
/// Input a, and output c.
// In this form (1 + c J) <- 1 + {(2a)/(1 + a^2 J^2)}
// => c . (1 + a^2 J^2) =?= 2a
// a c are passed as input to the script and the above equation is validated to show that c is the correct output
// Assumes input a is valid i.e (a + a) != 0 and (1 + a^2 J ^2) != 0
pub(crate) fn utils_fq12_square(a: ark_bn254::Fq6) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    let mut hints = vec![];

    let mock_value = ark_bn254::Fq6::ONE;
    let mut c = mock_value;

    let mut input_is_valid = false;

    let (asq_scr, denom_mul_c_scr) = (Fq6::hinted_square(ark_bn254::Fq6::ONE).0, Fq6::hinted_mul(6, ark_bn254::Fq6::ONE, 0, ark_bn254::Fq6::ONE).0);
    if a != ark_bn254::Fq6::ZERO {
        let res = Fq6::hinted_square(a);
        hints.extend_from_slice(&res.1);

        let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
        let denom = ark_bn254::Fq6::ONE + a * a * beta_sq;
        if denom != ark_bn254::Fq6::ZERO {
            input_is_valid = true;
            c = (a + a) / denom;
            let res = Fq6::hinted_mul(6, denom, 0, c);
            hints.extend_from_slice(&res.1);
        }
    }

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, c] []
        {Fq6::toaltstack()}
        // [hints, a] [c]
        {Fq6::copy(0)}
        {Fq6::is_zero()}
        OP_IF
            // [a] [c]
            {Fq6::fromaltstack()}
            // [a, c]
            {Fq6::drop()}
            {Fq6::push(mock_value)}
            {0}
            // [a, mock_c, 0]
        OP_ELSE
            // [hints, a, c]
            {Fq6::copy(0)}
            // [hints a, a] [c]
            {asq_scr}
            // [hints, a, asq]
            {mul_by_beta_sq_scr}
            // [hints, a, asq*beta_sq]
            {Fq6::push(ark_bn254::Fq6::ONE)}
            {Fq6::add(6, 0)}
            // [hints, a, denom] [c]
            {Fq6::copy(0)}
            {Fq6::is_zero()}
            OP_IF 
                // [a, denom] [c]
                {Fq6::drop()}
                {Fq6::push(mock_value)}
                {0}
                // [a, mock_c, 0]
            OP_ELSE
                {Fq6::fromaltstack()}
                // [hints, a, denom, c]
                {Fq6::copy(0)}
                // [hints, a, denom, c, c]
                {Fq6::roll(12)} {Fq6::roll(12)}
                // [hints, a, c, denom, c]

                {denom_mul_c_scr}

                // [a, c, denom_c]
                {Fq6::copy(12)}
                // [a, c, denom_c, a]
                {Fq6::double(0)}
                // [a, c, denom_c, 2a]
                {Fq6::equalverify()}
                // [a,c] []
                {1}
            OP_ENDIF
        OP_ENDIF
        // [a, c, 0/1]
    );

    (c, input_is_valid, scr, hints)
}

pub(crate) fn chunk_fq12_square(a: ark_bn254::Fq6) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    let (asq, is_valid_input, asq_scr, asq_hints) = utils_fq12_square(a);
    let _hash_scr = hash_messages(vec![ElementType::Fp6, ElementType::Fp6]);
    let scr = script!(
        // [hints, a, c] [chash, ahash]
        {asq_scr}
        // [a, asq, 0/1] [chash, ahash]
    );

    (asq, is_valid_input, scr, asq_hints)
}

pub(crate) fn chunk_dense_dense_mul(a: ark_bn254::Fq6, b:ark_bn254::Fq6) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    let (amulb, input_is_valid, amulb_scr, amulb_hints) = utils_fq12_dd_mul(a, b);
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
    );
    let scr = script!(
        // [hints, a, b, c] [chash, bhash, ahash]
        {amulb_scr}
        // [a, b, amulb, 0/1] [chash, bhash, ahash]
    );

    (amulb, input_is_valid, scr, amulb_hints)
}


#[cfg(test)]
mod test {

    use ark_ff::{AdditiveGroup, Field, Fp12Config, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6}, chunk::{wrap_hasher::hash_messages, elements::{DataType, ElementType},  taps_mul::{chunk_dense_dense_mul, chunk_fq12_square, utils_fq12_dd_mul, utils_fq12_square, utils_fq6_sd_mul, utils_fq6_ss_mul}}, execute_script, execute_script_without_stack_limit };

    
    #[test]
    fn test_utils_fq12_square_valid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, is_valid_input, h_scr, mut mul_hints) = utils_fq12_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);
        assert!(is_valid_input);
        let f_n_c1 = DataType::Fp6Data(f_n.c1);
        let h_n_c1 = DataType::Fp6Data(h_n.c1);

        let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
        let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
        mul_hints.extend_from_slice(&f6_hints);
        mul_hints.extend_from_slice(&h6_hints);

        let tap_len = h_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            {h_scr}
            OP_VERIFY
            {Fq6::push(hint_out)}
            {Fq6::equalverify()}
            {Fq6::push(f_n.c1)}
            {Fq6::equalverify()}
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
        println!("utils_fq12_square disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_utils_fq12_square_invalid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // todo: add test for 1 + a^2 J^2 == 0 => find value of a ?
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, ark_bn254::Fq6::ZERO);
        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        run_for_invalid_inputs(f_n, h_n);

        fn run_for_invalid_inputs(f_n: ark_bn254::Fq12, h_n: ark_bn254::Fq12) {
            let (hint_out, is_valid_input, h_scr, mut mul_hints) = utils_fq12_square(f_n.c1);
            assert!(!is_valid_input);
            let f_n_c1 = DataType::Fp6Data(f_n.c1);
            let h_n_c1 = DataType::Fp6Data(h_n.c1);
    
            let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
            let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
            mul_hints.extend_from_slice(&f6_hints);
            mul_hints.extend_from_slice(&h6_hints);
    
            let tap_len = h_scr.len();
            let scr= script!(
                for h in mul_hints {
                    {h.push()}
                }
                {h_scr}
                OP_NOT OP_VERIFY
                {Fq6::push(hint_out)}
                {Fq6::equalverify()}
                {Fq6::push(f_n.c1)}
                {Fq6::equalverify()}
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
            println!("utils_fq12_square disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
        }

    }

    #[test]
    fn test_chunk_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, input_is_valid, h_scr, mul_hints) = chunk_fq12_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);
        assert!(input_is_valid);

        let f_n_c1 = DataType::Fp6Data(f_n.c1);
        let h_n_c1 = DataType::Fp6Data(h_n.c1);
        let hint_out = DataType::Fp6Data(hint_out);

        let mut preimage_hints = vec![];
        let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
        let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let bitcom_scr = script!(
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {f_n_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = h_scr.len() + hash_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {h_scr}
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
        println!("chunk_fq12_square disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_utils_fq12_dd_mul_valid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, is_valid_input, h_scr, mul_hints) = utils_fq12_dd_mul(f_n.c1, g_n.c1);
        assert_eq!(h_n.c1, hint_out);
        assert!(is_valid_input);

        let f_n_c1 = DataType::Fp6Data(f_n.c1);
        let g_n_c1 = DataType::Fp6Data(g_n.c1);
        let h_n_c1 = DataType::Fp6Data(h_n.c1);

        let mut preimage_hints = vec![];
        let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
        let g6_hints = g_n_c1.to_witness(ElementType::Fp6);
        let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&g6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let tap_len = h_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in &preimage_hints {
                {h.push()}
            }
            // [hints, f, g, h]
            {h_scr}
            // [f, g, h, 1]
            OP_VERIFY
            {Fq6::push(hint_out)}
            {Fq6::equalverify()}
            for h in g6_hints.iter().rev() {
                {h.push()}
                {Fq::equalverify(1, 0)}
            }
            for h in f6_hints.iter().rev() {
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
        println!("utils_fq12_dd_mul disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_utils_fq12_dd_mul_invalid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        // a + b == 0
        // b = -a
        let invalid_g_n = -f_n.c1; 
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, invalid_g_n);
        run_for_invalid_inputs(f_n, g_n);

        // 1 + ab J^2 == 0
        // b = -1/(a J^2)
        let invalid_g_n = -(f_n.c1 * ark_bn254::Fq12Config::NONRESIDUE).inverse().unwrap(); 
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, invalid_g_n);
        run_for_invalid_inputs(f_n, g_n);
        
        fn run_for_invalid_inputs(f_n: ark_bn254::Fq12, g_n: ark_bn254::Fq12) {
            let h_n = f_n * g_n;

            let h_n = if h_n.c0 != ark_bn254::Fq6::ZERO {
                ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h_n.c1/h_n.c0)
            } else {
                ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, ark_bn254::Fq6::ZERO)
            };
    
            let (hint_out, is_valid_input, h_scr, mul_hints) = utils_fq12_dd_mul(f_n.c1, g_n.c1);
            assert!(!is_valid_input);         
    
            let f_n_c1 = DataType::Fp6Data(f_n.c1);
            let g_n_c1 = DataType::Fp6Data(g_n.c1);
            let h_n_c1 = DataType::Fp6Data(h_n.c1);
    
            let mut preimage_hints = vec![];
            let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
            let g6_hints = g_n_c1.to_witness(ElementType::Fp6);
            let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
            preimage_hints.extend_from_slice(&f6_hints);
            preimage_hints.extend_from_slice(&g6_hints);
            preimage_hints.extend_from_slice(&h6_hints);
    
            let tap_len = h_scr.len();
            let scr= script!(
                for h in mul_hints {
                    {h.push()}
                }
                for h in &preimage_hints {
                    {h.push()}
                }
                // [hints, f, g, h]
                {h_scr}
                // [f, g, hint_out, 0]
                OP_NOT OP_VERIFY
                {Fq6::push(hint_out)}
                {Fq6::equalverify()}
                for h in g6_hints.iter().rev() {
                    {h.push()}
                    {Fq::equalverify(1, 0)}
                }
                for h in f6_hints.iter().rev() {
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
            println!("utils_fq12_dd_mul disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
        }

    }

    #[test]
    fn test_chunk_dense_dense_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, is_valid_input, h_scr, mul_hints) = chunk_dense_dense_mul(f_n.c1, g_n.c1);
        assert_eq!(h_n.c1, hint_out);
        assert!(is_valid_input);

        let f_n_c1 = DataType::Fp6Data(f_n.c1);
        let g_n_c1 = DataType::Fp6Data(g_n.c1);
        let h_n_c1 = DataType::Fp6Data(h_n.c1);
        let hint_out = DataType::Fp6Data(hint_out);

        let mut preimage_hints = vec![];
        let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
        let g6_hints = g_n_c1.to_witness(ElementType::Fp6);
        let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&g6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let bitcom_scr = script!(
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {g_n_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {f_n_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = h_scr.len() + hash_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {h_scr}
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
        println!("chunk_dense_dense_mul disprovable(false) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_chunk_dense_dense_mul_invalid_data() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let g = ark_bn254::Fq12::rand(&mut prng);
        let g_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, -f.c1/f.c0);

        let h = f * g;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, is_invalid_input, h_scr, mul_hints) = chunk_dense_dense_mul(f_n.c1, g_n.c1);
        assert!(!is_invalid_input);

        let f_n_c1 = DataType::Fp6Data(f_n.c1);
        let g_n_c1 = DataType::Fp6Data(g_n.c1);
        let h_n_c1 = DataType::Fp6Data(h_n.c1);
        let hint_out = DataType::Fp6Data(hint_out);

        let mut preimage_hints = vec![];
        let f6_hints = f_n_c1.to_witness(ElementType::Fp6);
        let g6_hints = g_n_c1.to_witness(ElementType::Fp6);
        let h6_hints = h_n_c1.to_witness(ElementType::Fp6);
        preimage_hints.extend_from_slice(&f6_hints);
        preimage_hints.extend_from_slice(&g6_hints);
        preimage_hints.extend_from_slice(&h6_hints);

        let bitcom_scr = script!(
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {g_n_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {f_n_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        );

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = h_scr.len() + hash_scr.len();
        let scr= script!(
            for h in mul_hints {
                {h.push()}
            }
            for h in preimage_hints {
                {h.push()}
            }
            {bitcom_scr}
            {h_scr}
            {hash_scr}
        );
        let res = execute_script(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("chunk_dense_dense_mul disprovable(true) script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_utils_fq6_sd_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        n.c2 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_sd_mul(m, n);

        assert_eq!(res, o);
        let ops_len = ops_scr.len();
        let scr = script!(
            for h in hints {
                {h.push()}
            }
            {Fq2::push(m.c0)}
            {Fq2::push(m.c1)}
            {Fq2::push(m.c2)}
            {Fq2::push(n.c0)}
            {Fq2::push(n.c1)}
            {ops_scr}
            {Fq6::push(o)}
            {Fq6::equalverify()}
            {Fq2::push(n.c1)}
            {Fq2::equalverify()}
            {Fq2::push(n.c0)}
            {Fq2::equalverify()}
            {Fq6::push(m)}
            {Fq6::equalverify()}
            OP_TRUE
        );
        let res = execute_script_without_stack_limit(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        println!("utils_fq6_sd_mul disprovable(false) scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

    }

    #[test]
    fn test_utils_fq6_ss_mul() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        m.c2 = ark_bn254::Fq2::ZERO;
        n.c2 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_ss_mul(m, n);
        assert_eq!(res, o);
        let ops_len = ops_scr.len();
        let scr = script!(
            for h in hints {
                {h.push()}
            }
            {Fq2::push(m.c0)}
            {Fq2::push(m.c1)}
            {Fq2::push(n.c0)}
            {Fq2::push(n.c1)}
            {ops_scr}
            {Fq6::push(o)}
            {Fq6::equalverify()}
            for v in vec![n.c1, n.c0, m.c1, m.c0] {
                {Fq2::push(v)}
                {Fq2::equalverify()}
            }
            OP_TRUE
        );
        let res = execute_script_without_stack_limit(scr);
        if res.final_stack.len() > 1 {
            for i in 0..res.final_stack.len() {
                println!("{i:} {:?}", res.final_stack.get(i));
            }
        }
        assert!(res.success); 
        println!("utils_fq6_ss_mul disprovable(false) scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

    }
}