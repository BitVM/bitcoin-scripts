use ark_ff::{AdditiveGroup, Field};
use crate::bn254::fq6::Fq6;
use crate::bn254::g2::{hinted_ell_by_constant_affine};
use crate::bn254::utils::{Hint};
use crate::bn254::{fq12::Fq12, fq2::Fq2};
use crate::chunk::blake3compiled::hash_messages;
use crate::{
    bn254::{fq::Fq},
    treepp::*,
};
use ark_ff::{ Fp12Config, Fp6Config};

use super::elements::{ElementType};

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



pub(crate) fn utils_fq12_mul(a: ark_bn254::Fq6, b: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let beta_sq = ark_bn254::Fq12Config::NONRESIDUE;
    let denom = ark_bn254::Fq6::ONE + a * b * beta_sq;
    let c = (a + b)/denom;

    let (ab, ab_scr, ab_hints) = {
        let r = Fq6::hinted_mul(6, a, 0, b);
        (a*b, r.0, r.1)
    };
    assert_eq!(ab, a*b);

    let (denom_mul_c_scr, denom_mul_c_hints) = Fq6::hinted_mul(6, denom, 0, c);

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
        {ab_scr}
        // [hints, a, b, ab]
        {mul_by_beta_sq_scr}
        // [hints, a, b, ab*beta_sq]
        {Fq6::push(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, a, b, denom]
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
    );

    let mut hints = vec![];
    hints.extend_from_slice(&ab_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    (c, scr, hints)
}

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

pub(crate) fn chunk_hinted_square(a: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let (asq, asq_scr, asq_hints) = hinted_square(a);
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
    );
    let scr = script!(
        // [hints, a, c] [chash, ahash]
        {asq_scr}
        // [a, c] [chash, ahash]
    );

    (asq, scr, asq_hints)
}

pub(crate) fn chunk_dense_dense_mul(a: ark_bn254::Fq6, b:ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let (amulb, amulb_scr, amulb_hints) = utils_fq12_mul(a, b);
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6, ElementType::Fp6, ElementType::Fp6])}
    );
    let scr = script!(
        // [hints, a, b, c] [chash, bhash, ahash]
        {amulb_scr}
        // [a, b, c] [chash, bhash, ahash]
    );

    (amulb, scr, amulb_hints)
}

pub(crate) fn hinted_square(a: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let denom = ark_bn254::Fq6::ONE + a * a * ark_bn254::Fq12Config::NONRESIDUE;
    let c = (a + a)/denom;

    let (asq_scr, asq_hints) = Fq6::hinted_square(a);
    let (denom_mul_c_scr, denom_mul_c_hints) = Fq6::hinted_mul(6, denom, 0, c);

    let mul_by_beta_sq_scr = script!(
        {Fq6::mul_fq2_by_nonresidue()}
        {Fq2::roll(4)} {Fq2::roll(4)}
    );

    let scr = script!(
        // [hints a, c] []
        {Fq6::toaltstack()}
        // [a] [c]
        {Fq6::copy(0)}
        // [hints a, a] [c]
        {asq_scr}
        // [hints, a, asq]
        {mul_by_beta_sq_scr}
        // [hints, a, asq*beta_sq]
        {Fq6::push(ark_bn254::Fq6::ONE)}
        {Fq6::add(6, 0)}
        // [hints, a, denom]
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
    );

    let mut hints = vec![];
    hints.extend_from_slice(&asq_hints);
    hints.extend_from_slice(&denom_mul_c_hints);

    (c, scr, hints)
}


pub(crate) fn utils_fq6_hinted_sd_mul(m: ark_bn254::Fq6, n: ark_bn254::Fq6) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let a = m.c0;
    let b = m.c1;
    let c = m.c2;
    let d = n.c0;
    let e = n.c1;

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


#[cfg(test)]
mod test {

    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6}, chunk::{blake3compiled::hash_messages, elements::{DataType, ElementType},  taps_mul::{chunk_dense_dense_mul, chunk_hinted_square, hinted_square, utils_fq6_hinted_sd_mul, utils_fq6_ss_mul}}, execute_script, execute_script_without_stack_limit };

    
    #[test]
    fn test_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mut mul_hints) = hinted_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);
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
            {Fq6::push(h_n.c1)}
            {Fq6::equalverify()}
            {Fq6::push(f_n.c1)}
            {Fq6::equalverify()}
            OP_TRUE
        );
        let res = execute_script(scr);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_chunk_hinted_square() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let h = f * f;
        let h_n =ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, h.c1/h.c0);

        let (hint_out, h_scr, mul_hints) = chunk_hinted_square(f_n.c1);
        assert_eq!(h_n.c1, hint_out);

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
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
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

        let (hint_out, h_scr, mul_hints) = chunk_dense_dense_mul(f_n.c1, g_n.c1);
        assert_eq!(h_n.c1, hint_out);

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
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success); 
        assert!(res.final_stack.len() == 1);
        println!("script {} stack {:?}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_hinted_fq6_mul_le0_le1() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let m = ark_bn254::Fq6::rand(&mut prng);
        let mut n = ark_bn254::Fq6::rand(&mut prng);
        n.c2 = ark_bn254::Fq2::ZERO;
        let o = m * n;

        let (res, ops_scr, hints) = utils_fq6_hinted_sd_mul(m, n);

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
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        println!("scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

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
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success); 
        println!("scr len {:?} @ stack {:?}", ops_len, res.stats.max_nb_stack_items);

    }



}