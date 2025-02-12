use std::{ops::Neg, str::FromStr};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use bitcoin_script::script;
use num_bigint::BigUint;
use crate::treepp::Script;

use super::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, g2::{hinted_affine_add_line, hinted_affine_double_line, hinted_check_chord_line, hinted_check_tangent_line, G2Affine}, utils::Hint};

fn split_scalar(window: usize, scalar: u64) -> Vec<Vec<u8>> {
    fn u64_to_bits(x: u64) -> Vec<u8> {
        let mut bits = Vec::with_capacity(64);
        for i in 0..64 {
            // Shift so that we're checking the (63 - i)-th bit from the right.
            // That puts the most significant bit at i = 0.
            let bit = ((x >> (63 - i)) & 1) as u8;
            if bit == 0 {
                bits.push(0); // dbl
            } else if bit == 1 {
                bits.push(0); // dbl
                bits.push(1); // add
            }
        }
        bits
    }
    let mut scalar_bits: Vec<Vec<u8>> = vec![];
    u64_to_bits(scalar).chunks(window).for_each(|c| {
        scalar_bits.push(c.to_vec());
    });
    scalar_bits
}

fn hinted_check_double_and_add(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine, bits: Vec<u8>) -> (Script, Vec<Hint>) {
    let mut hints: Vec<Hint> = vec![];
    let mut acc = t;
    let mut script = script!();
    for bit in bits {
        if bit == 0 {
            let (scr, hint) = hinted_check_double(acc);
            hints.extend_from_slice(&hint);
            script = script!(
                {script}
                // [t, q]
                {Fq2::toaltstack()} {Fq2::toaltstack()}
                // [t]
                {scr}
                // [2t]
                {Fq2::fromaltstack()} {Fq2::fromaltstack()}
                // [2t, q]
            );
            acc = (acc + acc).into_affine(); // double
            
        } else if bit == 1 {
            let (scr, hint) = hinted_check_add(acc, q);
            hints.extend_from_slice(&hint);
            script = script!(
                {script}
                // [t. q]
                {Fq2::copy(2)} {Fq2::copy(2)}
                // [t, q, q]
                {Fq2::toaltstack()} {Fq2::toaltstack()}
                // [t, q]
                {scr}
                // [t+q]
                {Fq2::fromaltstack()} {Fq2::fromaltstack()}
                // [t+q, q]
            );
            acc = (acc + q).into_affine();   // add
        }
    }
    // drop q
    script = script!(
        {script}
        {Fq2::drop()}     
        {Fq2::drop()}
    );
    (script, hints)
}

fn hinted_check_double(t: ark_bn254::G2Affine) -> (Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let (alpha, bias) = if t_is_zero {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    } else {
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y); 
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    };

    let (hinted_script1, hint1) = hinted_check_tangent_line(t,alpha, bias);
    let (hinted_script2, hint2) = hinted_affine_double_line(t.x,alpha, bias);

    if !t_is_zero { 
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
    }

    let script = script! {       
        { G2Affine::is_zero_keep_element() }         // ... (dependent on input),  x, y, 0/1
        OP_NOTIF                                     // c3 (alpha), c4 (-bias), ... (other hints), x, y
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // -bias, ...,  x, y, alpha
            for _ in 0..Fq::N_LIMBS * 2 {
                OP_DEPTH OP_1SUB OP_ROLL 
            }                                        // x, y, alpha, -bias
            { Fq2::copy(6) }                          // x, y, alpha, -bias, x
            { Fq2::roll(6) }                          // x, alpha, -bias, x, y
            { hinted_script1 }                       // x, alpha, -bias, is_tangent_line_correct 
            { Fq2::roll(4) }                          // alpha, -bias, x
            { hinted_script2 }                       // alpha, -bias, x', y'
            {Fq2::toaltstack()}
            {Fq2::toaltstack()}
            {Fq2::drop()}
            {Fq2::drop()}
            {Fq2::fromaltstack()}
            {Fq2::fromaltstack()}                      // x', y'

        OP_ENDIF
    };
    (script, hints)
}

fn hinted_check_add(t: ark_bn254::G2Affine, q: ark_bn254::G2Affine) -> (Script, Vec<Hint>) {
    let mut hints = vec![];

    let t_is_zero = t.is_zero() || (t == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // t is none or Some(0)
    let q_is_zero = q.is_zero() || (q == ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)); // q is none or Some(0)
    
    let (alpha, bias) = if !t_is_zero && !q_is_zero && t != -q { // todo: add if t==q and if t == -q
        let alpha = (t.y - q.y) / (t.x - q.x);
        let bias = t.y - alpha * t.x;
        (alpha, bias)
    } else {
        (ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
    };

    let (hinted_script1, hint1) = hinted_check_chord_line(t, q, alpha, bias); // todo: remove unused arg: bias
    let (hinted_script2, hint2) = hinted_affine_add_line(t.x, q.x, alpha, bias);

    if !t.is_zero() && !q.is_zero() && t != -q {
        hints.push(Hint::Fq(alpha.c0));
        hints.push(Hint::Fq(alpha.c1));
        hints.push(Hint::Fq(-bias.c0));
        hints.push(Hint::Fq(-bias.c1));
        hints.extend(hint1);
        hints.extend(hint2);
    }

    let script = script! {        // tx ty qx qy
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
                    }                                  // qx qy tx ty c3 c4
                    { Fq2::copy(6) }
                    { Fq2::roll(6) }                    // qx qy tx c3 c4 tx ty
                    { Fq2::copy(12) }
                    { Fq2::roll(12) }                    // qx tx c3 c4 tx ty qx qy
                    { hinted_script1 }                 // qx tx c3 c4 0/1
                    { Fq2::roll(4) }
                    { Fq2::roll(6) }                    // c3 c4 tx qx
                    { hinted_script2 }                 // c3 c4 x' y'
                    {Fq2::toaltstack()}
                    {Fq2::toaltstack()}
                    {Fq2::drop()}
                    {Fq2::drop()}
                    {Fq2::fromaltstack()}
                    {Fq2::fromaltstack()}              // x', y'
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    };
    (script, hints)
}

fn hinted_msm(scalar: u64, q: ark_bn254::G2Affine, window: usize) -> Vec<(ark_bn254::G2Affine, Script, Vec<Hint>)> {
    let scalar_splits = split_scalar(window, scalar);
    let mut acc = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
    let mut chunks = vec![];
    for bits in scalar_splits {
        let chunk = hinted_check_double_and_add(acc, q, bits.clone());
        for bit in &bits {
            if *bit == 0 {
                acc = (acc + acc).into_affine();
            } else if *bit == 1 {
                acc = (acc + q).into_affine();
            }
        }
        chunks.push((acc, chunk.0, chunk.1));
    }
    // println!("chunks {:?}", chunks);
    chunks
}


// Stack: [q] q /in G2Affine
// compute q' = (q.x.conjugate()*beta_12, q.y.conjugate() * beta_13)
fn hinted_mul_by_char_on_q(q: ark_bn254::G2Affine) -> (ark_bn254::G2Affine, Script, Vec<Hint>) {
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


// ψ([x₀]P) + ψ²([x₀]P) - ψ³([2x₀]P)
fn g2_chain_endomorphism(t: ark_bn254::G2Affine) -> (ark_bn254::G2Affine, Script, Vec<Hint>) {

    let (sai_t, sai_t_scr, sai_t_hints) = hinted_mul_by_char_on_q(t);
    let (sai_2_t, sai_2_t_scr, sai_2_t_hints) = hinted_mul_by_char_on_q(sai_t);
    let (sai_3_t, sai_3_t_scr, sai_3_t_hints) = hinted_mul_by_char_on_q(sai_2_t);
    let (double_sai_3_t_scr, double_sai_3_t_hints) = hinted_check_double(sai_3_t);
    let mut sai_neg_dbl_3_t = (sai_3_t + sai_3_t).into_affine();
    sai_neg_dbl_3_t = sai_neg_dbl_3_t.neg();

    let (sai_add_0_scr, sai_add_0_hints) = hinted_check_add(sai_2_t, sai_neg_dbl_3_t);
    let sai_add_0 = (sai_neg_dbl_3_t + sai_2_t).into_affine();

    let (sai_add_1_scr, sai_add_1_hints) = hinted_check_add(sai_t, sai_add_0);
    let sai_add_1 = (sai_add_0 + sai_t).into_affine();

    let scr = script!(
        // [t]
        { sai_t_scr }
        // [sai_t]
        {Fq2::copy(2)} {Fq2::copy(2)}
        // [sai_t, sai_t]
        { sai_2_t_scr }
        // [sai_t, sai_2_t]
        {Fq2::copy(2)} {Fq2::copy(2)}
        // [sai_t, sai_2_t, sai_2_t]
        { sai_3_t_scr }
        // [sai_t, sai_2_t, sai_3_t]
        { double_sai_3_t_scr }
        // [sai_t, sai_2_t, 2 * sai_3_t]
        { Fq2::neg(0) }
        // [sai_t, sai_2_t, -2 * sai_3_t]
        {sai_add_0_scr}
        // [sai_t, sai_add_0]
        {sai_add_1_scr}
        // [sai_add_1]
    );

    let mut hints = vec![];
    hints.extend_from_slice(&sai_t_hints);
    hints.extend_from_slice(&sai_2_t_hints);
    hints.extend_from_slice(&sai_3_t_hints);
    hints.extend_from_slice(&double_sai_3_t_hints);
    hints.extend_from_slice(&sai_add_0_hints);
    hints.extend_from_slice(&sai_add_1_hints);
    (sai_add_1, scr, hints)
}

// IsInSubGroup returns true if p is on the r-torsion, false otherwise.
// https://eprint.iacr.org/2022/348.pdf, sec. 3 and 5.1
// [r]P == 0 <==> [x₀+1]P + ψ([x₀]P) + ψ²([x₀]P) = ψ³([2x₀]P)
pub(crate) fn is_in_g2_subgroup(q: ark_bn254::G2Affine, window: usize) -> Vec<(ark_bn254::G2Affine, Script, Vec<Hint>)> {
    let scalar = 4965661367192848881;
    let mut all_chunks = vec![];
    let msm_chunks = hinted_msm(scalar, q, window);
    let msm_res = (q * ark_bn254::Fr::from(scalar)).into_affine();
    all_chunks.extend_from_slice(&msm_chunks);

    let endo_chunk = g2_chain_endomorphism(msm_res);
    let endo_res = endo_chunk.0;
    all_chunks.push(endo_chunk);

    let last_chunk = {
        let (add_0_scr, add_0_hints) = hinted_check_add(msm_res, q);
        let add_0 = (msm_res + q).into_affine();

        let (add_1_scr, add_1_hints) = hinted_check_add(endo_res, add_0);
        let mut add_1 = (endo_res + add_0).into_affine();
        if add_1.is_zero() {
            add_1 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO);
        }

        let scr = script!(
            // [endo_res, msm_res, q]
            {add_0_scr}
            // [endo_res, [x₀+1]P]
            {add_1_scr}
        );
        let mut hints = vec![];
        hints.extend_from_slice(&add_0_hints);
        hints.extend_from_slice(&add_1_hints);
        (add_1, scr, hints)
    };

    all_chunks.push(last_chunk);

    all_chunks
}



#[cfg(test)]
mod test {
    use ark_ec::CurveGroup;
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use bitcoin_script::script;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::{bn254::{fq2::Fq2, g2_sg_check::{hinted_check_add, hinted_check_double, hinted_check_double_and_add, is_in_g2_subgroup}, utils::Hint}, execute_script, execute_script_without_stack_limit, treepp};

    use super::{g2_chain_endomorphism, hinted_msm, split_scalar};

    #[test]
    fn test_g2_affine_hinted_check_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_add, hints) = hinted_check_add(t, q);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            { hinted_check_add.clone() }
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
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_add_line: {} @ {} stack",
            hinted_check_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_g2_affine_hinted_check_double() {
        //println!("G1.hinted_add: {} bytes", G1Affine::check_add().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let alpha = (t.x.square() + t.x.square() + t.x.square()) / (t.y + t.y);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - t.x;
        let y = bias_minus - alpha * x;

        let (hinted_check_double, hints) = hinted_check_double(t);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { hinted_check_double.clone() }
            { Fq2::push(y) }
            { Fq2::equalverify() }
            { Fq2::push(x) }
            { Fq2::equalverify() }
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_check_double: {} @ {} stack",
            hinted_check_double.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_g2_affine_hinted_check_double_and_add() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G2Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let bits = vec![0, 1, 0, 1];
        let mut acc = t;
        for bit in &bits {
            if *bit == 0 {
                acc = (acc + acc).into_affine();
            } else if *bit == 1 {
                acc = (acc + q).into_affine();
            }
        }

        let (hinted_check_dbl_add, hints) = hinted_check_double_and_add(t, q, bits);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            { Fq2::push(t.x) }
            { Fq2::push(t.y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            { hinted_check_dbl_add.clone() }
            // [x']
            { Fq2::push(acc.y) }
            // [x', y', y]
            { Fq2::equalverify() }
            // [x']
            { Fq2::push(acc.x) }
            // [x', x]
            { Fq2::equalverify() }
            // []
            OP_TRUE
            // [OP_TRUE]
        };
        let exec_result = execute_script_without_stack_limit(script);
        assert!(exec_result.success);
        assert!(exec_result.final_stack.len() == 1);
        println!(
            "hinted_check_dbl_add: {} @ {} stack",
            hinted_check_dbl_add.len(),
            exec_result.stats.max_nb_stack_items
        );
    }


    #[test]
    fn test_hinted_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let scalar = u64::rand(&mut prng);
        let window = 4;
        let chunks = hinted_msm(scalar, q, window);
        let chunk_hints: Vec<Vec<Hint>> = chunks.iter().map(|c| c.2.clone()).collect();
        let chunk_scripts: Vec<treepp::Script> = chunks.iter().map(|c| c.1.clone()).collect();
        let chunk_results: Vec<ark_bn254::G2Affine> = chunks.iter().map(|c| c.0).collect();
        
        let expected = (q * ark_bn254::Fr::from(scalar)).into_affine();
        assert_eq!(expected, chunk_results[chunk_results.len()-1]);

        for i in 0..chunk_scripts.len() {
            let scr = script!(
                for hint in &chunk_hints[i] {
                    {hint.push()}
                }
                // [t]
                if i == 0 {
                    { Fq2::push(ark_bn254::Fq2::ZERO) }
                    { Fq2::push(ark_bn254::Fq2::ZERO) }
                } else {
                    { Fq2::push(chunk_results[i-1].x) }
                    { Fq2::push(chunk_results[i-1].y) }
                }
                // [t, q]
                { Fq2::push(q.x) }
                { Fq2::push(q.y) }
                { chunk_scripts[i].clone() }
                // [nt]
                { Fq2::push(chunk_results[i].y) }
                { Fq2::equalverify() }
                { Fq2::push(chunk_results[i].x) }
                { Fq2::equalverify() }
                OP_TRUE
            );
            let exec_result = execute_script_without_stack_limit(scr);
            assert!(exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            println!(
                "hinted_msm {}: {} @ {} stack",
                i,
                chunk_scripts[i].len(),
                exec_result.stats.max_nb_stack_items
            );
        }

        
    }

    #[test]
    fn test_g2_chain_endomorphism() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (t, t_scr, t_hints) = g2_chain_endomorphism(q);
        
        let script_len = t_scr.len();
        let scr = script!(
            for hint in t_hints {
                {hint.push()}
            }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }
            {t_scr}
            {Fq2::push(t.y)}
            {Fq2::equalverify()}
            {Fq2::push(t.x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let exec_result = execute_script_without_stack_limit(scr);
        println!("hinted_p_power_endomorphism script {} and stack {}", script_len, exec_result.stats.max_nb_stack_items);
        assert!(exec_result.success);
        assert_eq!(exec_result.final_stack.len(), 1);
    }



    #[test]
    fn test_is_in_g2_subgroup() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let scalar = 4965661367192848881;
        let window = 4;
        let num_msm_chunks = split_scalar(window, scalar).len();

        let expected_msm = (q * ark_bn254::Fr::from(scalar)).into_affine();


        let chunks = is_in_g2_subgroup(q, window);
        let chunk_hints: Vec<Vec<Hint>> = chunks.iter().map(|c| c.2.clone()).collect();
        let chunk_scripts: Vec<treepp::Script> = chunks.iter().map(|c| c.1.clone()).collect();
        let chunk_results: Vec<ark_bn254::G2Affine> = chunks.iter().map(|c| c.0).collect();

        // MSM Chunks
        assert_eq!(num_msm_chunks+2, chunk_results.len());
        assert_eq!(chunk_results[num_msm_chunks-1], expected_msm);
        assert_eq!(chunk_results[num_msm_chunks+1], ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO));

        for i in 0..num_msm_chunks {
            let scr = script!(
                for hint in &chunk_hints[i] {
                    {hint.push()}
                }
                // [t]
                if i == 0 {
                    { Fq2::push(ark_bn254::Fq2::ZERO) }
                    { Fq2::push(ark_bn254::Fq2::ZERO) }
                } else {
                    { Fq2::push(chunk_results[i-1].x) }
                    { Fq2::push(chunk_results[i-1].y) }
                }
                // [t, q]
                { Fq2::push(q.x) }
                { Fq2::push(q.y) }
                { chunk_scripts[i].clone() }
                // [nt]
                { Fq2::push(chunk_results[i].y) }
                { Fq2::equalverify() }
                { Fq2::push(chunk_results[i].x) }
                { Fq2::equalverify() }
                OP_TRUE
            );
            let exec_result = execute_script_without_stack_limit(scr);
            assert!(exec_result.success);
            assert!(exec_result.final_stack.len() == 1);
            println!(
                "hinted_msm {}: {} @ {} stack",
                i,
                chunk_scripts[i].len(),
                exec_result.stats.max_nb_stack_items
            );
        }

        // ENDO CHUNK
        let script_len = chunk_scripts[num_msm_chunks].len();
        let scr = script!(
            for hint in &chunk_hints[num_msm_chunks] {
                {hint.push()}
            }
            { Fq2::push(chunk_results[num_msm_chunks-1].x) }
            { Fq2::push(chunk_results[num_msm_chunks-1].y) }
            { chunk_scripts[num_msm_chunks].clone() }

            {Fq2::push(chunk_results[num_msm_chunks].y)}
            {Fq2::equalverify()}
            {Fq2::push(chunk_results[num_msm_chunks].x)}
            {Fq2::equalverify()}
            OP_TRUE
        );

        let exec_result = execute_script_without_stack_limit(scr);
        println!("hinted_p_power_endomorphism {}: {} @ {} stack ",num_msm_chunks, script_len, exec_result.stats.max_nb_stack_items);
        assert!(exec_result.success);
        assert_eq!(exec_result.final_stack.len(), 1);

        // LAST_CHUNK
        let script_len = chunk_scripts[num_msm_chunks+1].len();
        let scr = script!(
            for hint in &chunk_hints[num_msm_chunks+1] {
                {hint.push()}
            }
            // aux hints
            { Fq2::push(chunk_results[num_msm_chunks].x) }
            { Fq2::push(chunk_results[num_msm_chunks].y) }
            { Fq2::push(chunk_results[num_msm_chunks-1].x) }
            { Fq2::push(chunk_results[num_msm_chunks-1].y) }
            { Fq2::push(q.x) }
            { Fq2::push(q.y) }

            { chunk_scripts[num_msm_chunks+1].clone() }
            { Fq2::push(chunk_results[num_msm_chunks+1].y) }
            { Fq2::equalverify() }
            { Fq2::push(chunk_results[num_msm_chunks+1].x) }
            { Fq2::equalverify() }
            OP_TRUE
        );

        let exec_result = execute_script(scr);
        println!("hinted verify {}: {} @ {} stack",num_msm_chunks+1, script_len, exec_result.stats.max_nb_stack_items);
        assert!(exec_result.success);
        assert_eq!(exec_result.final_stack.len(), 1);

    }
}