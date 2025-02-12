
use crate::bn254::g1::G1Affine;
use crate::bn254::fr::Fr;
use crate::bn254::utils::Hint;
use crate::{
    bn254::fp254impl::Fp254Impl,
    treepp::*,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::AdditiveGroup;

use super::blake3compiled::hash_messages;
use super::elements::{ ElementType};
use crate::bn254::fq2::Fq2;

pub(crate) fn chunk_msm(window: usize, ks: Vec<ark_ff::BigInt<4>>, qs: Vec<ark_bn254::G1Affine>) -> Vec<(ark_bn254::G1Affine, Script, Vec<Hint>)> {
    let num_pubs = qs.len();
    let chunks = G1Affine::hinted_scalar_mul_by_constant_g1(ks.into_iter().map(|f| f.into()).collect(), qs.clone(), window as u32);

    // [G1AccDashHash, G1AccHash, k0, k1, k2]
    // [Dec, G1Acc]

    let mut chunk_scripts = vec![];
    for (msm_tap_index, chunk) in chunks.iter().enumerate() {
        let ops_script = 
        if msm_tap_index == 0 {
            script!(
                {G1Affine::push( ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO))}
                for _ in 0..num_pubs {
                    {Fr::fromaltstack()}
                }
                // [Dec, k2, k1, k0]
                for i in 0..num_pubs {
                    {Fr::roll(i as u32)}
                }
                // [Dec, k0, k1, k2]
                {chunk.1.clone()}
                //M: [G1AccDash]
                //A: [G1AccDashHash]
            )
        } else {
            script!(
                // [Dec, G1Acc]
                for _ in 0..num_pubs {
                    {Fr::fromaltstack()}
                }
                for i in 0..num_pubs {
                    {Fr::roll(i as u32)}
                }
                // [Dec, G1Acc, k0, k1, k2]      
                {Fq2::copy(num_pubs as u32)}          
                {Fq2::toaltstack()}
                // [Dec, G1Acc, k0, k1, k2]
                {chunk.1.clone()}
                //M: [G1AccDash]
                //A: [G1AccDashHash, G1AccHash, G1Acc]
                {Fq2::fromaltstack()}
                // [G1AccDash, G1Acc] [G1AccDashHash, G1AccHash]
                {Fq2::roll(2)}
                // [G1Acc, G1AccDash] [G1AccDashHash, G1AccHash]
            )
        };

        let hash_script = script!(
            if msm_tap_index == 0 {
                //M: [G1AccDash]
                //A: [G1AccDashHash]
                {hash_messages(vec![ElementType::G1])}
            } else {
                // [G1Acc, G1AccDash] [G1AccDashHash, G1AccHash]
                {hash_messages(vec![ElementType::G1, ElementType::G1])}
            }
            OP_TRUE
        );

        let sc = script! {
            {ops_script}
            // {hash_script}
        };


        chunk_scripts.push((chunk.0, sc, chunk.2.clone()));
    }
    chunk_scripts
}

// Hash P
//vk0: G1Affine

pub(crate) fn chunk_hash_p(
    hint_in_t: ark_bn254::G1Affine,
    hint_in_q: ark_bn254::G1Affine,
) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
    // r (gp3) = t(msm) + q(vk0)
    let (tx, qx, ty, qy) = (hint_in_t.x, hint_in_q.x, hint_in_t.y, hint_in_q.y);
    let t = ark_bn254::G1Affine::new_unchecked(tx, ty);
    let q = ark_bn254::G1Affine::new_unchecked(qx, qy);
    let (add_scr, add_hints) = G1Affine::hinted_check_add(t, q);
    let r = (t + q).into_affine();
    
    let ops_script = script!{
        // [t] [hash_r, hash_t]
        { Fq2::copy(0)} 
        // [t, t]
        {G1Affine::push(q)}
        // [t, t, q]
        {add_scr}
        // [t, r]
    };

    let hash_script = script!(
        {hash_messages(vec![ElementType::G1, ElementType::G1])}
        OP_TRUE
    );

    let sc = script! {
        {ops_script}
        // {hash_script}
    };

    let mut all_hints = vec![];
    all_hints.extend_from_slice(&add_hints);

    (r, sc, all_hints)
}


#[cfg(test)]
mod test {

    use crate::{
        bn254::{fq::Fq, fq2::Fq2}, chunk::elements::{DataType}, execute_script_without_stack_limit
    };
    use super::*;
    use ark_ff::{Field, UniformRand};
    
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn u32_to_bits_vec(value: u32, window: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity(window);
        for i in (0..window).rev() {
            bits.push(((value >> i) & 1) as u8);
        }
        bits
    }

    #[test]
    fn test_precompute_table() {
        let window = 8;
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let mut p_mul: Vec<ark_bn254::G1Affine> = Vec::new();
        p_mul.push(ark_bn254::G1Affine::zero());
        for _ in 1..(1 << window) {
            p_mul.push((*p_mul.last().unwrap() + q).into_affine());
        }

        let scr = script!{ 
            
            {G1Affine::dfs_with_constant_mul(0, window as u32 - 1, 0, &p_mul) }
        };
        let index = 1; //u32::rand(&mut prng) % (1 << window);
        let index_bits = u32_to_bits_vec(index, window);

        println!("index_bits {:?}", index_bits);
        println!("script len {:?}", scr.len());
        let script = script! {
            for i in index_bits {
                {i}
            }
            {scr}
            {Fq::push(p_mul[index as usize].y)}
            {Fq::equalverify(1, 0)}
            {Fq::push(p_mul[index as usize].x)}
            {Fq::equalverify(1, 0)}
            OP_TRUE
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(res.success);
    }


    #[test]
    fn test_hinted_check_tangent_line() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let two_inv = ark_bn254::Fq::ONE.double().inverse().unwrap();
        let three_div_two = (ark_bn254::Fq::ONE.double() + ark_bn254::Fq::ONE) * two_inv;
        let mut alpha = t.x.square();
        alpha /= t.y;
        alpha *= three_div_two;
        // -bias
        let bias_minus = alpha * t.x - t.y;
        assert_eq!(alpha * t.x - t.y, bias_minus);

        let nx = alpha.square() - t.x.double();
        let ny = bias_minus - alpha * nx;

        let (hinted_check_line, hints) = G1Affine::hinted_check_tangent_line(t, alpha);
        let (hinted_double_line, hintsd) = G1Affine::hinted_double(t, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {Fq::push(alpha)}
            {Fq::push(bias_minus)}
            { Fq::push(t.x) }
            { Fq::push(t.y) }
            { hinted_check_line.clone() }
            OP_VERIFY
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_check_line: {} @ {} stack",
            hinted_check_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        let script = script! {
            for hint in hintsd {
                { hint.push() }
            }
            {Fq::push(alpha)}
            {Fq::push(bias_minus)}
            { Fq::push(t.x) }
            { hinted_double_line.clone() }
            {Fq::push(nx)}
            {Fq::push(ny)}
            {Fq2::equalverify()}
            OP_TRUE
        };
        let exec_result = execute_script(script);
        assert!(exec_result.success);
        println!(
            "hinted_double_line: {} @ {} stack",
            hinted_double_line.len(),
            exec_result.stats.max_nb_stack_items
        );

        // doubling check
    }

    #[test]
    fn test_hinted_affine_add_line() {
        // alpha = (t.y - q.y) / (t.x - q.x)
        // bias = t.y - alpha * t.x
        // x' = alpha^2 - T.x - Q.x
        // y' = -bias - alpha * x'
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let alpha = (t.y - q.y) / (t.x - q.x);
        // -bias
        let bias_minus = alpha * t.x - t.y;

        let x = alpha.square() - t.x - q.x;
        let y = bias_minus - alpha * x;
        let (hinted_add_line, hints) = G1Affine::hinted_add(t.x, q.x, alpha);

        let script = script! {
            for hint in hints {
                { hint.push() }
            }
            {Fq::push(alpha)}
            {Fq::push(bias_minus)}
            { Fq::push(t.x) }
            { Fq::push(q.x) }
            { hinted_add_line.clone() }
            { Fq::push(x) }
            { Fq::push(y) }
            { Fq2::equalverify() }
            OP_TRUE
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
    fn test_tap_hash_var_p() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let t = ark_bn254::G1Affine::rand(&mut prng);
        let r = (t + q).into_affine();

        let (hint_out,  op_scr, mut hint_script) = chunk_hash_p( t, q);
        let t = DataType::G1Data(t);
        let hint_out = DataType::G1Data(hint_out);
        hint_script.extend_from_slice(&t.to_witness(ElementType::G1));
        
        let bitcom_scr = script!{
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {t.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        };
        let hash_script = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE
        );

        let tap_len = op_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {op_scr}
            {hash_script}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success);
        assert!(res.final_stack.len() == 1);

        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }


    #[test]
    fn test_tap_msm() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G1Affine::rand(&mut prng);
        let scalar = ark_bn254::Fr::rand(&mut prng);
        let scalars = vec![scalar.into()];
        let qs = vec![q];

        let window = 7;
        let hints_msm = chunk_msm(window, scalars.clone(), qs.clone());

        for msm_chunk_index in 0..hints_msm.len() {
            let hint_in = if msm_chunk_index > 0 {
                DataType::G1Data(hints_msm[msm_chunk_index-1].0)
            } else {
                DataType::G1Data(ark_bn254::G1Affine::identity())
            };
            let hint_out = DataType::G1Data(hints_msm[msm_chunk_index].0);
            
            let bitcom_scr = script!{
                {hint_out.to_hash().as_hint_type().push()}
                {Fq::toaltstack()}
                if msm_chunk_index > 0 {
                    {hint_in.to_hash().as_hint_type().push()}
                    {Fq::toaltstack()}
                }

                for scalar in &scalars {
                    {Fr::push(ark_bn254::Fr::from(*scalar))}
                    {Fr::toaltstack()}  
                }
            };
    
            let mut op_hints = vec![];
            if msm_chunk_index > 0 {
                op_hints.extend_from_slice(&hint_in.to_witness(ElementType::G1));
            }
            let tap_len = hints_msm[msm_chunk_index].1.len();
            let hash_script = script!(
                if msm_chunk_index == 0 {
                    //M: [G1AccDash]
                    //A: [G1AccDashHash]
                    {hash_messages(vec![ElementType::G1])}
                } else {
                    // [G1Acc, G1AccDash] [G1AccDashHash, G1AccHash]
                    {hash_messages(vec![ElementType::G1, ElementType::G1])}
                }
                OP_TRUE
            );
            let script = script! {
                for h in &hints_msm[msm_chunk_index].2 {
                    {h.push()}
                }
                for i in op_hints {
                    {i.push()}
                }
                {bitcom_scr}
                {hints_msm[msm_chunk_index].1.clone()}
                {hash_script}
            };
    
            let res = execute_script_without_stack_limit(script);
            println!("{} script {} stack {}", msm_chunk_index, tap_len, res.stats.max_nb_stack_items);
    
            assert!(!res.success);
            assert!(res.final_stack.len() == 1);
        }


    }


}