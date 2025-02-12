use crate::bigint::U254;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq6::Fq6;
use crate::bn254::{utils::*};
use crate::bn254::g1::{hinted_from_eval_points, G1Affine};
use crate::bn254::g2::G2Affine;
use crate::bn254::fq2::Fq2;
use crate::chunk::blake3compiled::hash_messages;
use crate::chunk::elements::ElementType;
use crate::chunk::primitives::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use core::ops::Neg;



// verify
pub(crate) fn chunk_verify_g1_is_on_curve(
    hint_in_py: ark_ff::BigInt<4>,
    hint_in_px: ark_ff::BigInt<4>,
) -> (bool, Script, Vec<Hint>) {
    fn tap_verify_p_is_on_curve() -> Script {
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let scr = script! {
            {Fq2::fromaltstack()}
            // [hints, px, py] []
            {Fq::is_zero_keep_element(0)}
            OP_IF 
                {G1Affine::drop()}
                for i in 0..on_curve_hint.len() {
                    {Fq::drop()}
                }
                OP_TRUE
            OP_ELSE 
                // [hints, px, py]
                {on_curve_scr}
                OP_NOT
            OP_ENDIF
        };
        scr
    }
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px.into(), hint_in_py.into());
    let (_, hints) = G1Affine::hinted_is_on_curve(p.x, p.y);

    let is_on_curve = p.is_on_curve() && p.y().is_some() && p.y != ark_bn254::Fq::ZERO;

    (is_on_curve, tap_verify_p_is_on_curve(), hints)
}

// verify
pub(crate) fn chunk_verify_g1_hash_is_on_curve(
    hint_in_p: ark_bn254::G1Affine,
) -> (bool, Script, Vec<Hint>) {
    fn tap_verify_p_is_on_curve() -> Script {
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            // [hints, px, py] [phash]
            {Fq::fromaltstack()}
            {Fq2::copy(1)} {Fq2::toaltstack()}
            // [hints, px, py, phash] [py, px]
            for _ in 0..Fq::N_LIMBS as usize * on_curve_hint.len() {
                OP_DEPTH OP_1SUB OP_ROLL 
            }  
            // [px, py, phash, hints]
            for _ in 0..on_curve_hint.len() {
                {Fq::toaltstack()}
            }
            {Fq::toaltstack()}
            // [px, py] [py, px, hints, phash]
            {hash_fp2()} 
            {Fq::fromaltstack()}
            {Fq::equalverify(1, 0)}

            for _ in 0..on_curve_hint.len() {
                {Fq::fromaltstack()}
            }
            {Fq2::fromaltstack()}
            // [hints, px, py]

            // actual curve validation begins
            {Fq::is_zero_keep_element(0)}
            OP_IF 
                {G1Affine::drop()}
                for i in 0..on_curve_hint.len() {
                    {Fq::drop()}
                }
                OP_TRUE
            OP_ELSE 
                // [hints, px, py]
                {on_curve_scr}
                OP_NOT
            OP_ENDIF
        };
    
        script! {
            {ops_scr}
        }
    }


    // assert_eq!(sec_in.len(), 3);
    let p =  hint_in_p;
    let (_, hints) = G1Affine::hinted_is_on_curve(p.x, p.y);

    let is_on_curve = p.is_on_curve() && p.y().is_some() && p.y != ark_bn254::Fq::ZERO;

    (is_on_curve, tap_verify_p_is_on_curve(), hints)
}

// precompute P
pub(crate) fn chunk_precompute_p(
    hint_in_py: ark_ff::BigInt<4>,
    hint_in_px: ark_ff::BigInt<4>,
) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
    fn tap_precompute_p() -> Script {
        let (eval_xy, hints) = hinted_from_eval_points(
            ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        );
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            {Fq2::fromaltstack()}
            // [hints, px, py] [pdash_hash]
            {eval_xy} 
        };
    
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1])}
            OP_TRUE     
        );
        script! {
            {ops_scr}
            // [pdx, pdy]    
            // {hash_scr}
        }
    }
    let p =  ark_bn254::G1Affine::new_unchecked(hint_in_px.into(), hint_in_py.into());
    let pdy = p.y.inverse().unwrap();
    let pdx = -p.x * pdy;
    let pd = ark_bn254::G1Affine::new_unchecked(pdx, pdy);
    let (_, hints) =  hinted_from_eval_points(p);

    (pd, tap_precompute_p(), hints)
}

pub(crate) fn chunk_precompute_p_from_hash(
    hint_in_p: ark_bn254::G1Affine,
) -> (ark_bn254::G1Affine, Script, Vec<Hint>) {
    fn tap_precompute_p_from_hash() -> Script {
        let (eval_xy, hints) = hinted_from_eval_points(
            ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE),
        );
        let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
        let ops_scr = script! {
            // [hints, px, py] [pdash_hash, phash]
            {Fq2::copy(0)}
            // [hints, p, p]
            {eval_xy} 
            // [hints, p, pdash]
        };
    
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE     
        );
        script! {
            {ops_scr}
            // [pdx, pdy]    
            // {hash_scr}
        }
    }
    let p =  hint_in_p;
    let pdy = p.y.inverse().unwrap();
    let pdx = -p.x * pdy;
    let pd = ark_bn254::G1Affine::new_unchecked(pdx, pdy);
    let (_, hints) =  hinted_from_eval_points(p);

    (pd, tap_precompute_p_from_hash(), hints)
}

// hash T4
pub(crate) fn chunk_verify_g2_on_curve(
    hint_q4y1: ark_ff::BigInt<4>,
    hint_q4y0: ark_ff::BigInt<4>,
    hint_q4x1: ark_ff::BigInt<4>,
    hint_q4x0: ark_ff::BigInt<4>,
) -> (bool, Script, Vec<Hint>) {

    fn tap_verify_g2_on_curve(on_curve_scr: Script) -> Script {
        let scr = script! {
            for _ in 0..4 {
                {Fq::fromaltstack()}
            }
            // [hints, x0,x1,y0,y1] []
            {on_curve_scr}
            OP_NOT            
        };
        scr
    }

    let t4 = ark_bn254::G2Affine::new_unchecked(ark_bn254::Fq2::new(hint_q4x0.into(), hint_q4x1.into()), ark_bn254::Fq2::new(hint_q4y0.into(), hint_q4y1.into()));
    let (on_curve_scr, hints) = G2Affine::hinted_is_on_curve(t4.x, t4.y);
    let is_valid = t4.is_on_curve();

    (is_valid, tap_verify_g2_on_curve(on_curve_scr), hints)
}


pub(crate) fn chunk_frob_fp12(f: ark_bn254::Fq6, power: usize) -> (ark_bn254::Fq6, Script, Vec<Hint>) {

    let fp12 = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f);
    let (hinted_frob_scr, hints_frobenius_map) = Fq12::hinted_frobenius_map(power, fp12);
    let g = fp12.frobenius_map(power);

    let ops_scr = script! {
        // [f]
        {Fq6::push(ark_bn254::Fq6::ONE)}
        {Fq6::copy(6)}
        // [f, (1, f)]
        {hinted_frob_scr}
        // [f, (1, g)]
        {Fq6::roll(6)} 
        {Fq6::push(ark_bn254::Fq6::ONE)}
        {Fq6::equalverify()}
        // [f, g]
    };

    (g.c1, ops_scr, hints_frobenius_map)
}
 

pub(crate) fn chunk_hash_c(
    hint_in_c: Vec<ark_ff::BigInt<4>>,
) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let fvec: Vec<ark_bn254::Fq> = hint_in_c.iter().map(|f| ark_bn254::Fq::from(*f)).collect();

    let f = ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(fvec[0], fvec[1]),
        ark_bn254::Fq2::new(fvec[2], fvec[3]),
        ark_bn254::Fq2::new(fvec[4], fvec[5]),
    );
    let ops_scr = script! {
        for _ in 0..6 {
            {Fq::fromaltstack()}
        }
        // Stack:[fs]
        // Altstack: [f_hash_claim]
    };
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6])}
        OP_TRUE
    );

    (
        f,
        ops_scr,
        vec![],
    )
}

pub(crate) fn chunk_hash_c_inv(
    hint_in_c: Vec<ark_ff::BigInt<4>>,
) -> (ark_bn254::Fq6, Script, Vec<Hint>) {
    let fvec: Vec<ark_bn254::Fq> = hint_in_c.iter().map(|f| ark_bn254::Fq::from(*f)).collect();

    let f = ark_bn254::Fq6::new(
        ark_bn254::Fq2::new(fvec[0], fvec[1]),
        ark_bn254::Fq2::new(fvec[2], fvec[3]),
        ark_bn254::Fq2::new(fvec[4], fvec[5]),
    );
    let ops_scr = script! {
        for _ in 0..6 {
            {Fq::fromaltstack()}
            {Fq::neg(0)}
        }
        // Stack:[fs]
        // Altstack: [f_hash_claim]
    };
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6])}
        OP_TRUE
    );
    let fneg = f.neg();
    (
        fneg,
        ops_scr,
        vec![],
    )
}

pub(crate) fn chunk_final_verify(
    hint_in_a: ark_bn254::Fq6, // 
    hint_in_b: ark_bn254::Fq6,
) -> (bool, Script, Vec<Hint>) {

    let (f, g) = (hint_in_a, hint_in_b);
    let is_valid = f + g == ark_bn254::Fq6::ZERO;

    let scr = script!(
        // [f] [fhash]
        {Fq6::copy(0)}
        {Fq6::toaltstack()}
        {hash_fp6()}
        {Fq6::fromaltstack()}
        {Fq::fromaltstack()}
        // [fh, f, fhash]
        {Fq::equalverify(7, 0)}
        // [f]
        {Fq6::push(hint_in_b)}
        {Fq6::add(6, 0)}
        for _ in 0..6 {
            {Fq::push(ark_bn254::Fq::ZERO)}
            {Fq::equal(1, 0)}
            OP_TOALTSTACK
        }
        {1}
        for _ in 0..6 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }
        OP_NOT
    );

    (
        is_valid,
        scr,
        vec![],
    )
}

pub(crate) fn chunk_verify_fq6_is_on_field(
    hint_in_c: Vec<ark_ff::BigInt<4>>,
) -> (bool, Script, Vec<Hint>) {
    fn tap_verify_fq6_is_on_field() -> Script {
        let ops_scr = script! {
            for _ in 0..6 {
                {Fq::fromaltstack()}
            }
            // Stack:[f11 ..,f0], []
            for _ in 0..6 {
                { Fq::push_hex(Fq::MODULUS) }
                { U254::lessthan(1, 0) } // a < p
                OP_TOALTSTACK
            }
            for _ in 0..6 {
                OP_FROMALTSTACK
            }
            for _ in 0..5 {
                OP_BOOLAND
            }
            // <p => 1 -> good
            // >p => 0 -> faulty
            OP_NOT
        };
        let sc = script! {
            {ops_scr}
        };
        sc
    }

    let is_valid = hint_in_c.iter().filter(|f| **f >= ark_bn254::Fq::MODULUS).count() == 0; 
    (
        is_valid,
        tap_verify_fq6_is_on_field(),
        vec![],
    )
}


#[cfg(test)]
mod test {

    use crate::bn254::g1::G1Affine;
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    
    use crate::chunk::blake3compiled::hash_messages;
    use crate::chunk::elements::{DataType, ElementType};
    use crate::chunk::taps_ext_miller::{chunk_final_verify, chunk_hash_c, chunk_verify_fq6_is_on_field};
    
    use crate::chunk::taps_ext_miller::*;
    use ark_ff::{Field, PrimeField};
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use crate::treepp::*;



    #[test]
    fn test_chunk_frob_fp12() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        let power = 2;
        let (hout, hout_scr, hout_hints) = chunk_frob_fp12(f_n.c1, power);
        let hout = DataType::Fp6Data(hout);
        let f_n_c1_elem = DataType::Fp6Data(f_n.c1);

        let bitcom_scr = script!{
            {hout.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {f_n_c1_elem.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        };

        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6, ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = hash_scr.len() + hout_scr.len();

        let scr = script!(
            for h in hout_hints {
                {h.push()}
            }
            for h in f_n_c1_elem.to_witness(ElementType::Fp6) {
                {h.push()}
            }
            {bitcom_scr}
            {hout_scr}
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
    fn test_tap_hash_c() {

        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq6::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (hint_out, tap_hash_c, hint_script) = chunk_hash_c(fqvec.clone().into_iter().map(|f| f.into()).collect::<Vec<ark_ff::BigInt<4>>>());
        let fqvec: Vec<DataType> = fqvec.iter().map(|f| DataType::U256Data(f.into_bigint())).collect();
        let hint_out = DataType::Fp6Data(hint_out);

        let bitcom_scr = script!{
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            for f in fqvec.iter().rev() {
                {f.to_hash().as_hint_type().push()}
                {Fq::toaltstack()}                
            }
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::Fp6])}
            OP_TRUE
        );

        let tap_len = tap_hash_c.len() + hash_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
            {hash_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_verify_fq6() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq6::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();

        let (is_valid, tap_hash_c, hint_script) = chunk_verify_fq6_is_on_field(fqvec.clone().into_iter().map(|f| f.into()).collect::<Vec<ark_ff::BigInt<4>>>());
        assert!(is_valid);
        let bitcom_scr = script!{
            for f in fqvec.iter().rev() {
                {Fq::push(*f)}
                {Fq::toaltstack()}                
            }
        };

        let tap_len = tap_hash_c.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_hash_c}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_chunk_verify_g2_on_curve() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let q = ark_bn254::G2Affine::rand(&mut prng);
        let (hint_out, init_t4_tap, hint_script) = chunk_verify_g2_on_curve(q.y.c1.into(), q.y.c0.into(), q.x.c1.into(), q.x.c0.into());
        assert_eq!(hint_out, q.is_on_curve());
        let bitcom_script = script!{
            {Fq::push(q.y.c1)}
            {Fq::toaltstack()}
            {Fq::push(q.y.c0)}
            {Fq::toaltstack()}
            {Fq::push(q.x.c1)}
            {Fq::toaltstack()}
            {Fq::push(q.x.c0)}
            {Fq::toaltstack()}
        };
        let tap_len = init_t4_tap.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_script}
            {init_t4_tap}
        };

        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

    #[test]
    fn test_tap_precompute_p() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p(p.y.into(), p.x.into());

        let hint_out = DataType::G1Data(hint_out);
        let bitcom_scr = script!{
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}    
            {G1Affine::push(p)}
            {Fq2::toaltstack()}     
        };
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
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
    fn test_tap_precompute_p_from_hash() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let (hint_out, tap_prex, hint_script) = chunk_precompute_p_from_hash(p);

        let hint_out = DataType::G1Data(hint_out);
        let p = DataType::G1Data(p);

        let bitcom_scr = script!{
            {hint_out.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}    
            {p.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        };
        let preim_hints = p.to_witness(ElementType::G1);
        let hash_scr = script!(
            {hash_messages(vec![ElementType::G1, ElementType::G1])}
            OP_TRUE     
        );

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
            {hash_scr}
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
    fn test_tap_verify_p_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_is_on_curve(p.y.into(), p.x.into());
        assert_eq!(p.is_on_curve(), is_valid_point);
        let bitcom_scr = script!{
            {G1Affine::push(p)}
            {Fq2::toaltstack()}     
        };

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_prex}
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
    fn test_tap_verify_phash_is_on_curve() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let (is_valid_point, tap_prex, hint_script) = chunk_verify_g1_hash_is_on_curve(p);
        assert_eq!(p.is_on_curve(), is_valid_point);

        let p = DataType::G1Data(p);

        let bitcom_scr = script!{
            {p.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}     
        };
        let preim_hints = p.to_witness(ElementType::G1);

        let tap_len = tap_prex.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            for h in preim_hints {
                {h.push()}
            }
            {bitcom_scr}
            {tap_prex}
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
    fn test_tap_verify_fp12_is_unity() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap();
        let f =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        let g =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);

        let (_, tap_scr, mut hint_script) = chunk_final_verify(f.c1, g.c1);

        let f_c1 = DataType::Fp6Data(f.c1);
        
        hint_script.extend_from_slice(&f_c1.to_witness(ElementType::Fp6));

        let bitcom_scr = script!{
            {f_c1.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
        };

        let tap_len = tap_scr.len();
        let script = script! {
            for h in hint_script {
                { h.push() }
            }
            {bitcom_scr}
            {tap_scr}
        };
        let res = execute_script(script);
        for i in 0..res.final_stack.len() {
            println!("{i:} {:?}", res.final_stack.get(i));
        }
        assert!(!res.success && res.final_stack.len() == 1);
        println!("script {} stack {}", tap_len, res.stats.max_nb_stack_items);
    }

}
