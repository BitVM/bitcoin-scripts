use crate::bigint::U254;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq6::Fq6;
use crate::bn254::utils::*;
use crate::bn254::g1::{hinted_from_eval_points, G1Affine};
use crate::bn254::fq2::Fq2;
use crate::chunk::wrap_hasher::hash_messages;
use crate::chunk::elements::ElementType;
use crate::chunk::primitives::*;
use crate::{
    bn254::{fp254impl::Fp254Impl, fq::Fq},
    treepp::*,
};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use core::ops::Neg;



pub(crate) fn chunk_precompute_p(
    hint_in_py: ark_ff::BigInt<4>,
    hint_in_px: ark_ff::BigInt<4>,
) -> (ark_bn254::G1Affine, bool, Script, Vec<Hint>) {
    let mut hints = vec![];

    // is py and px less than f_p i.e. are they field elements
    let mut px: ark_bn254::Fq = ark_bn254::Fq::ONE;
    let mut py: ark_bn254::Fq = ark_bn254::Fq::ONE;

    let are_valid_field_elems = hint_in_py < ark_bn254::Fq::MODULUS && hint_in_px < ark_bn254::Fq::MODULUS && hint_in_py != ark_ff::BigInt::<4>::zero();
    if are_valid_field_elems {
        px = hint_in_px.into();
        py = hint_in_py.into();
    }

    let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(px, py);
    if are_valid_field_elems {
        hints.extend_from_slice(&on_curve_hint);
    }

    let p = ark_bn254::G1Affine::new_unchecked(px, py);
    let (eval_xy, eval_hints) =  hinted_from_eval_points(p);

    let valid_point = are_valid_field_elems && py != ark_bn254::Fq::ZERO && p.is_on_curve();
    let mock_pd = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
    let pd = if valid_point {
        hints.extend_from_slice(&eval_hints);

        let pdy = py.inverse().unwrap();
        let pdx = -px * pdy;
        
        ark_bn254::G1Affine::new_unchecked(pdx, pdy)
    } else {
        mock_pd
    };

    let drop_and_return_scr = script!(
        // [px, py] [pdhash]
        {G1Affine::drop()}
        // [] [pdhash]
        {G1Affine::push(mock_pd)} // mock values for pd,these values won't be useful as we add {0} <- skip output hash check for invalid input
        // [pd] [pdhash]
        {0} // skip output hash check because input was invalid
    );
    let scr = script! {
        // [hints] [pdhash, py, px]
        {Fq2::fromaltstack()}
        // [hints, px, py] [pdhash]
        // {is_field_element}
        // [hints, px, py, px, py]
        {Fq2::copy(0)}

        { Fq::push_hex(Fq::MODULUS) }
        { U254::lessthan(1, 0) } // py < p
        OP_TOALTSTACK
        { Fq::push_hex(Fq::MODULUS) }
        { U254::lessthan(1, 0) } // px < p
        OP_FROMALTSTACK 
        OP_BOOLAND
        OP_IF // IS_VALID_FIELD_ELEM
            // px, py <p : valid field elems
            // [hints, px, py] [pdhash]
            {Fq::is_zero_keep_element(0)}
            OP_IF // PY = 0
                {drop_and_return_scr.clone()}
            OP_ELSE // PY != 0
                // [hints, px, py]
                {Fq2::copy(0)}
                // [hints, px, py, px, py]
                {on_curve_scr}
                OP_IF // IS_ON_CURVE
                    // [hints, px, py]
                    {eval_xy}
                    // [pdx, pdy] [pdhash]
                    {1}
                    // [pdx, pdy, 1] [pdhash]
                OP_ELSE  // IS_NOT_ON_CURVE
                    {drop_and_return_scr.clone()}
                OP_ENDIF
            OP_ENDIF
        OP_ELSE // IS_NOT_VALID_FIELD_ELEM
            // px | py > p : at least one invalid field elem
            {drop_and_return_scr}
        OP_ENDIF
        // [pd, 0/1] [pdhash]
    };

    let _hash_scr = script!(
        {hash_messages(vec![ElementType::G1])}
        OP_TRUE     
    );

    (pd, valid_point, scr, hints)
}

// precompute P
pub(crate) fn chunk_precompute_p_from_hash(
    hint_in_p: ark_bn254::G1Affine,
) -> (ark_bn254::G1Affine, bool, Script, Vec<Hint>) {
    let mut hints = vec![];

    let mut px: ark_bn254::Fq = ark_bn254::Fq::ONE;
    let mut py: ark_bn254::Fq = ark_bn254::Fq::ONE;

    let py_is_not_zero =  hint_in_p.y != ark_bn254::Fq::ZERO;
    if py_is_not_zero {
        px = hint_in_p.x;
        py = hint_in_p.y;
    }

    let (on_curve_scr, on_curve_hint) = G1Affine::hinted_is_on_curve(px, py);
    if py_is_not_zero {
        hints.extend_from_slice(&on_curve_hint);
    }

    let p = ark_bn254::G1Affine::new_unchecked(px, py);
    let (eval_xy, eval_hints) =  hinted_from_eval_points(p);

    let valid_point = py_is_not_zero && p.is_on_curve();
    let mock_pd = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ONE);
    
    let pd = if valid_point {
        hints.extend_from_slice(&eval_hints);

        let pdy = p.y.inverse().unwrap();
        let pdx = -p.x * pdy;
        
        ark_bn254::G1Affine::new_unchecked(pdx, pdy)
    } else {
        mock_pd
    };

    let drop_and_return_scr = script!(
        // [px, py] [pdhash, phash]
        {G1Affine::push(mock_pd)} // mock values for pd,these values won't be useful as we add {0} <- skip output hash check for invalid input
        // [p, pd] [pdhash, phash]
        {0} // skip output hash check because input was invalid
    );
    let scr = script! {
        // [hints, px, py] [pdhash, phash]
        {Fq::is_zero_keep_element(0)}
        OP_IF // PY = 0
            {drop_and_return_scr.clone()}
        OP_ELSE // PY != 0
            // [hints, px, py]
            {Fq2::copy(0)}
            // [hints, px, py, px, py]
            {on_curve_scr}
            OP_IF // IS_ON_CURVE
                // [hints, px, py]
                {Fq2::copy(0)}
                // [hints, px, py, px, py]
                {eval_xy}
                // [px, py, pdx, pdy] [pdhash, phash]
                {1}
                // [p, pd, 1] [pdhash, phash]
            OP_ELSE  // IS_NOT_ON_CURVE
                {drop_and_return_scr.clone()}
            OP_ENDIF
        OP_ENDIF

    // [pd, 0/1] [pdhash]
    };

    let _hash_scr = script!(
        {hash_messages(vec![ElementType::G1, ElementType::G1])}
        OP_TRUE     
    );

    (pd, valid_point, scr, hints)
}

// Assumes (1 + f) is valid Fp12 i.e. f != Fq6::ZERO
// power is in the range (0, 1, 2)
pub(crate) fn chunk_frob_fp12(f: ark_bn254::Fq6, power: usize) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
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
        {1} // input was valid
    };

    let valid_input = true;
    (g.c1, valid_input, ops_scr, hints_frobenius_map)
}
 
pub(crate) fn chunk_hash_c(
    hint_in_c: Vec<ark_ff::BigInt<4>>,
) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    assert_eq!(hint_in_c.len(), 6);

    let mock_f = ark_bn254::Fq6::ONE;
    let are_valid_fps = hint_in_c.iter().filter(|f| **f < ark_bn254::Fq::MODULUS).count() == hint_in_c.len();

    let f = if are_valid_fps {
        let fvec = hint_in_c.iter().map(|f| ark_bn254::Fq::from(*f)).collect::<Vec<ark_bn254::Fq>>();
        ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(fvec[0], fvec[1]),
            ark_bn254::Fq2::new(fvec[2], fvec[3]),
            ark_bn254::Fq2::new(fvec[4], fvec[5]),
        )
    } else {
        mock_f
    };

    let ops_scr = script! {
        // [] [fhash, fqs]
        for _ in 0..6 {
            {Fq::fromaltstack()}
        }
        // [fqs, fqs] [fhash]
        {Fq6::copy(0)}
        for _ in 0..6 {
            { Fq::push_hex(Fq::MODULUS) }
            { U254::lessthan(1, 0) } // a < p
            OP_TOALTSTACK
        }
        {1}
        for _ in 0..6 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }
        // are_valid_fps -> 1 -> verify_final_hash
        // not_valid_fps -> 0 -> skip verify_final_hash 
        // [fqs, 0/1] [fhash]
        OP_IF 
            // [fs] [fhash]
            {1} // verify_final_hash
            // [fs, 1] [fhash]
        OP_ELSE
            // [fs] [fhash]
            {Fq6::drop()}
            {Fq6::push(mock_f)}
            {0} // skip verify_final hash
            // [mock_fs, 0] [fhash]
        OP_ENDIF
        // [fs, 0/1] [fhash]
    };
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6])}
        OP_TRUE
    );

    (
        f,
        are_valid_fps,
        ops_scr,
        vec![],
    )
}

pub(crate) fn chunk_hash_c_inv(
    hint_in_c: Vec<ark_ff::BigInt<4>>,
) -> (ark_bn254::Fq6, bool, Script, Vec<Hint>) {
    assert_eq!(hint_in_c.len(), 6);

    let mock_f = ark_bn254::Fq6::ONE;
    let are_valid_fps = hint_in_c.iter().filter(|f| **f < ark_bn254::Fq::MODULUS).count() == hint_in_c.len();
    
    let f = if are_valid_fps {
        let fvec = hint_in_c.iter().map(|f| ark_bn254::Fq::from(*f)).collect::<Vec<ark_bn254::Fq>>();
        let tmp = ark_bn254::Fq6::new(
            ark_bn254::Fq2::new(fvec[0], fvec[1]),
            ark_bn254::Fq2::new(fvec[2], fvec[3]),
            ark_bn254::Fq2::new(fvec[4], fvec[5]),
        );
        
        tmp.neg()
    } else {
        mock_f
    };

    let ops_scr = script! {
        // [] [fneghash, fqs]
        for _ in 0..6 {
            {Fq::fromaltstack()}
        }
        // [fqs] [fneghash]
        {Fq6::copy(0)}
        // [fqs, fqs] [fneghash]
        for _ in 0..6 {
            { Fq::push_hex(Fq::MODULUS) }
            { U254::lessthan(1, 0) } // a < p
            OP_TOALTSTACK
        }
        {1}
        for _ in 0..6 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }
        // are_valid_fps -> 1 -> verify_final_hash
        // not_valid_fps -> 0 -> skip verify_final_hash 
        // [fqs, 0/1] [fneghash]
        OP_IF 
            // [fs] [fneghash]
            for _ in 0..6 {
                {Fq::roll(5)}
                {Fq::neg(0)}
            }
            // [-fs] [fneghash]
            {1} // verify_final_hash
            // [-fs, 1] [fneghash]
        OP_ELSE
            // [fs] [fneghash]
            {Fq6::drop()}
            {Fq6::push(mock_f)}
            {0} // skip verify_final hash
            // [fs, 0] [fneghash]
        OP_ENDIF
        // [fs, 0/1] [fneghash]
    };
    let _hash_scr = script!(
        {hash_messages(vec![ElementType::Fp6])}
        OP_TRUE
    );

    (
        f,
        are_valid_fps,
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


#[cfg(test)] 
mod test {
    use crate::bn254::fp254impl::Fp254Impl;
    use crate::bn254::fq::Fq;
    use crate::bn254::fq2::Fq2;
    
    use crate::chunk::wrap_hasher::hash_messages;
    use crate::chunk::elements::{CompressedStateObject, DataType, ElementType};
    use crate::chunk::taps_ext_miller::{chunk_final_verify, chunk_hash_c};
    
    use crate::chunk::taps_ext_miller::*;
    use ark_ff::{BigInt, Field, PrimeField};
    use ark_std::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_chunk_frob_fp12() {
        let mut prng = ChaCha20Rng::seed_from_u64(1);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let f_n = ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);

        for (power, should_corrupt_output_hash) in [(1, true), (2, true), (3, true), (1, false), (2, false), (3, false)] { // data points
            let (hout, input_is_valid, hout_scr, hout_hints) = chunk_frob_fp12(f_n.c1, power);
            assert!(input_is_valid);
            let hout = DataType::Fp6Data(hout);
            let f_n_c1_elem = DataType::Fp6Data(f_n.c1);
    
            let mut output_hash = hout.to_hash();
            if should_corrupt_output_hash {
                if let CompressedStateObject::Hash(r) = output_hash {
                    let random_hash = extern_hash_nibbles(vec![r, r]);
                    output_hash = CompressedStateObject::Hash(random_hash);
                }
            }
            let bitcom_scr = script!{
                {output_hash.as_hint_type().push()}
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
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(should_corrupt_output_hash, res.success); // if output is corrupted, should have successful disprove
            assert!(res.final_stack.len() == 1);
            assert!(res.stats.max_nb_stack_items < 1000);
            println!("chunk_frob_fp12(power: {}) disprovable({}) script {} stack {:?}", power, should_corrupt_output_hash, tap_len, res.stats.max_nb_stack_items);

        }
    
    
    }

    #[test]
    fn test_tap_hash_c() {
        let mut prng = ChaCha20Rng::seed_from_u64(179);
        let f = ark_bn254::Fq6::rand(&mut prng);
        let fqvec = f.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>();
        let fqvec1 = fqvec.clone().into_iter().map(|f| f.into()).collect::<Vec<ark_ff::BigInt<4>>>(); // random
        let fqvec2 = (0..6).map(|_| ark_bn254::Fq::MODULUS).collect::<Vec<BigInt<4>>>(); // not a field elem
        let fqvec3 = (0..6).map(|_| ark_ff::BigInt::zero()).collect::<Vec<BigInt<4>>>(); // all zeros
        let fqvec4 = (0..6).map(|_| { ark_ff::BigInt::<4>::one() << 255}).collect::<Vec<BigInt<4>>>(); // > 254 bit

        for (fqvec, disprovable) in [(fqvec1, false), (fqvec2, true), (fqvec3, false), (fqvec4, true)] {
            let (hint_out, input_is_valid, tap_hash_c, hint_script) = chunk_hash_c(fqvec.clone());
            assert_eq!(input_is_valid, !disprovable);

            let fqvec: Vec<DataType> = fqvec.into_iter().map(DataType::U256Data).collect();
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
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(res.success, disprovable);
            assert!(res.final_stack.len() == 1);
            println!("chunk_hash_c disprovable({}) script {} stack {}", disprovable, tap_len, res.stats.max_nb_stack_items);
        }
    }

    #[test]
    fn test_tap_precompute_p() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let p0 = [ark_ff::BigInt::<4>::one(), ark_ff::BigInt::<4>::zero()];
        let p1 = [ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::zero()];
        let p2 = [ark_ff::BigInt::<4>::zero(), ark_ff::BigInt::<4>::one()];
        let p3 = [ark_ff::BigInt::<4>::one() << 255, ark_ff::BigInt::<4>::one() << 255]; 
        let p4: [ark_ff::BigInt::<4>; 2] = [p.x.into(), p.y.into()]; 
        let p5: [ark_ff::BigInt::<4>; 2] = [p.x.double().into(), p.y.into()]; 
        let dataset = vec![(p0, true), (p1, true), (p2, true), (p3, true), (p4, false), (p5, true)];

        for (p, disprovable) in dataset {
            let (hint_out, input_is_valid, tap_prex, hint_script) = chunk_precompute_p(p[1], p[0]);
            assert_eq!(input_is_valid, !disprovable);
            let hint_out = DataType::G1Data(hint_out);
            let bitcom_scr = script!{
                {hint_out.to_hash().as_hint_type().push()}
                {Fq::toaltstack()}    
                {Hint::U256(p[0].into()).push()}
                {Hint::U256(p[1].into()).push()}
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
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(res.success, disprovable);
            assert!(res.final_stack.len() == 1);
            println!("chunk_precompute_p disprovable({}) script {} stack {}", disprovable, tap_len, res.stats.max_nb_stack_items);
        }
    }

    #[test]
    fn test_tap_precompute_p_from_hash() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ONE, ark_bn254::Fq::ZERO);
        let p3 = ark_bn254::G1Affine::new_unchecked(ark_bn254::Fq::ZERO, ark_bn254::Fq::ZERO);
        let p4 = ark_bn254::G1Affine::new_unchecked(p1.x, p1.x);
        let dataset = vec![(p1, false), (p2, true), (p3, true), (p4, true)];

        for (p, disprovable) in dataset {
            let (hint_out, input_is_valid, tap_prex, hint_script) = chunk_precompute_p_from_hash(p);
            assert_eq!(input_is_valid, !disprovable);
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
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(res.success, disprovable);
            assert!(res.final_stack.len() == 1);
            println!("chunk_precompute_p_from_hash disprovable({}) script {} stack {}", disprovable, tap_len, res.stats.max_nb_stack_items);
        }
    }

    #[test]
    fn test_tap_verify_fp12_is_unity() {
        // runtime
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let f = ark_bn254::Fq12::rand(&mut prng);
        let g = f.inverse().unwrap();
        let f =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, f.c1/f.c0);
        let g =  ark_bn254::Fq12::new(ark_bn254::Fq6::ONE, g.c1/g.c0);
        let gdash = ark_bn254::Fq12::rand(&mut prng);

        for (f, g, disprovable) in vec![(f, g, true), (f, gdash, false)] {
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
            if res.final_stack.len() > 1 {
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
            }
            assert_eq!(res.success, !disprovable);
            assert!(res.final_stack.len() == 1);
            println!("chunk_final_verify: disprovable{} script {} stack {}", disprovable, tap_len, res.stats.max_nb_stack_items);
        }
    }

}
