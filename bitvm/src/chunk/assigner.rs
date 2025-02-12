use std::ops::Neg;

use ark_bn254::{Bn254};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};

use crate::{chunk::{primitives::HashBytes, segment::*}, groth16::g16::{Assertions, Signatures, N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS}};


use super::{compile::{NUM_PUBS, NUM_U160, NUM_U256}, elements::{CompressedStateObject, DataType, ElementType}, wots::{wots160_sig_to_byte_array, wots256_sig_to_byte_array}};

#[derive(Debug)]
pub(crate) struct InputProof {
    pub(crate) p2: ark_bn254::G1Affine,
    pub(crate) p4: ark_bn254::G1Affine,
    pub(crate) q4: ark_bn254::G2Affine,
    pub(crate) c: ark_bn254::Fq6,
    pub(crate) s: ark_bn254::Fq6,
    pub(crate) ks: Vec<ark_bn254::Fr>,
}

impl InputProof {
    pub(crate) fn to_raw(&self) -> InputProofRaw {
        let p2x = self.p2.x.into_bigint();
        let p2y = self.p2.y.into_bigint();
        let p4x = self.p4.x.into_bigint();
        let p4y = self.p4.y.into_bigint();
        let q4x0 = self.q4.x.c0.into_bigint();
        let q4x1 = self.q4.x.c1.into_bigint();
        let q4y0 = self.q4.y.c0.into_bigint();
        let q4y1 = self.q4.y.c1.into_bigint();
        let c: Vec<ark_ff::BigInt<4>> = self.c.to_base_prime_field_elements().map(|f| f.into_bigint()).collect();
        let s: Vec<ark_ff::BigInt<4>> = self.s.to_base_prime_field_elements().map(|f| f.into_bigint()).collect();
        let ks: Vec<ark_ff::BigInt<4>> = self.ks.iter().map(|f| f.into_bigint()).collect();

        InputProofRaw {
            p2: [p2x, p2y],
            p4: [p4x, p4y],
            q4: [q4x0, q4x1, q4y0, q4y1],
            c: c.try_into().unwrap(),
            s: s.try_into().unwrap(),
            ks: ks.try_into().unwrap(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct InputProofRaw {
    pub(crate) p2: [ark_ff::BigInt<4>; 2],
    pub(crate) p4: [ark_ff::BigInt<4>; 2],
    pub(crate) q4: [ark_ff::BigInt<4>; 4],
    pub(crate) c: [ark_ff::BigInt<4>; 6],
    pub(crate) s: [ark_ff::BigInt<4>; 6],
    pub(crate) ks: [ark_ff::BigInt<4>; NUM_PUBS],
}


#[derive(Debug)]
pub struct PublicParams {
    pub q2: ark_bn254::G2Affine,
    pub q3: ark_bn254::G2Affine,
    pub fixed_acc: ark_bn254::Fq6,
    pub ks_vks: Vec<ark_bn254::G1Affine>,
    pub vky0: ark_bn254::G1Affine,
}

pub(crate) fn collect_raw_assertion_data_from_segments(segments: Vec<Segment>) -> Assertions {
    let mut vs: Vec<CompressedStateObject> = vec![];
    for v in segments {
        if v.is_validation {
            continue;
        }
        let x = v.result.0.to_hash();
        vs.push(x);
    }

    let mut batch1 = vec![];
    for i in 0..NUM_PUBS {
        let val = &vs[i];
        let bal: [u8; 32] = val.serialize_to_byte_array().try_into().unwrap();
        batch1.push(bal);
    }
    let batch1: [[u8; 32]; NUM_PUBS] = batch1.try_into().unwrap();

    let len = batch1.len();
    let mut batch2 = vec![];
    for i in 0..NUM_U256 {
        let val = &vs[i + len];
        let bal: [u8; 32] = val.serialize_to_byte_array().try_into().unwrap();
        batch2.push(bal);
    }
    let batch2: [[u8; 32]; N_VERIFIER_FQS] = batch2.try_into().unwrap();

    let len = batch1.len() + batch2.len();
    let mut batch3 = vec![];
    for i in 0..NUM_U160 {
        let val = &vs[i+len];
        let bal: [u8; 20] = val.serialize_to_byte_array().try_into().unwrap();
        batch3.push(bal);
    }
    let batch3: [[u8; 20]; N_VERIFIER_HASHES] = batch3.try_into().unwrap();

    (batch1, batch2, batch3)
}

pub(crate) type TypedAssertions = (
    [ark_ff::BigInt<4>; N_VERIFIER_PUBLIC_INPUTS],
    [ark_ff::BigInt<4>; N_VERIFIER_FQS],
    [HashBytes; N_VERIFIER_HASHES],
);

pub(crate) fn get_intermediate_hashes(asserts: &TypedAssertions) -> Vec<HashBytes> { // Intermediates
    let mut hashes= asserts.2.to_vec();
    hashes.reverse();
    hashes
}

pub(crate) fn collect_assertions_from_wots_signature(signed_asserts: Signatures) -> TypedAssertions {
    let mut ks: Vec<ark_ff::BigInt<4>> = vec![];
    for i in 0..N_VERIFIER_PUBLIC_INPUTS {
        let nibs = wots256_sig_to_byte_array(signed_asserts.0[i]);
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        if let CompressedStateObject::U256(cobj) = cobj {
            ks.push(cobj);
        } else {
            panic!()
        }
    }

    let mut numfqs: Vec<ark_ff::BigInt<4>> = vec![];
    for i in 0..N_VERIFIER_FQS {
        let nibs = wots256_sig_to_byte_array(signed_asserts.1[i]);
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        if let CompressedStateObject::U256(cobj) = cobj {
            numfqs.push(cobj);
        } else {
            panic!()
        }
    }

    let mut numhashes: Vec<HashBytes> = vec![];
    for i in 0..N_VERIFIER_HASHES {
        let nibs = wots160_sig_to_byte_array(signed_asserts.2[i]);
        let cobj = CompressedStateObject::deserialize_from_byte_array(nibs);
        if let CompressedStateObject::Hash(cobj) = cobj {
            numhashes.push(cobj);
        } else {
            panic!()
        }
    }
    (ks.try_into().unwrap(), numfqs.try_into().unwrap(), numhashes.try_into().unwrap())
}

pub(crate) fn extract_public_params(vk: &ark_groth16::VerifyingKey<Bn254>) -> PublicParams {
    let mut msm_gs = vk.gamma_abc_g1.clone(); // vk.vk_pubs[0]
    msm_gs.reverse();
    let vky0 = msm_gs.pop().unwrap();

    let (q3, q2, q1) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
    );
    let fixed_acc = Bn254::multi_miller_loop_affine([vk.alpha_g1], [q1]).0;
    
    let pubs: PublicParams = PublicParams { q2, q3, fixed_acc: fixed_acc.c1/fixed_acc.c0, ks_vks: msm_gs.clone(), vky0 };
    pubs
}


pub(crate) fn extract_proof_from_assertions(asserts: &TypedAssertions) -> InputProofRaw { // EvalIns
    let numfqs = asserts.1;
    let p4 = [numfqs[1], numfqs[0]];
    let p2 = [numfqs[3], numfqs[2]];
    let step = 4;
    let c = [
            numfqs[step], numfqs[step+1],
            numfqs[step+2], numfqs[step+3],
            numfqs[step+4], numfqs[step+5],
    ];       
    let step = step + 6;
    let s = [
        numfqs[step], numfqs[step+1],
        numfqs[step+2], numfqs[step+3],
        numfqs[step+4], numfqs[step+5],
];

    let step = step + 6;
    let q4 = [
        numfqs[step], numfqs[step+1],
        numfqs[step+2], numfqs[step+3],
    ];

    let eval_ins: InputProofRaw = InputProofRaw { p2, p4, q4, c, s, ks: asserts.0 };
    eval_ins
}
