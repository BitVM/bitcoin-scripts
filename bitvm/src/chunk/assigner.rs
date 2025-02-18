use ark_ff::{Field, PrimeField};
use super::{api_compiletime_utils::{NUM_PUBS}};

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
