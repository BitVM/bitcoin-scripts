#![allow(non_snake_case)]
use crate::groth16::constants::{COFACTOR_CUBIC, H, K, LAMBDA, MM, R, S, T, W};
use ark_ff::{Field, One};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

#[macro_export]
macro_rules! log_assert_eq {
    ($left:expr, $right:expr) => {
        if $left != $right {
            // log error
            println! {"fail assert"}
        }
    };
    ($left:expr, $right:expr, $message: expr) => {
        if $left != $right {
            // log error
            println! {"fail assert: {}", $message}
        }
    };
    ($left:expr, $right:expr, $text: expr, $message: expr) => {
        if $left != $right {
            // log error
            println! {$text, $message}
        }
    };
}

#[macro_export]
macro_rules! log_assert_ne {
    ($left:expr, $right:expr) => {
        if $left == $right {
            println! {"fail assert"}
        }
    };
    ($left:expr, $right:expr, $message: expr) => {
        if $left == $right {
            // log error
            println! {"fail assert: {}", $message}
        }
    };
}

// refer table 3 of https://eprint.iacr.org/2009/457.pdf
// a: Fp12 which is cubic residue
// c: random Fp12 which is cubic non-residue
// s: satisfying p^12 - 1 = 3^s * t
// t: satisfying p^12 - 1 = 3^s * t
// k: k = (t + 1) // 3
fn tonelli_shanks_cubic(
    a: ark_bn254::Fq12,
    c: ark_bn254::Fq12,
    s: u32,
    t: BigUint,
    k: BigUint,
) -> ark_bn254::Fq12 {
    let mut r = a.pow(t.to_u64_digits());
    let e = 3_u32.pow(s - 1);
    let exp = 3_u32.pow(s) * &t;

    // compute cubic root of (a^t)^-1, say h
    let (mut h, cc, mut c) = (
        ark_bn254::Fq12::ONE,
        c.pow([e as u64]),
        c.inverse().unwrap(),
    );
    for i in 1..(s as i32) {
        let delta = (s as i32) - i - 1;
        let d = if delta < 0 {
            r.pow((&exp / 3_u32.pow((-delta) as u32)).to_u64_digits())
        } else {
            r.pow([3_u32.pow(delta as u32).to_u64().unwrap()])
        };
        if d == cc {
            (h, r) = (h * c, r * c.pow([3_u64]));
        } else if d == cc.pow([2_u64]) {
            (h, r) = (h * c.pow([2_u64]), r * c.pow([3_u64]).pow([2_u64]));
        }
        c = c.pow([3_u64])
    }

    // recover cubic root of a
    r = a.pow(k.to_u64_digits()) * h;
    if t == 3_u32 * k + 1_u32 {
        r = r.inverse().unwrap();
    }

    log_assert_eq!(r.pow([3_u64]), a);
    r
}

// Finding C
// refer from Algorithm 5 of "On Proving Pairings"(https://eprint.iacr.org/2024/640.pdf)
pub fn compute_c_wi(f: ark_bn254::Fq12) -> (ark_bn254::Fq12, ark_bn254::Fq12) {
    // make sure f is r-th residue
    log_assert_eq!(f.pow(&*H.to_u64_digits()), ark_bn254::Fq12::ONE);

    let w = *W;

    // options for wi are 1, w, w^2
    let mut wi = ark_bn254::Fq12::ONE;
    if (f * wi).pow(&*COFACTOR_CUBIC.to_u64_digits()) != ark_bn254::Fq12::ONE {
        wi *= w;
        if (f * wi).pow(&*COFACTOR_CUBIC.to_u64_digits()) != ark_bn254::Fq12::ONE {
            wi *= w;
            log_assert_eq!(
                (f * wi).pow(&*COFACTOR_CUBIC.to_u64_digits()),
                ark_bn254::Fq12::ONE
            );
        }
    }
    log_assert_eq!(wi.pow(&*H.to_u64_digits()), ark_bn254::Fq12::ONE);

    // f1 is scaled f
    let f1 = f * wi;

    // r-th root of f1, say f2
    let r_inv = R.modinv(&H).unwrap();
    log_assert_ne!(r_inv, BigUint::one());
    let f2 = f1.pow(r_inv.to_u64_digits());
    log_assert_ne!(f2, ark_bn254::Fq12::ONE);

    // m'-th root of f, say f3
    let mm_inv = MM.modinv(&(&*R * &*H)).unwrap();
    log_assert_ne!(mm_inv, BigUint::one());
    let f3 = f2.pow(mm_inv.to_u64_digits());
    log_assert_eq!(f3.pow(&*COFACTOR_CUBIC.to_u64_digits()), ark_bn254::Fq12::ONE);
    log_assert_ne!(f3, ark_bn254::Fq12::ONE);

    // d-th (cubic) root, say c
    let c = tonelli_shanks_cubic(f3, w, S, T.clone(), K.clone());
    log_assert_ne!(c, ark_bn254::Fq12::ONE);
    log_assert_eq!(c.pow(LAMBDA.to_u64_digits()), f * wi);

    (c, wi)
}
