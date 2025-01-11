use super::common::not_equal;
use super::elements::Fq12Type;
use super::segment::Segment;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::treepp::*;

pub fn verify_accumulator(pa: Fq12Type) -> Vec<Segment> {
    let script = script! {
        {Fq12::push(<ark_bn254::Fq12 as ark_ff::Field>::ONE)}
        {not_equal(Fq::N_LIMBS as usize * 12)}
    };

    let mut segments = vec![];
    let segment = Segment::new_with_name(format!("{}", "verify_f"), script)
        .add_parameter(&pa)
        .mark_final();

    segments.push(segment);
    segments
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bn254::ell_coeffs::G2Prepared;
    use crate::bn254::g2::collect_line_coeffs;
    use crate::chunker::assigner::*;
    use crate::chunker::chunk_accumulator::*;
    use crate::chunker::chunk_g1_points::*;
    use crate::chunker::elements::DataType::G1PointData;
    use crate::chunker::elements::Fq6Type;
    use crate::chunker::elements::{DataType::Fq6Data,DataType::Fq12Data, ElementTrait, G1PointType};
    use crate::execute_script_with_inputs;
    use crate::groth16::constants::{LAMBDA, P_POW3};
    use crate::groth16::offchain_checker::compute_c_wi;

    use ark_bn254::Bn254;
    use ark_bn254::G1Projective;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing as ark_Pairing;
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_ff::{Field, PrimeField};
    use ark_groth16::Groth16;
    use ark_groth16::{Proof, VerifyingKey};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};

    use core::ops::Neg;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[derive(Copy)]
    struct DummyCircuit<F: PrimeField> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_variables: usize,
        pub num_constraints: usize,
    }

    impl<F: PrimeField> Clone for DummyCircuit<F> {
        fn clone(&self) -> Self {
            DummyCircuit {
                a: self.a,
                b: self.b,
                num_variables: self.num_variables,
                num_constraints: self.num_constraints,
            }
        }
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.new_input_variable(|| {
                let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                Ok(a * b)
            })?;

            for _ in 0..(self.num_variables - 3) {
                let _ =
                    cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            }

            for _ in 0..self.num_constraints - 1 {
                cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            }

            cs.enforce_constraint(lc!(), lc!(), lc!())?;

            Ok(())
        }
    }

    pub fn generate_p1<T: BCAssigner>(
        assigner: &mut T,
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        vk: &VerifyingKey<Bn254>,
    ) -> (ark_bn254::G1Affine, G1PointType) {
        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let msm_g1 =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

        let g1a = msm_g1.into_affine();
        let mut g1p = G1PointType::new(assigner, "test");
        g1p.fill_with_data(G1PointData(g1a));

        (g1a, g1p)
    }

    pub fn generate_f_arg(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> (
        Vec<G2Prepared>,
        ark_bn254::Fq12,
        ark_bn254::Fq12,
        ark_bn254::Fq12,
        Vec<ark_bn254::G1Affine>,
        ark_bn254::G2Affine,
    ) {
        // constants: Vec<G2Prepared>,
        // c: ark_bn254::Fq12,
        // c_inv: ark_bn254::Fq12,
        // wi: ark_bn254::Fq12,
        // p_lst: Vec<ark_bn254::G1Affine>,
        // q4: ark_bn254::G2Affine,

        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let msm_g1 =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

        let (_, _) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };

        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        let _t4 = q4;

        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let q_prepared = [G2Prepared::from_affine(q1),
            G2Prepared::from_affine(q2),
            G2Prepared::from_affine(q3),
            G2Prepared::from_affine(q4)];

        let p_lst = vec![p1, p2, p3, p4];
        (q_prepared.to_vec(), c, c_inv, wi, p_lst, q4)
    }

    pub fn generate_f(
        public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
        proof: &Proof<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> ark_bn254::Fq12 {
        let scalars = [
            vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
            public_inputs.clone(),
        ]
        .concat();
        let msm_g1 =
            G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");
        let (exp, sign) = if LAMBDA.gt(&P_POW3) {
            (&*LAMBDA - &*P_POW3, true)
        } else {
            (&*P_POW3 - &*LAMBDA, false)
        };
        // G1/G2 points for pairings
        let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
        let (q1, q2, q3, q4) = (
            vk.gamma_g2.into_group().neg().into_affine(),
            vk.delta_g2.into_group().neg().into_affine(),
            -vk.beta_g2,
            proof.b,
        );
        // hint from arkworks
        let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
        let (c, wi) = compute_c_wi(f);
        let c_inv = c.inverse().unwrap();
        let hint = if sign {
            f * wi * (c_inv.pow((exp).to_u64_digits()))
        } else {
            f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
        };
        assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");
        hint
    }

    #[allow(unused)]
    fn test_g1_points() {
        let mut assigner = DummyAssigner::default();

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        // let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);
        let (g1a, g1p) = generate_p1(&mut assigner, &vec![c], &vk);
        let (segments, _) = g1_points(&mut assigner, g1p, g1a, &proof, &vk);

        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }

    #[test]
    fn test_chunk_accumulator() {
        let mut assigner = DummyAssigner::default();

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let rc = ark_bn254::Fq12::rand(&mut prng);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c"));
        tc.fill_with_data(Fq12Data(rc));
        let tf = generate_f(&vec![c], &proof, &vk);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c1"));
        tc.fill_with_data(Fq12Data(tf));

        // let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);
        let (g1a, g1p) = generate_p1(&mut assigner, &vec![c], &vk);
        let (_, tp_lst) = g1_points(&mut assigner, g1p, g1a, &proof, &vk);

        let (constants, c, c_inv, wi, p_lst, _) = generate_f_arg(&vec![c], &proof, &vk);
        

        let constants = constants.clone();
        assert_eq!(constants.len(), 4);
        let num_line_groups = constants.len();
        let mut line_coeffs_4: Vec<Vec<Fq6Type>> = vec![];
        let line_coeffs = collect_line_coeffs(constants.clone());
        for i in 0..line_coeffs.len() {
            let line_coeff = &line_coeffs[i];
            assert_eq!(line_coeff.len(), num_line_groups);
            let mut line_coeff_4 = vec![];
            for j in 0..line_coeff[num_line_groups-1].len() {
                let coeff = &line_coeff[num_line_groups-1][j];
                let mut fq6 = Fq6Type::new(&mut assigner, &format!("line_coeffs_4_{i}{j}"));
                let data = ark_bn254::Fq6::new(coeff.0,coeff.1,coeff.2);
                fq6.fill_with_data(Fq6Data(data));
                line_coeff_4.push(fq6);
            }
            line_coeffs_4.push(line_coeff_4);
        }
        
        let (segments, fs, f) =
            chunk_accumulator(&mut assigner, tp_lst, constants, &line_coeffs_4,c, c_inv, wi, p_lst);
        println!("tf: {} \n f: {}", tf, f);
        println!("tc: {:?} \n fs: {:?}", tc, fs);

        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }

    #[test]
    fn test_verify_accumulator() {
        let mut assigner = DummyAssigner::default();

        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        let mut prng: ChaCha20Rng = ChaCha20Rng::seed_from_u64(0);
        let rc = ark_bn254::Fq12::rand(&mut prng);
        let mut tc = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c"));
        tc.fill_with_data(Fq12Data(rc));
        let f = generate_f(&vec![c], &proof, &vk);
        let mut tc1 = Fq12Type::new(&mut assigner, &format!("{}{}", "test".to_owned(), "c1"));
        tc1.fill_with_data(Fq12Data(f));

        let segments = verify_accumulator(tc1);
        println!("segments len {}", segments.len());
        for segment in segments {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            let res = execute_script_with_inputs(script.clone(), witness.clone());
            println!("segment exec_result: {}", res);

            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{}",
                res.stats.max_nb_stack_items
            );

            let mut lenw = 0;
            for w in witness {
                lenw += w.len();
            }
            assert!(script.len() + lenw < 4000000, "script and witness len");
        }
    }
}
