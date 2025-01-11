use crate::bn254::ell_coeffs::G2Prepared;
use crate::bn254::g2::collect_line_coeffs;
use crate::chunker::chunk_g1_points::g1_points;
use crate::chunker::chunk_msm::chunk_hinted_msm_with_constant_bases_affine;
use crate::chunker::chunk_non_fixed_point::chunk_q4;
use crate::chunker::elements::{ElementTrait, DataType::Fq6Data,Fq6Type, FrType, G2PointType};
use crate::chunker::{chunk_accumulator, chunk_hinted_accumulator};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::log_assert_eq;
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;

use super::assigner::BCAssigner;
use super::segment::Segment;

/// This function outputs a vector segment, which is equivalent to the plain groth16 verifier.
/// Each segment will generate script and witness for each branch of disprove transaction.
/// Bitcommitments are collected into assinger.
pub fn groth16_verify_to_segments<T: BCAssigner>(
    assigner: &mut T,
    public_inputs: &[<Bn254 as ark_Pairing>::ScalarField],
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Vec<Segment> {
    let scalars = [
        vec![<Bn254 as ark_Pairing>::ScalarField::ONE],
        public_inputs.to_owned(),
    ]
    .concat();
    let msm_g1 = G1Projective::msm(&vk.gamma_abc_g1, &scalars).expect("failed to calculate msm");

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

    log_assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let q_prepared = [
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    let p_lst = vec![p1, p2, p3, p4];

    let mut segments = vec![];

    // skip the first scalar
    let mut scalar_types = vec![FrType::new_dummy("scalar_0")];
    for (idx, scalar) in scalars.iter().enumerate().skip(1) {
        let mut scalar_type = FrType::new(assigner, &format!("scalar_{}", idx));
        scalar_type.fill_with_data(crate::chunker::elements::DataType::FrData(*scalar));
        scalar_types.push(scalar_type);
    }

    // calculate p1
    let (segment, p1_type) = chunk_hinted_msm_with_constant_bases_affine(
        assigner,
        &vk.gamma_abc_g1,
        &scalars,
        &scalar_types,
    );

    segments.extend(segment);

    let (segment, tp_lst) = g1_points(assigner, p1_type, p1, proof, vk);
    segments.extend(segment);

    let constants = q_prepared.to_vec();
    assert_eq!(constants.len(), 4);
    let num_line_groups = constants.len();
    let mut line_coeffs_4: Vec<Vec<Fq6Type>> = vec![];
    let line_coeffs = collect_line_coeffs(constants);
    for i in 0..line_coeffs.len() {
        let line_coeff = &line_coeffs[i];
        assert_eq!(line_coeff.len(), num_line_groups);
        let mut line_coeff_4 = vec![];
        for j in 0..line_coeff[num_line_groups-1].len() {
            let coeff = &line_coeff[num_line_groups-1][j];
            let mut fq6 = Fq6Type::new(assigner, &format!("line_coeffs_4_{i}{j}"));
            let data = ark_bn254::Fq6::new(coeff.0,coeff.1,coeff.2);
            fq6.fill_with_data(Fq6Data(data));
            line_coeff_4.push(fq6);
        }
        line_coeffs_4.push(line_coeff_4);
    }

    let (segment, fs, f) = chunk_accumulator::chunk_accumulator(
        assigner,
        tp_lst,
        q_prepared.to_vec(),
        &line_coeffs_4,
        c,
        c_inv,
        wi,
        p_lst,
    );
    segments.extend(segment);

    let segment = chunk_hinted_accumulator::verify_accumulator(fs);
    segments.extend(segment);

    let mut q4_input = G2PointType::new(assigner, "q4");
    q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));
    let segment = chunk_q4(q_prepared.to_vec(),&line_coeffs_4, q4, q4_input, assigner);

    segments.extend(segment);

    segments
}

#[cfg(test)]
mod test {
    use crate::chunker::assigner::*;
    use crate::chunker::chunk_groth16_verifier::groth16_verify_to_segments;
    use crate::chunker::disprove_execution::RawProof;
    use crate::chunker::{common::*, elements::ElementTrait};
    use crate::treepp::*;
    use crate::{execute_script_with_inputs, log_assert_eq};

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ff::{BigInt, PrimeField};
    use ark_groth16::Groth16;
    use ark_groth16::{ProvingKey, VerifyingKey};
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{test_rng, UniformRand};
    use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
    use rand::{RngCore, SeedableRng};
    use std::collections::HashMap;

    #[derive(Default)]
    struct StatisticAssinger {
        commitments: HashMap<String, u32>,
        dummy_assigner: DummyAssigner,
    }
    impl StatisticAssinger {
        fn new() -> StatisticAssinger {
            StatisticAssinger {
                commitments: HashMap::new(),
                dummy_assigner: DummyAssigner::default(),
            }
        }
        fn commitment_count(&self) -> usize {
            self.commitments.len()
        }
    }

    impl BCAssigner for StatisticAssinger {
        fn create_hash(&mut self, id: &str) {
            if self.commitments.contains_key(id) {
                panic!("varible name is repeated, check {}", id);
            }
            self.commitments.insert(id.to_owned(), 1);
            self.dummy_assigner.create_hash(id);
        }

        fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
            self.dummy_assigner.locking_script(element)
        }

        fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
            self.dummy_assigner.get_witness(element)
        }

        fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
            self.dummy_assigner.all_intermediate_scripts()
        }

        fn all_intermediate_witnesses(
            &self,
            elements: std::collections::BTreeMap<String, std::rc::Rc<Box<dyn ElementTrait>>>,
        ) -> Vec<Vec<RawWitness>> {
            self.dummy_assigner.all_intermediate_witnesses(elements)
        }

        fn recover_from_witness(
            &mut self,
            witnesses: Vec<Vec<RawWitness>>,
            vk: VerifyingKey<ark_bn254::Bn254>,
        ) -> (std::collections::BTreeMap<String, BLAKE3HASH>, RawProof) {
            self.dummy_assigner.recover_from_witness(witnesses, vk)
        }
    }

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

    #[test]
    fn test_hinted_groth16_verifier() {
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

        let mut assigner = StatisticAssinger::new();

        let segments = groth16_verify_to_segments(&mut assigner, &vec![c], &proof, &vk);

        let mut small_segment_size = 0;
        let mut min_segment = 4_000_000;
        let mut max_segment = 0;

        for (_, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let witness = segment.witness(&assigner);
            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }

            let script = segment.script(&assigner);

            // script length + witness length
            let total_size = script.len() + lenw;

            // total size should not be bigger than 4M
            assert!(
                total_size < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            // how many segments are smaller than 1.6M
            if total_size < 1_600_000 {
                small_segment_size += 1;
            }

            // minimal size segment
            min_segment = min_segment.min(total_size);

            // maximal size segment
            max_segment = max_segment.max(total_size);

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            log_assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            log_assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            log_assert_eq!(
                (res.stats.max_nb_stack_items < 1000) as bool,
                true,
                "limit max stack usage {}",
                segment.name
            );
        }

        println!("segments number: {}", segments.len());
        println!("small_segment_size: {}", small_segment_size);
        println!("minimal segment size: {}", min_segment);
        println!("maximal segment size: {}", max_segment);
        println!("assign commitment size {}", assigner.commitment_count());
    }

    #[test]
    fn test_hinted_groth16_verifier_small_public() {
        type E = Bn254;
        let k = 6;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(
                <E as Pairing>::ScalarField::from_bigint(BigInt::from(u32::rand(&mut rng)))
                    .unwrap(),
            ),
            b: Some(
                <E as Pairing>::ScalarField::from_bigint(BigInt::from(u32::rand(&mut rng)))
                    .unwrap(),
            ),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        // let mut assigner = DummyAssinger {};
        let mut assigner = StatisticAssinger::new();

        let segments = groth16_verify_to_segments(&mut assigner, &vec![c], &proof, &vk);

        let mut small_segment_size = 0;

        for (_, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let witness = segment.witness(&assigner);
            let script = segment.script(&assigner);

            if script.len() < 1600 * 1000 {
                small_segment_size += 1;
            }

            let mut lenw = 0;
            for w in witness.iter() {
                lenw += w.len();
            }
            assert!(
                script.len() + lenw < 4000000,
                "script and witness len is over 4M {}",
                segment.name
            );

            let res = execute_script_with_inputs(script, witness);
            let zero: Vec<u8> = vec![];
            assert_eq!(res.final_stack.len(), 1, "{}", segment.name); // only one element left
            assert_eq!(res.final_stack.get(0), zero, "{}", segment.name);
            assert!(
                res.stats.max_nb_stack_items < 1000,
                "{} in {}",
                res.stats.max_nb_stack_items,
                segment.name
            );
        }

        println!("segments number: {}", segments.len());
        println!("small_segment_size: {}", small_segment_size);
        println!("assign commitment size {}", assigner.commitment_count());
    }

    #[test]
    fn test_hinted_groth16_verifier_stable() {
        type E = Bn254;
        let k = 6;
        let mut rng: rand::prelude::StdRng =
            ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit: DummyCircuit<<ark_ec::bn::Bn<ark_bn254::Config> as Pairing>::ScalarField> =
            DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
                b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
                num_variables: 10,
                num_constraints: 1 << k,
            };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        // let mut segmentes = vec![];
        let mut hashes = vec![];
        let count = 2;
        for i in 0..count {
            println!("generate hash {}", i);
            // let (hash, segment) = test_hinted_groth16_verifier_stable_tool();
            let hash = test_hinted_groth16_verifier_stable_tool(&mut rng, &pk, &vk);

            hashes.push(hash);
            // segmentes.push(segment)
        }
        for i in 1..count {
            assert_eq!(
                hashes[i].len(),
                hashes[i - 1].len(),
                "test{} len {}",
                i,
                hashes[i].len()
            );

            for j in 0..hashes[i].len() {
                // assert_eq!(hashes[i][j] , hashes[i-1][j], "segment  {} {} name {}", i, j, segmentes[i][j].name);
                assert_eq!(hashes[i][j], hashes[i - 1][j], "segment  {} {} ", i, j);
            }
        }
    }

    // fn test_hinted_groth16_verifier_stable_tool() -> (Vec<Sha256>, Vec<Segment>) {
    fn test_hinted_groth16_verifier_stable_tool(
        rng: &mut rand::prelude::StdRng,
        pk: &ProvingKey<Bn254>,
        vk: &VerifyingKey<Bn254>,
    ) -> Vec<Sha256> {
        type E = Bn254;
        let k = 6;
        // let mut rng: rand::prelude::StdRng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
            a: Some(<E as Pairing>::ScalarField::rand(rng)),
            b: Some(<E as Pairing>::ScalarField::rand(rng)),
            num_variables: 10,
            num_constraints: 1 << k,
        };
        let c = circuit.a.unwrap() * circuit.b.unwrap();

        let proof = Groth16::<E>::prove(pk, circuit, rng).unwrap();

        let mut assigner = DummyAssigner::default();
        let segments = groth16_verify_to_segments(&mut assigner, &vec![c], &proof, &vk);

        println!("segments number: {}", segments.len());

        let mut hashes = vec![];
        for (i, segment) in tqdm::tqdm(segments.iter().enumerate()) {
            let script = segment.script(&assigner);
            let hash = Sha256::hash(script.compile().as_bytes());
            println!("segment {} {} hash {}", i, segment.name, hash.clone());

            hashes.push(hash);
        }

        // (hashes, segments)
        hashes
    }
}
