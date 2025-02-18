use ark_bn254::{Bn254, Fr};

use crate::chunk::api_compiletime_utils::{NUM_PUBS, NUM_TAPS, NUM_U160, NUM_U256};
use crate::signatures::wots_api::{wots160, wots256};
use crate::{chunk, treepp::*};

pub const N_VERIFIER_PUBLIC_INPUTS: usize = NUM_PUBS;
pub const N_VERIFIER_FQS: usize = NUM_U256;
pub const N_VERIFIER_HASHES: usize = NUM_U160;
pub const N_TAPLEAVES: usize = NUM_TAPS;

pub type Proof = ark_groth16::Proof<Bn254>;
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;

pub type PublicInputs = [Fr; N_VERIFIER_PUBLIC_INPUTS];

pub type PublicKeys = (
    [wots256::PublicKey; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::PublicKey; N_VERIFIER_FQS],
    [wots160::PublicKey; N_VERIFIER_HASHES],
);

pub type Signatures = (
    [wots256::Signature; N_VERIFIER_PUBLIC_INPUTS],
    [wots256::Signature; N_VERIFIER_FQS],
    [wots160::Signature; N_VERIFIER_HASHES],
);

pub type Assertions = (
    [[u8; 32]; N_VERIFIER_PUBLIC_INPUTS],
    [[u8; 32]; N_VERIFIER_FQS],
    [[u8; 20]; N_VERIFIER_HASHES],
);

pub fn compile_verifier(vk: VerifyingKey) -> [Script; N_TAPLEAVES] {
    chunk::api::api_generate_partial_script(&vk).try_into().unwrap()
}

pub fn generate_disprove_scripts(
    public_keys: PublicKeys,
    partial_disprove_scripts: &[Script; N_TAPLEAVES],
) -> [Script; N_TAPLEAVES] {
    chunk::api::api_generate_full_tapscripts(public_keys, partial_disprove_scripts)
        .try_into()
        .unwrap()
}

pub fn generate_proof_assertions(vk: VerifyingKey, proof: Proof, public_inputs: PublicInputs) -> Assertions {
    chunk::api::generate_assertions(proof, public_inputs.to_vec(), &vk)
}

pub fn generate_proof_signature(vk: VerifyingKey, proof: Proof, public_inputs: PublicInputs, secret: &str) -> Signatures {
    chunk::api::generate_signatures(proof, public_inputs.to_vec(), &vk, secret)
}

/// Validates the groth16 proof assertion signatures and returns a tuple of (tapleaf_index, witness_script) if
/// the proof is invalid, else returns none
pub fn verify_signed_assertions(
    vk: VerifyingKey,
    public_keys: PublicKeys,
    signatures: Signatures,
    disprove_scripts: &[Script; N_TAPLEAVES],
) -> Option<(usize, Script)> {
    chunk::api::validate_assertions(&vk,signatures,public_keys, disprove_scripts)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ark_ec::{pairing::Pairing, AffineRepr};
    
    
    use rand::Rng;

    use crate::groth16::g16::test::test_utils::{read_scripts_from_file, write_scripts_to_file, write_scripts_to_separate_files};


    use self::{chunk::api_compiletime_utils::NUM_PUBS, test_utils::{read_map_from_file, write_map_to_file}};

    use super::*;


    mod test_utils {
        use crate::treepp::*;
        use bitcoin::ScriptBuf;
        use std::collections::HashMap;
        use std::error::Error;
        use std::fs::File;
        use std::io::BufReader;
        use std::io::Write;


        pub(crate) fn write_map_to_file(
            map: &HashMap<u32, Vec<Vec<u8>>>,
            filename: &str,
        ) -> Result<(), Box<dyn Error>> {
            // Serialize the map to a JSON string
            let json = serde_json::to_string(map)?;

            // Write the JSON string to a file
            let mut file = File::create(filename)?;
            file.write_all(json.as_bytes())?;
            Ok(())
        }

        pub(crate) fn read_map_from_file(
            filename: &str,
        ) -> Result<HashMap<u32, Vec<Vec<u8>>>, Box<dyn Error>> {
            let file = File::open(filename)?;
            let reader = BufReader::new(file);
            let map = serde_json::from_reader(reader)?;
            Ok(map)
        }

        pub fn write_scripts_to_file(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
            let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            for (k, v) in sig_cache {
                let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
                buf.insert(k, vs);
            }
            write_map_to_file(&buf, file).unwrap();
        }

        pub fn write_scripts_to_separate_files(sig_cache: HashMap<u32, Vec<Script>>, file: &str) {
            let mut buf: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
            std::fs::create_dir_all("bridge_data/chunker_data")
                .expect("Failed to create directory structure");

            for (k, v) in sig_cache {
                let file = format!("bridge_data/chunker_data/{file}_{k}.json");
                let vs = v.into_iter().map(|x| x.compile().to_bytes()).collect();
                buf.insert(k, vs);
                write_map_to_file(&buf, &file).unwrap();
                buf.clear();
            }
        }

        pub fn read_scripts_from_file(file: &str) -> HashMap<u32, Vec<Script>> {
            let mut scr: HashMap<u32, Vec<Script>> = HashMap::new();
            let f = read_map_from_file(file).unwrap();
            for (k, v) in f {
                let vs: Vec<Script> = v
                    .into_iter()
                    .map(|x| {
                        let sc = script! {};
                        let bf = ScriptBuf::from_bytes(x);
                        
                        sc.push_script(bf)
                    })
                    .collect();
                scr.insert(k, vs);
            }
            scr
        }

    }

    pub mod mock {
        use super::*;
        use ark_bn254::Bn254;
        use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
        use ark_ff::{BigInt, PrimeField};
        use ark_groth16::{Groth16, ProvingKey};
        use ark_relations::{lc, r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError}};
        use ark_std::test_rng;
        use rand::{RngCore, SeedableRng};
        

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

        pub fn compile_circuit() -> (ProvingKey<Bn254>, VerifyingKey) {
            type E = Bn254;
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let (a, b): (u32, u32) = (5, 6);
            let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(a)).unwrap()),
                b: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(b)).unwrap()),
                num_variables: 10,
                num_constraints: 1 << 6,
            };

            let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();
            (pk, vk)
        }

        pub fn generate_proof() -> (Proof, PublicInputs) {
            type E = Bn254;

            let (a, b): (u32, u32) = (5, 6);

            //let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
            let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
                a: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(a)).unwrap()),
                b: Some(<E as Pairing>::ScalarField::from_bigint(BigInt::from(b)).unwrap()),
                num_variables: 10,
                num_constraints: 1 << 6,
            };

            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

            let (pk, _) = compile_circuit();
            let pub_c = circuit.a.unwrap() * circuit.b.unwrap();

            let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
            let public_inputs = [pub_c];

            (proof, public_inputs)
        }
    }

    
    const MOCK_SECRET: &str = "a138982ce17ac813d505a5b40b665d404e9528e7";

    fn sign_assertions(assn: Assertions) -> Signatures {
        let (ps, fs, hs) = (assn.0, assn.1, assn.2);
        let secret = MOCK_SECRET;
        
        let mut psig: Vec<wots256::Signature> = vec![];
        for i in 0..NUM_PUBS {
            let psi = wots256::get_signature(&format!("{secret}{:04x}", i), &ps[i]);
            psig.push(psi);
        }
        let psig: [wots256::Signature; NUM_PUBS] = psig.try_into().unwrap();

        let mut fsig: Vec<wots256::Signature> = vec![];
        for i in 0..fs.len() {
            let fsi = wots256::get_signature(&format!("{secret}{:04x}", NUM_PUBS + i), &fs[i]);
            fsig.push(fsi);
        }
        let fsig: [wots256::Signature; N_VERIFIER_FQS] = fsig.try_into().unwrap();

        let mut hsig: Vec<wots160::Signature> = vec![];
        for i in 0..hs.len() {
            let hsi =
                wots160::get_signature(&format!("{secret}{:04x}", NUM_PUBS + fs.len() + i), &hs[i]);
            hsig.push(hsi);
        }
        let hsig: [wots160::Signature; N_VERIFIER_HASHES] = hsig.try_into().unwrap();

        
        (psig, fsig, hsig)
    }

    // Step 1: Anyone can Generate Operation (mul & hash) part of tapscript: same for all vks
    #[test]
    fn test_fn_compile() {
        let (_, mock_vk) = mock::compile_circuit();
        
        assert_eq!(mock_vk.gamma_abc_g1.len(), NUM_PUBS + 1); 

        let ops_scripts = compile_verifier(mock_vk);
        let mut script_cache = HashMap::new();

        for i in 0..ops_scripts.len() {
            script_cache.insert(i as u32, vec![ops_scripts[i].clone()]);
        }

        write_scripts_to_separate_files(script_cache, "tapnode");
    }

    pub fn mock_pubkeys(mock_secret: &str) -> PublicKeys {

        let mut pubins = vec![];
        for i in 0..NUM_PUBS {
            pubins.push(wots256::generate_public_key(&format!("{mock_secret}{:04x}", i)));
        }
        let mut fq_arr = vec![];
        for i in 0..N_VERIFIER_FQS {
            let p256 = wots256::generate_public_key(&format!("{mock_secret}{:04x}", NUM_PUBS + i));
            fq_arr.push(p256);
        }
        let mut h_arr = vec![];
        for i in 0..N_VERIFIER_HASHES {
            let p160 = wots160::generate_public_key(&format!("{mock_secret}{:04x}", N_VERIFIER_FQS + NUM_PUBS + i));
            h_arr.push(p160);
        }
        let wotspubkey: PublicKeys = (
            pubins.try_into().unwrap(),
            fq_arr.try_into().unwrap(),
            h_arr.try_into().unwrap(),
        );
        wotspubkey
    }

    // Step 2: Operator Generates keypairs and broadcasts pubkeys for a Bitvm setup; 
    // Anyone can create Bitcomm part of tapscript; yields complete tapscript
    #[test]
    fn test_fn_generate_tapscripts() {
        println!("start");

        let (_, mock_vk) = mock::compile_circuit();
        println!("compiled circuit");

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1); 
        let mock_pubs = mock_pubkeys(MOCK_SECRET);
        let mut op_scripts = vec![];

        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");

        for i in 0..N_TAPLEAVES {
            println!("taps_len {}", op_scripts[i].len());
        }

        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap(); //compile_verifier(mock_vk);

        let tapscripts = generate_disprove_scripts(mock_pubs, &ops_scripts);
        println!(
            "tapscript.lens: {:?}",
            tapscripts.clone().map(|script| script.len())
        );
 

    }

    // Step 3: Operator Generates Assertions, Signs it and submit on chain
    #[test]
    fn test_fn_generate_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);
        let proof_asserts = generate_proof_assertions(mock_vk, proof, public_inputs);
        println!("signed_asserts {:?}", proof_asserts);
   
        std::fs::create_dir_all("bridge_data/chunker_data")
        .expect("Failed to create directory structure");
    
        write_asserts_to_file(proof_asserts, "bridge_data/chunker_data/assert.json");
        let _signed_asserts = sign_assertions(proof_asserts);
    }

    // Step 3: Operator Generates Assertions, Signs it and submit on chain
    #[test]
    fn test_fn_generate_signatures() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);
        let _ = generate_proof_signature(mock_vk, proof, public_inputs, MOCK_SECRET);
        //println!("signed_asserts {:?}", proof_asserts);
    
        // std::fs::create_dir_all("bridge_data/chunker_data")
        // .expect("Failed to create directory structure");
    
        // write_asserts_to_file(proof_asserts, "bridge_data/chunker_data/assert.json");
        // let _signed_asserts = sign_assertions(proof_asserts);
    }

    #[test]
    fn test_fn_validate_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert!(mock_vk.gamma_abc_g1.len() == NUM_PUBS + 1);

        let mut op_scripts = vec![];
        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");
        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap();

       let mock_pubks = mock_pubkeys(MOCK_SECRET);
       let verifier_scripts = generate_disprove_scripts(mock_pubks, &ops_scripts);

    //     // let proof_asserts = generate_proof_assertions(mock_vk.clone(), proof, public_inputs);
        let proof_asserts = read_asserts_from_file("bridge_data/chunker_data/assert.json");
        let signed_asserts = sign_assertions(proof_asserts);
    //     let mock_pubks = mock_pubkeys(MOCK_SECRET);

        println!("verify_signed_assertions");
        let fault = verify_signed_assertions(mock_vk, mock_pubks, signed_asserts, &verifier_scripts);
        assert!(fault.is_none());
    }

    

    fn corrupt(proof_asserts: &mut Assertions, random: Option<usize>) {
        let mut rng = rand::thread_rng();

        // Generate a random number between 1 and 100 (inclusive)
        let mut index = rng.gen_range(0..N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES);
        if random.is_some() {
            index = random.unwrap();
        }
        // WARN: KNOWN ISSUE: scramble: [u8; 32] = [255; 32]; fails because tapscripts do not check that the asserted value is a field element 
        // A 256 bit number is not a field element. For now, this prototype only supports corruption that is still a field element
        let mut scramble: [u8; 32] = [0u8; 32];
        scramble[16] = 37;
        let mut scramble2: [u8; 20] = [0u8; 20];
        scramble2[10] = 37;
        println!("corrupted assertion at index {}", index);
        if index < N_VERIFIER_PUBLIC_INPUTS {
            if index == 0 {
                if proof_asserts.0[0] == scramble {
                    scramble[16] += 1;
                }
                proof_asserts.0[0] = scramble;
            } 
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS {
            let index = index - N_VERIFIER_PUBLIC_INPUTS;
            if proof_asserts.1[index] == scramble {
                scramble[16] += 1;
            }
            proof_asserts.1[index] = scramble;
        } else if index < N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES {
            let index = index - N_VERIFIER_PUBLIC_INPUTS - N_VERIFIER_FQS;
            if proof_asserts.2[index] == scramble2 {
                scramble2[10] += 1;
            }
            proof_asserts.2[index] = scramble2;
        }
    }

    // Step 4: Challenger finds fault given signatures
    #[test]
    fn test_fn_disprove_invalid_assertions() {
        let (_, mock_vk) = mock::compile_circuit();
        let (proof, public_inputs) = mock::generate_proof();

        assert_eq!(mock_vk.gamma_abc_g1.len(), NUM_PUBS+1); 

        let mut op_scripts = vec![];
        println!("load scripts from file");
        for index in 0..N_TAPLEAVES {
            let read = read_scripts_from_file(&format!("bridge_data/chunker_data/tapnode_{index}.json"));
            let read_scr = read.get(&(index as u32)).unwrap();
            assert_eq!(read_scr.len(), 1);
            let tap_node = read_scr[0].clone();
            op_scripts.push(tap_node);
        }
        println!("done");
        let ops_scripts: [Script; N_TAPLEAVES] = op_scripts.try_into().unwrap();

        let mock_pubks = mock_pubkeys(MOCK_SECRET);
        let verifier_scripts = generate_disprove_scripts(mock_pubks, &ops_scripts);


        let total = N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + N_VERIFIER_HASHES;
        for i in 0..1{ //total {
            println!("ITERATION {:?}", i);
            let mut proof_asserts = read_asserts_from_file("bridge_data/chunker_data/assert.json");
            corrupt(&mut proof_asserts, Some(i));
            let signed_asserts = sign_assertions(proof_asserts);
    
            let fault = verify_signed_assertions(mock_vk.clone(), mock_pubks, signed_asserts, &verifier_scripts);
            assert!(fault.is_some());
            if fault.is_some() {
                let (index, hint_script) = fault.unwrap();
                println!("taproot index {:?}", index);
                let scr = script!(
                    {hint_script.clone()}
                    {verifier_scripts[index].clone()}
                );
                let res = execute_script(scr);
                for i in 0..res.final_stack.len() {
                    println!("{i:} {:?}", res.final_stack.get(i));
                }
                let mut disprove_map: HashMap<u32, Vec<Script>> = HashMap::new();
                let disprove_f = &format!("bridge_data/chunker_data/disprove_{index}.json");
                disprove_map.insert(index as u32, vec![hint_script]);
                write_scripts_to_file(disprove_map, disprove_f);
                assert!(res.success);
            }
        }
    }

    fn write_asserts_to_file(proof_asserts: Assertions, filename: &str) {
        //let proof_asserts = mock_asserts();
        let mut proof_vec: Vec<Vec<u8>> = vec![];
        for k in proof_asserts.0 {
            proof_vec.push(k.to_vec());
        }
        for k in proof_asserts.1 {
            proof_vec.push(k.to_vec());
        }
        for k in proof_asserts.2 {
            proof_vec.push(k.to_vec());
        }
        let mut obj: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        obj.insert(0, proof_vec);

        write_map_to_file(&obj, filename).unwrap();
    }

    fn read_asserts_from_file(filename: &str) -> Assertions {
        let res = read_map_from_file(filename).unwrap();
        let proof_vec = res.get(&0).unwrap();
        
        let mut assert1 = vec![];
        for i in 0..N_VERIFIER_PUBLIC_INPUTS {
            let v:[u8;32] = proof_vec[i].clone().try_into().unwrap();
            assert1.push(v);
        }
        let assert1: [[u8; 32]; N_VERIFIER_PUBLIC_INPUTS] = assert1.try_into().unwrap();

        let mut assert2 = vec![];
        for i in 0..N_VERIFIER_FQS {
            let v:[u8;32] = proof_vec[N_VERIFIER_PUBLIC_INPUTS + i].clone().try_into().unwrap();
            assert2.push(v);
        }
        let assert2: [[u8; 32]; N_VERIFIER_FQS] = assert2.try_into().unwrap();

        let mut assert3 = vec![];
        for i in 0..N_VERIFIER_HASHES {
            let v:[u8;20] = proof_vec[N_VERIFIER_PUBLIC_INPUTS + N_VERIFIER_FQS + i].clone().try_into().unwrap();
            assert3.push(v);
        }
        let assert3: [[u8; 20]; N_VERIFIER_HASHES] = assert3.try_into().unwrap();
        (assert1, assert2, assert3)
    }

}
