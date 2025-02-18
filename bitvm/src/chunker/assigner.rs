use ark_groth16::VerifyingKey;
use itertools::Itertools;

use super::{
    chunk_groth16_verifier::groth16_verify_to_segments,
    common::{self, *},
    disprove_execution::RawProof,
    elements::ElementTrait,
};
use crate::{
    signatures::signing_winternitz::{
        generate_winternitz_checksig_leave_hash, generate_winternitz_checksig_leave_variable,
        generate_winternitz_witness, WinternitzPublicKey, WinternitzSecret,
        WinternitzSigningInputs,
    },
    execute_script_with_inputs,
    treepp::*,
};
use std::{collections::BTreeMap, rc::Rc};

/// Implement `BCAssinger` to adapt with bridge.
#[allow(clippy::borrowed_box)]
pub trait BCAssigner: Default {
    /// check hash
    fn create_hash(&mut self, id: &str);
    /// return a element of
    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness;
    /// output sciprt for all elements, used by assert transaction
    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>>;
    /// output witness for all elements, used by assert transaction
    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>>;
    /// recover hashes from witnesses
    fn recover_from_witnesses(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
        vk: VerifyingKey<ark_bn254::Bn254>,
    ) -> (BTreeMap<String, BLAKE3HASH>, RawProof);
}

#[derive(Default)]
pub struct DummyAssigner {
    bc_map: BTreeMap<String, String>,
}

impl BCAssigner for DummyAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), id.to_string());
    }

    fn locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
        script! {}
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        if common::PROOF_NAMES.contains(&element.id()) {
            // if element is original proof, commit them original message
            element.to_witness().unwrap()
        } else {
            // else use the hash of element
            element.to_hash_witness().unwrap()
        }
    }

    fn recover_from_witnesses(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
        vk: VerifyingKey<ark_bn254::Bn254>,
    ) -> (BTreeMap<String, BLAKE3HASH>, RawProof) {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.bc_map.len());

        let mut raw_proof_recover = RawProofRecover::default();
        for ((id, _), idx) in self.bc_map.iter().zip(0..flat_witnesses.len()) {
            // skip when the param is in proof
            if common::PROOF_NAMES.contains(&&*id.clone()) {
                raw_proof_recover.add_witness(&id.clone(), flat_witnesses[idx].clone());
                continue;
            }
            btree_map.insert(id.to_owned(), witness_to_array(flat_witnesses[idx].clone()));
        }

        // rebuild the raw proof
        let raw_proof = raw_proof_recover.to_raw_proof(vk).unwrap();

        (btree_map, raw_proof)
    }

    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
        vec![self.bc_map.iter().map(|(_, _)| script! {}).collect()]
    }

    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>> {
        for (key, _) in self.bc_map.iter() {
            if !elements.contains_key(key) {
                println!("unconsistent key: {}", key)
            }
        }
        assert_eq!(elements.len(), self.bc_map.len());
        vec![elements
            .values()
            .map(|element| self.get_witness(element))
            .collect()]
    }
}

/// This assigner records all intermediate values messages.
/// It run the entire chunker with a default proof. A git-commit-related cache may reduce the time.
#[derive(Default)]
pub struct BridgeAssigner {
    bc_map: BTreeMap<String, usize>,
    commits_secrets: BTreeMap<String, WinternitzSecret>,
    commits_publickeys: BTreeMap<String, WinternitzPublicKey>,
    is_operator: bool,
    recoverd_witness_store: BTreeMap<String, RawWitness>,
}

impl BridgeAssigner {
    pub fn new_operator(commits_secrets: BTreeMap<String, WinternitzSecret>) -> Self {
        Self {
            bc_map: BTreeMap::new(),
            commits_publickeys: commits_secrets
                .iter()
                .map(|(k, v)| (k.clone(), v.into()))
                .collect(),
            commits_secrets,
            is_operator: true,
            recoverd_witness_store: BTreeMap::new(),
        }
    }

    pub fn new_variable_tracer() -> Self {
        Self::default()
    }

    pub fn new_watcher(commits_publickeys: BTreeMap<String, WinternitzPublicKey>) -> Self {
        Self {
            bc_map: BTreeMap::new(),
            commits_secrets: BTreeMap::new(),
            commits_publickeys,
            is_operator: false,
            recoverd_witness_store: BTreeMap::new(),
        }
    }

    pub fn all_intermediate_variables(&mut self) -> BTreeMap<String, usize> {
        let proof = RawProof::default();
        let _ = groth16_verify_to_segments(self, &proof.public, &proof.proof, &proof.vk);
        self.bc_map.clone()
    }
}

impl BCAssigner for BridgeAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }

        self.bc_map
            .insert(id.to_string(), variable_name_to_size(id));
    }

    fn locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
        let var_name = element.id();
        if common::PROOF_NAMES.contains(&var_name) {
            generate_winternitz_checksig_leave_variable(
                self.commits_publickeys.get(var_name).unwrap_or_else(|| {
                    panic!("{}/{} variables", var_name, self.commits_publickeys.len())
                }),
                variable_name_to_size(var_name),
            )
        } else {
            generate_winternitz_checksig_leave_hash(
                self.commits_publickeys.get(var_name).unwrap_or_else(
                    || panic! {"{}/{} variables", var_name, self.commits_publickeys.len()},
                ),
                variable_name_to_size(var_name),
            )
        }
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        // for recover case
        if !self.is_operator {
            return self
                .recoverd_witness_store
                .get(element.id())
                .unwrap()
                .clone();
        }

        assert!(self.commits_secrets.contains_key(element.id()));
        let secret_key = self.commits_secrets.get(element.id()).unwrap();


        let message = if common::PROOF_NAMES.contains(&element.id()) {
            // if element is original proof, commit them original message
            &u32_witness_to_bytes(element.to_witness().unwrap())
        } else {
            // else use the hash of element
            &element.to_hash().unwrap().to_vec()
        };

        let signing_input = WinternitzSigningInputs {
            message,
            signing_key: secret_key,
        };

        generate_winternitz_witness(&signing_input).to_vec()
    }

    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>> {
        todo!()
    }

    fn all_intermediate_witnesses(
        &self,
        _elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>> {
        todo!()
    }

    fn recover_from_witnesses(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
        vk: VerifyingKey<ark_bn254::Bn254>,
    ) -> (BTreeMap<String, BLAKE3HASH>, RawProof) {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.commits_publickeys.len());

        self.recoverd_witness_store = BTreeMap::from_iter(
            self.commits_publickeys
                .clone()
                .into_keys()
                .collect_vec()
                .into_iter()
                .zip(flat_witnesses.clone()),
        );

        let mut raw_proof_recover = RawProofRecover::default();
        for ((var_name, _pk), witness) in self.commits_publickeys.iter().zip(flat_witnesses) {
            // skip when the param is in proof
            if common::PROOF_NAMES.contains(&&*var_name.clone()) {
                let script = generate_winternitz_checksig_leave_variable(
                    self.commits_publickeys.get(var_name).unwrap_or_else(|| {
                        panic!("{}/{} variables", var_name, self.commits_publickeys.len())
                    }),
                    variable_name_to_size(var_name),
                );
                let witness_left =
                    extract_witness_from_stack(execute_script_with_inputs(script, witness));
                raw_proof_recover.add_witness(&var_name.clone(), witness_left);
                continue;
            }
            let script = generate_winternitz_checksig_leave_hash(
                self.commits_publickeys.get(var_name).unwrap_or_else(
                    || panic! {"{}/{} variables", var_name, self.commits_publickeys.len()},
                ),
                variable_name_to_size(var_name),
            );
            let witness_left =
                extract_witness_from_stack(execute_script_with_inputs(script, witness));
            btree_map.insert(var_name.to_owned(), witness_to_array(witness_left));
        }

        // rebuild the raw proof
        let raw_proof = raw_proof_recover.to_raw_proof(vk).unwrap();

        (btree_map, raw_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::DummyAssigner;
    use crate::chunker::common::witness_size;
    use crate::execute_script_with_inputs;
    use crate::treepp::script;
    use crate::{
        signatures::signing_winternitz::{
            generate_winternitz_witness, winternitz_message_checksig, WinternitzPublicKey,
            WinternitzSecret, WinternitzSigningInputs,
        },
        chunker::{
            assigner::BridgeAssigner,
            disprove_execution::RawProof,
            elements::{ElementTrait as _, G2PointType},
        },
    };

    #[test]
    fn test_variable_names() {
        let variable_names = BridgeAssigner::default().all_intermediate_variables();
        println!("variable_name: {}", variable_names.len());
    }

    #[test]
    fn test_commitment_size() {
        let mut dummy_assigner = DummyAssigner::default();
        let proof = RawProof::default();
        let q4 = proof.proof.b;

        let mut q4_input = G2PointType::new(&mut dummy_assigner, "q4");
        q4_input.fill_with_data(crate::chunker::elements::DataType::G2PointData(q4));

        let witness = q4_input.to_witness().unwrap();

        println!(
            "{:?}, total_length: {}",
            witness.iter().map(|x| x.len()).collect::<Vec<usize>>(),
            witness.len()
        );

        let bc_secret = WinternitzSecret::new(20);
        let public_key = WinternitzPublicKey::from(&bc_secret);

        let times = 10;
        let witness = (0..times)
            .map(|_| {
                generate_winternitz_witness(&WinternitzSigningInputs {
                    message: &[0; 20],
                    signing_key: &bc_secret,
                })
                .to_vec()
            })
            .collect::<Vec<_>>()
            .concat();
        let script = script! {
            for _ in 0..times {
                { winternitz_message_checksig(&public_key) }
                for _ in 0..40 {
                    OP_DROP
                }
            }
        };

        println!(
            "witness size: {}, script size: {}",
            witness_size(&witness),
            script.len()
        );
        // witness size: 8830, script size: 30120

        let res = execute_script_with_inputs(script, witness);
        println!("res.max_stack {}", res.stats.max_nb_stack_items);
        // res.max_stack 889
    }
}
