use super::{common::*, elements::ElementTrait};
use crate::{bridge::transactions::signing_winternitz::{WinternitzPublicKey, WinternitzSecret}, signatures::{winternitz::PublicKey, winternitz_hash::{WINTERNITZ_HASH_PARAMETERS, WINTERNITZ_HASH_VERIFIER}}, treepp::*};
use std::{collections::BTreeMap, rc::Rc};

/// Implement `BCAssinger` to adapt with bridge.
pub trait BCAssigner: Default {
    /// check hash
    fn create_hash(&mut self, id: &str);
    /// return a element of
    fn winternitz_locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script;
    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness;
    /// output sciprt for all elements, used by assert transaction
    fn all_intermediate_scripts(&self) -> Vec<Vec<Script>>;
    /// output witness for all elements, used by assert transaction
    fn all_intermediate_witnesses(
        &self,
        elements: BTreeMap<String, Rc<Box<dyn ElementTrait>>>,
    ) -> Vec<Vec<RawWitness>>;
    /// recover hashes from witnesses
    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH>;
}

#[derive(Default)]
pub struct DummyAssigner {
    bc_map: BTreeMap<String, String>,
}

impl BCAssigner for DummyAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("varible name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), id.to_string());
    }

    fn winternitz_locking_script<T: ElementTrait + ?Sized>(&self, _: &Box<T>) -> Script {
        script! {}
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        element.to_hash_witness().unwrap()
    }

    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH> {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.bc_map.len());
        for ((id, _), idx) in self.bc_map.iter().zip(0..flat_witnesses.len()) {
            btree_map.insert(id.to_owned(), witness_to_array(flat_witnesses[idx].clone()));
        }
        btree_map
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
            .iter()
            .map(|(_, element)| self.get_witness(element))
            .collect()]
    }
}

#[derive(Default)]
pub struct OperatorAssigner {
    bc_map: BTreeMap<String, WinternitzSecret>,
}

#[derive(Default)]
//TODO: Fill in operator_public_keys from on chain txs or file store.
pub struct VerifierAssigner {
    bc_map: BTreeMap<String, WinternitzPublicKey>,
    // List of winternitz public keys the operator used in
    // their scripts in the order they are generated with at
    // segment creation time.
    operator_public_keys: Vec<PublicKey>, }

impl BCAssigner for OperatorAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        self.bc_map.insert(id.to_string(), WinternitzSecret::new_hash());
    }

    fn winternitz_locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
        let winternitz_public_key: WinternitzPublicKey = self.bc_map.get(element.id()).expect("Missing key.").into();
        WINTERNITZ_HASH_VERIFIER.checksig_verify(&winternitz_public_key.parameters, &winternitz_public_key.public_key)
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        element.to_hash_witness().unwrap()
    }

    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH> {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.bc_map.len());
        for ((id, _), idx) in self.bc_map.iter().zip(0..flat_witnesses.len()) {
            btree_map.insert(id.to_owned(), witness_to_array(flat_witnesses[idx].clone()));
        }
        btree_map
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
                println!("inconsistent key: {}", key)
            }
        }
        assert_eq!(elements.len(), self.bc_map.len());
        vec![elements
            .iter()
            .map(|(_, element)| self.get_witness(element))
            .collect()]
    }
}

impl BCAssigner for VerifierAssigner {
    fn create_hash(&mut self, id: &str) {
        if self.bc_map.contains_key(id) {
            panic!("variable name is repeated, check {}", id);
        }
        let winternitz_public_key = WinternitzPublicKey {
            public_key: self.operator_public_keys.pop().expect("No operator public key remaining"),
            parameters: WINTERNITZ_HASH_PARAMETERS.clone(),
        };

        self.bc_map.insert(id.to_string(), winternitz_public_key);
    }

    fn winternitz_locking_script<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> Script {
        let winternitz_public_key = self.bc_map.get(element.id()).expect("Missing key.");
        WINTERNITZ_HASH_VERIFIER.checksig_verify(&winternitz_public_key.parameters, &winternitz_public_key.public_key)
    }

    fn get_witness<T: ElementTrait + ?Sized>(&self, element: &Box<T>) -> RawWitness {
        element.to_hash_witness().unwrap()
    }

    fn recover_from_witness(
        &mut self,
        witnesses: Vec<Vec<RawWitness>>,
    ) -> BTreeMap<String, BLAKE3HASH> {
        let mut btree_map: BTreeMap<String, BLAKE3HASH> = Default::default();
        // flat the witnesses and recover to btreemap
        let flat_witnesses: Vec<RawWitness> = witnesses.into_iter().fold(vec![], |mut w, x| {
            w.extend(x);
            w
        });
        assert_eq!(flat_witnesses.len(), self.bc_map.len());
        for ((id, _), idx) in self.bc_map.iter().zip(0..flat_witnesses.len()) {
            btree_map.insert(id.to_owned(), witness_to_array(flat_witnesses[idx].clone()));
        }
        btree_map
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
                println!("inconsistent key: {}", key)
            }
        }
        assert_eq!(elements.len(), self.bc_map.len());
        vec![elements
            .iter()
            .map(|(_, element)| self.get_witness(element))
            .collect()]
    }
}
