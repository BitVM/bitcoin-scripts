use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{mmr_native::MMRInclusionProof, utils::hash_pair};

/// Represents the MMR for inside zkVM (guest)
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]

pub struct MMRGuest {
    pub subroots: Vec<[u8; 32]>,
    pub size: u32,
}

impl MMRGuest {
    /// Creates a new MMR for inside zkVM
    pub fn new() -> Self {
        MMRGuest {
            subroots: vec![],
            size: 0,
        }
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut current = leaf;
        let mut size = self.size;
        while size % 2 == 1 {
            let sibling = self.subroots.pop().unwrap();
            current = hash_pair(sibling, current);
            size /= 2
        }
        self.subroots.push(current);
        self.size += 1;
    }

    // fn get_helpers_from_index(&self, index: u32) -> (usize, usize, u32) {
    //     let xor = self.size ^ index;
    //     let xor_leading_digit = 31 - xor.leading_zeros() as usize;
    //     let internal_idx = index & ((1 << xor_leading_digit) - 1);

    //     let leading_zeros_size = 31 - self.size.leading_zeros() as usize;
    //     let mut tree_idx = 0;
    //     for i in xor_leading_digit + 1..=leading_zeros_size {
    //         if self.size & (1 << i) != 0 {
    //             tree_idx += 1;
    //         }
    //     }
    //     (tree_idx, xor_leading_digit, internal_idx)
    // }

    // pub fn get_root(&self) -> [u8; 32] {
    //     let mut preimage: Vec<u8> = vec![];
    //     for i in 0..self.subroots.len() {
    //         preimage.extend_from_slice(&self.subroots[i]);
    //     }
    //     calculate_sha256(&preimage)
    // }

    /// Verifies an inclusion proof against the current MMR root
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        println!("GUEST: mmr_proof: {:?}", mmr_proof);
        println!("GUEST: leaf: {:?}", leaf);
        // let (subroot_idx, subtree_size, internal_idx) = self.get_helpers_from_index(index);
        let mut current_hash = leaf;
        for i in 0..mmr_proof.inclusion_proof.len() {
            let sibling = mmr_proof.inclusion_proof[i];
            if mmr_proof.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        println!("GUEST: calculated subroot: {:?}", current_hash);
        println!("GUEST: subroots: {:?}", self.subroots);
        self.subroots[mmr_proof.subroot_idx] == current_hash
        // let mut preimage: Vec<u8> = vec![];
        // for i in 0..subroot_idx {
        //     preimage.extend_from_slice(&self.subroots[i]);
        // }
        // preimage.extend_from_slice(&current_hash);
        // for i in subroot_idx + 1..self.subroots.len() {
        //     preimage.extend_from_slice(&self.subroots[i]);
        // }
        // let calculated_root = calculate_sha256(&preimage);
        // calculated_root == self.get_root()
    }
}
