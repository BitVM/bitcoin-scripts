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

    /// Verifies an inclusion proof against the current MMR root
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        println!("GUEST: mmr_proof: {:?}", mmr_proof);
        println!("GUEST: leaf: {:?}", leaf);
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
    }
}
