use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::utils::hash_pair;

/// Represents the MMR for outside zkVM (native).
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRNative {
    pub nodes: Vec<Vec<[u8; 32]>>,
}

impl MMRNative {
    /// Creates a new MMR for native usage.
    pub fn new() -> Self {
        MMRNative {
            nodes: vec![vec![]],
        }
    }

    /// Appends a new leaf to the MMR.
    pub fn append(&mut self, leaf: [u8; 32]) {
        self.nodes[0].push(leaf);
        self.recalculate_peaks();
    }

    /// Recalculates peaks based on the current leaves.
    fn recalculate_peaks(&mut self) {
        let depth = self.nodes.len();
        for level in 0..depth - 1 {
            if self.nodes[level].len() % 2 == 1 {
                break;
            } else {
                let node = hash_pair(
                    self.nodes[level][self.nodes[level].len() - 2],
                    self.nodes[level][self.nodes[level].len() - 1],
                );
                self.nodes[level + 1].push(node);
            }
        }
        if self.nodes[depth - 1].len() > 1 {
            let node = hash_pair(self.nodes[depth - 1][0], self.nodes[depth - 1][1]);
            self.nodes.push(vec![node]);
        }
    }

    /// Returns the subroots of the MMR.
    fn get_subroots(&self) -> Vec<[u8; 32]> {
        let mut subroots: Vec<[u8; 32]> = vec![];
        for level in &self.nodes {
            if level.len() % 2 == 1 {
                subroots.push(level[level.len() - 1]);
            }
        }
        subroots.reverse();
        subroots
    }

    /// Returns the root of the MMR.
    // pub fn get_root(&self) -> [u8; 32] {
    //     let mut preimage: Vec<u8> = vec![];
    //     let subroots = self.get_subroots();
    //     for i in 0..subroots.len() {
    //         preimage.extend_from_slice(&subroots[i]);
    //     }
    //     calculate_sha256(&preimage)
    // }

    /// Returns the subroot helpers for a given subroot. These are the subroots that are not the provided subroot.
    // fn get_subroot_helpers(&self, subroot: [u8; 32]) -> Vec<[u8; 32]> {
    //     let mut subroots: Vec<[u8; 32]> = vec![];
    //     for level in &self.nodes {
    //         if level.len() % 2 == 1 {
    //             if level[level.len() - 1] != subroot {
    //                 subroots.push(level[level.len() - 1]);
    //             }
    //         }
    //     }
    //     subroots
    // }

    /// Generates a proof for a given index. Returns the leaf as well.
    pub fn generate_proof(&self, index: u32) -> ([u8; 32], MMRInclusionProof) {
        if self.nodes[0].len() == 0 {
            panic!("MMR is empty");
        }
        if self.nodes[0].len() <= index as usize {
            panic!("Index out of bounds");
        }
        let mut proof: Vec<[u8; 32]> = vec![];
        let mut current_index = index;
        let mut current_level = 0;
        // Returns the subtree proof for the subroot.
        while !(current_index == self.nodes[current_level].len() as u32 - 1
            && self.nodes[current_level].len() % 2 == 1)
        {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            proof.push(self.nodes[current_level][sibling_index as usize]);
            current_index = current_index / 2;
            current_level += 1;
        }
        let (subroot_idx, internal_idx) = self.get_helpers_from_index(index);
        // let subroot = self.nodes[current_level][current_index as usize];
        // proof.extend(self.get_subroot_helpers(subroot));
        let mmr_proof = MMRInclusionProof::new(subroot_idx, internal_idx, proof);
        (self.nodes[0][index as usize], mmr_proof)
    }

    /// Given an index, returns the subroot index (which subtree the index is in), subtree size, and internal index (of the subtree that the index belongs to).
    fn get_helpers_from_index(&self, index: u32) -> (usize, u32) {
        let xor = (self.nodes[0].len() as u32) ^ index;
        let xor_leading_digit = 31 - xor.leading_zeros() as usize;
        let internal_idx = index & ((1 << xor_leading_digit) - 1);
        let leading_zeros_size = 31 - (self.nodes[0].len() as u32).leading_zeros() as usize;
        let mut subtree_idx = 0;
        for i in xor_leading_digit + 1..=leading_zeros_size {
            if self.nodes[0].len() & (1 << i) != 0 {
                subtree_idx += 1;
            }
        }
        // (tree_idx, xor_leading_digit, internal_idx)
        (subtree_idx, internal_idx)
    }

    /// Verifies an inclusion proof against the current MMR root.
    pub fn verify_proof(&self, leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool {
        println!("NATIVE: inclusion_proof: {:?}", mmr_proof);
        println!("NATIVE: leaf: {:?}", leaf);
        // let (subroot_idx, subtree_size, internal_idx) = self.get_helpers_from_index(index);
        let subroot = mmr_proof.get_subroot(leaf);
        println!("NATIVE: calculated_subroot: {:?}", subroot);
        let subroots = self.get_subroots();
        println!("NATIVE: subroots: {:?}", subroots);
        subroots[mmr_proof.subroot_idx] == subroot
        // let mut preimage: Vec<u8> = vec![];
        // for i in 0..subroot_idx {
        //     preimage.extend_from_slice(&subroots[i]);
        // }
        // preimage.extend_from_slice(&current_hash);
        // for i in subroot_idx + 1..subroots.len() {
        //     preimage.extend_from_slice(&subroots[i]);
        // }
        // let calculated_root = calculate_sha256(&preimage);
        // calculated_root == self.get_root()
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: usize,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<[u8; 32]>,
}

impl MMRInclusionProof {
    pub fn new(subroot_idx: usize, internal_idx: u32, inclusion_proof: Vec<[u8; 32]>) -> Self {
        MMRInclusionProof {
            subroot_idx,
            internal_idx,
            inclusion_proof,
        }
    }

    pub fn get_subroot(&self, leaf: [u8; 32]) -> [u8; 32] {
        // let (subroot_idx, subtree_size, internal_idx) = mmr_guest.get_helpers_from_index(index);
        let mut current_hash = leaf;
        for i in 0..self.inclusion_proof.len() {
            let sibling = self.inclusion_proof[i];
            if self.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        current_hash
    }
}

mod tests {

    use crate::mmr_guest::MMRGuest;

    use super::*;

    #[test]
    #[should_panic(expected = "MMR is empty")]
    fn test_mmr_native_fail_0() {
        let mmr = MMRNative::new();
        // let root = mmr.get_root();
        // let (leaf, proof, index) = mmr.generate_proof(0);
        let (_leaf, _mmr_proof) = mmr.generate_proof(0);
        // assert_eq!(mmr.get_root(), root);
        // assert_eq!(mmr.verify_proof(leaf, &proof, index), true);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_mmr_native_fail_1() {
        let mut mmr = MMRNative::new();
        mmr.append([0; 32]);
        // let root = mmr.get_root();
        // let (leaf, proof, index) = mmr.generate_proof(1);
        let (_leaf, _mmr_proof) = mmr.generate_proof(1);
        // assert_eq!(mmr.get_root(), root);
        // assert_eq!(mmr.verify_proof(leaf, &proof, index), true);
    }

    #[test]
    fn test_mmr_native() {
        let mut mmr = MMRNative::new();
        let mut leaves = vec![];

        for i in 0..42 {
            let leaf = [i as u8; 32];
            leaves.push(leaf);

            mmr.append(leaf);

            for j in 0..=i {
                let (leaf, mmr_proof) = mmr.generate_proof(j);
                assert!(mmr.verify_proof(leaf, &mmr_proof));
            }
        }
    }

    #[test]
    fn test_mmr_crosscheck() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();
        let mut leaves = vec![];

        for i in 0..42 {
            let leaf = [i as u8; 32];
            leaves.push(leaf);

            mmr_native.append(leaf);
            mmr_guest.append(leaf);

            let subroots_native = mmr_native.get_subroots();
            let subroots_guest = mmr_guest.subroots.clone();
            assert_eq!(
                subroots_native, subroots_guest,
                "Subroots do not match after adding leaf {}",
                i
            );

            // let root_native = mmr_native.get_root();
            // let root_guest = mmr_guest.get_root();
            // assert_eq!(
            //     root_native, root_guest,
            //     "Roots do not match after adding leaf {}",
            //     i
            // );

            for j in 0..=i {
                let (leaf, mmr_proof) = mmr_native.generate_proof(j);
                assert!(
                    mmr_native.verify_proof(leaf, &mmr_proof),
                    "Failed to verify proof for leaf {} in native MMR",
                    j
                );
                assert!(
                    mmr_guest.verify_proof(leaf, &mmr_proof),
                    "Failed to verify proof for leaf {} in guest MMR",
                    j
                );
            }
        }
    }
}
