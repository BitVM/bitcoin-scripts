use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::header_chain::BlockHeaderCircuitOutput;

use crate::spv::SPV;

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]

pub struct FinalCircuitInput {
    pub block_header_circuit_output: BlockHeaderCircuitOutput,
    pub spv: SPV,
}
