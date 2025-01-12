use super::{
    super::{scripts::*, transactions::base::Input},
    base::*,
};
use crate::graphs::peg_out::CommitmentMessageId;
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Network, PublicKey, ScriptBuf, TxIn,
};
use bitcoin_script::script;
use bitvm::signatures::signing_winternitz::{
    winternitz_message_checksig_verify, WinternitzPublicKey,
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ConnectorE {
    pub network: Network,
    pub operator_public_key: PublicKey,
    pub commitment_public_keys: BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
}

impl ConnectorE {
    pub fn new(
        network: Network,
        operator_public_key: &PublicKey,
        commitment_public_keys: &BTreeMap<CommitmentMessageId, WinternitzPublicKey>,
    ) -> Self {
        ConnectorE {
            network,
            operator_public_key: *operator_public_key,
            commitment_public_keys: commitment_public_keys.clone(),
        }
    }
}

impl TaprootConnector for ConnectorE {
    fn generate_taproot_leaf_script(&self, leaf_index: u32) -> ScriptBuf {
        assert_eq!(leaf_index, 0, "Invalid leaf index");
        let mut script = script! {};
        for (message, pk) in self.commitment_public_keys.iter().rev() {
            match message {
                CommitmentMessageId::Groth16IntermediateValues((str, size)) => {
                    script = script.push_script(
                        script! {
                            {winternitz_message_checksig_verify(pk, *size)}
                            for _ in 0..*size {
                                OP_DROP
                            }
                            // it's must be exactly one on stack after execution
                            OP_TRUE
                        }
                        .compile(),
                    );
                }
                _ => {
                    panic!("connector e only reveal intermediate value of groth16")
                }
            }
        }
        script.compile()
    }

    fn generate_taproot_leaf_tx_in(&self, leaf_index: u32, input: &Input) -> TxIn {
        assert_eq!(leaf_index, 0, "Invalid leaf index");
        generate_default_tx_in(input)
    }

    fn generate_taproot_spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.generate_taproot_leaf_script(0))
            .expect("Unable to add leaf 0")
            .finalize(SECP256K1, self.operator_public_key.into())
            .expect("Unable to finalize taproot")
    }

    fn generate_taproot_address(&self) -> Address {
        Address::p2tr_tweaked(
            self.generate_taproot_spend_info().output_key(),
            self.network,
        )
    }
}
