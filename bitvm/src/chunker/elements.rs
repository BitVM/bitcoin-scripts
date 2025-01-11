use super::common::*;
use crate::bn254::fq::Fq;
use crate::bn254::fq12::Fq12;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fr::Fr;
use crate::bn254::{g1::G1Affine, g2::G2Affine};
use crate::treepp::*;
use crate::{chunker::assigner::BCAssigner, execute_script_with_inputs};
use std::any::Any;
use std::fmt::Debug;

/// FqElements are used in the chunker, representing muliple Fq.
#[derive(Debug, Clone)]
pub struct FqElement {
    pub identity: String,
    pub size: usize,
    pub witness_data: Option<RawWitness>,
    pub data: Option<DataType>,
}

/// Achieve witness depth, `9` is the witness depth of `U254`
impl FqElement {
    fn witness_size(&self) -> usize {
        self.size * 9
    }
}

/// Define all data types
#[derive(Debug, Clone)]
pub enum DataType {
    FqData(ark_bn254::Fq),
    FrData(ark_bn254::Fr),
    Fq2Data(ark_bn254::Fq2),
    Fq6Data(ark_bn254::Fq6),
    Fq12Data(ark_bn254::Fq12),
    G1PointData(ark_bn254::G1Affine),
    G2PointData(ark_bn254::G2Affine),
}

/// This trait defines the intermediate values
pub trait ElementTrait: Debug {
    /// Fill data by a specific value
    fn fill_with_data(&mut self, x: DataType);
    /// Convert the intermediate values to witness
    fn to_witness(&self) -> Option<RawWitness>;
    /// Convert the intermediate values from witness.
    /// If witness is none, return none.
    fn to_data(&self) -> Option<DataType>;
    /// Hash witness by blake3, return Hash
    fn to_hash(&self) -> Option<BLAKE3HASH>;
    /// Hash witness by blake3, return witness of Hash
    fn to_hash_witness(&self) -> Option<RawWitness>;
    /// Size of element by Fq
    fn size(&self) -> usize;
    /// Witness size of element by u32
    fn witness_size(&self) -> usize;
    /// Return the name of identity.
    fn id(&self) -> &str;
}

macro_rules! impl_element_trait {
    ($element_type:ident, $data_type:ident, $size:expr, $push_method:expr) => {
        #[derive(Clone, Debug)]
        pub struct $element_type(FqElement);

        impl $element_type {
            /// Create a new element by using bitcommitment assigner
            pub fn new<F: BCAssigner>(assigner: &mut F, id: &str) -> Self {
                assigner.create_hash(id);
                Self {
                    0: FqElement {
                        identity: id.to_owned(),
                        size: $size,
                        witness_data: None,
                        data: None,
                    },
                }
            }

            pub fn new_dummy(id: &str) -> Self {
                Self {
                    0: FqElement {
                        identity: id.to_owned(),
                        size: $size,
                        witness_data: None,
                        data: None,
                    },
                }
            }
        }

        /// impl element for Fq6
        impl ElementTrait for $element_type {
            fn fill_with_data(&mut self, x: DataType) {
                match x {
                    DataType::$data_type(fq6_data) => {
                        let res = execute_script(script! {
                            {$push_method(fq6_data)}
                        });
                        let witness = extract_witness_from_stack(res);
                        assert_eq!(witness.len(), self.0.witness_size());

                        self.0.witness_data = Some(witness);
                        self.0.data = Some(x)
                    }
                    _ => panic!("fill wrong data {:?}", x.type_id()),
                }
            }

            fn to_witness(&self) -> Option<RawWitness> {
                self.0.witness_data.clone()
            }

            fn to_data(&self) -> Option<DataType> {
                self.0.data.clone()
            }

            fn to_hash(&self) -> Option<BLAKE3HASH> {
                match self.0.witness_data.clone() {
                    None => None,
                    Some(witness) => {
                        let res = execute_script_with_inputs(
                            script! {
                                {blake3_var_length(self.0.witness_size())}
                            },
                            witness,
                        );
                        let hash = witness_to_array(extract_witness_from_stack(res));
                        Some(hash)
                    }
                }
            }

            fn to_hash_witness(&self) -> Option<RawWitness> {
                match self.0.witness_data.clone() {
                    None => None,
                    Some(witness) => {
                        let res = execute_script_with_inputs(
                            script! {
                                {blake3_var_length(self.0.witness_size())}
                            },
                            witness,
                        );
                        let witness = extract_witness_from_stack(res);
                        Some(witness)
                    }
                }
            }

            fn size(&self) -> usize {
                self.0.size
            }

            fn witness_size(&self) -> usize {
                self.0.witness_size()
            }

            fn id(&self) -> &str {
                &self.0.identity
            }
        }
    };
}

// (Fq)
impl_element_trait!(FqType, FqData, 1, Fq::push);
// (Fr)
impl_element_trait!(FrType, FrData, 1, Fr::push);
// (Fq2)
impl_element_trait!(Fq2Type, Fq2Data, 2, Fq2::push);
// (Fq6)
impl_element_trait!(Fq6Type, Fq6Data, 6, Fq6::push);
// (Fq12)
impl_element_trait!(Fq12Type, Fq12Data, 12, Fq12::push);
// (x: Fq, y: Fq)
impl_element_trait!(G1PointType, G1PointData, 2, G1Affine::push);
// (x: Fq, y: Fq2)
impl_element_trait!(G2PointType, G2PointData, 4, G2Affine::push);

#[derive(Debug, Clone)]
pub struct DummyElement {
    id: String,
    hash: BLAKE3HASH,
}

impl ElementTrait for DummyElement {
    fn fill_with_data(&mut self, _: DataType) {}

    fn to_witness(&self) -> Option<RawWitness> {
        None
    }

    fn to_data(&self) -> Option<DataType> {
        None
    }

    fn to_hash(&self) -> Option<BLAKE3HASH> {
        Some(self.hash)
    }

    fn to_hash_witness(&self) -> Option<RawWitness> {
        Some(array_to_witness(self.hash))
    }

    fn size(&self) -> usize {
        0
    }

    fn witness_size(&self) -> usize {
        0
    }

    fn id(&self) -> &str {
        &self.id
    }
}

pub fn dummy_element(id: &str, hash: BLAKE3HASH) -> DummyElement {
    DummyElement {
        id: id.to_owned(),
        hash,
    }
}
