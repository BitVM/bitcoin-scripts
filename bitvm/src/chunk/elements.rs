use std::str::FromStr;

use crate::{bn254::utils::Hint, chunk::primitives::{extern_bigint_to_nibbles, extern_hash_nibbles, extern_nibbles_to_bigint}};
use ark_ff::Field;
use num_bigint::{BigInt, BigUint};
use std::fmt::Debug;

use super::primitives::{extern_hash_fps, extern_nibbles_to_limbs, HashBytes};

// /// FqElements are used in the chunker, representing muliple Fq.
// #[derive(Debug, Clone)]
// pub(crate) struct FqElement {
//     pub identity: String,
//     pub size: usize,
//     pub witness_data: Vec<Hint>,
//     pub data: Option<DataType>,
//     pub of_type: ElementType,
// }

// /// Achieve witness depth, `9` is the witness depth of `U254`
// impl FqElement {
//     fn witness_size(&self) -> usize {
//         self.size * 9
//     }
// }

#[derive(Debug, Clone, Copy)]
pub enum DataType {
    Fp6Data(ark_bn254::Fq6), 
    G2EvalData(ElemG2Eval),
    G1Data(ark_bn254::G1Affine),
    U256Data(ark_ff::BigInt<4>),
}

/// Helper macro to reduce repetitive code for `TryFrom<Element>`.
macro_rules! impl_try_from_element {
    ($t:ty, { $($variant:ident),+ }) => {
        impl TryFrom<DataType> for $t {
            type Error = String;

            fn try_from(value: DataType) -> Result<Self, Self::Error> {
                match value {
                    $(
                        DataType::$variant(v) => Ok(v),
                    )+
                    other => {
                        Err(format!("attempted: {:?} found: {:?}",
                        stringify!($t),
                        other,
                    ))},
                }
            }
        }
    };
}

impl_try_from_element!(ark_bn254::Fq6, { Fp6Data });
impl_try_from_element!(ark_ff::BigInt<4>, { U256Data });
impl_try_from_element!(ark_bn254::G1Affine, { G1Data });
impl_try_from_element!(ElemG2Eval, { G2EvalData });

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ElementType {
    Fp6,
    G2EvalPoint,
    G2EvalMul,
    G2Eval,
    FieldElem, // 1
    ScalarElem, // 1
    G1, // 2
}


impl ElementType {
    pub fn number_of_limbs_of_hashing_preimage(&self) -> usize {
        match self {
            ElementType::Fp6 => 6,
            ElementType::FieldElem => 0, // field element is not hashed
            ElementType::G1 => 2,
            ElementType::ScalarElem => 0,
            ElementType::G2EvalPoint => 4 + 1,
            ElementType::G2EvalMul => 14 + 1,
            ElementType::G2Eval => 14 + 4,
        }
    }
}

// Data Type to represent an Assertion data (i.e output State of a tapscript)
// For intermediate values, the type is always HashBytes
// For the input groth16 proof, the type includes BigInt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressedStateObject {
    Hash(HashBytes),
    U256(ark_ff::BigInt<4>)
}

impl CompressedStateObject {
    // helper function to represent State as hint
    // used in tests to check the validity of checksig_verify()
    #[cfg(test)]
    pub(crate) fn as_hint_type(self) -> Hint {
        match self {
            CompressedStateObject::Hash(h) => Hint::Hash(extern_nibbles_to_limbs(h)),
            CompressedStateObject::U256(f) => {
                let fuint: BigUint = f.into();
                let fint: BigInt = BigInt::from_biguint(num_bigint::Sign::Plus, fuint);
                Hint::U256(fint)
            }
        }
    }

    // Serialize StateObject to byte array so that it can be wots-signed
    pub(crate) fn serialize_to_byte_array(&self) -> Vec<u8> {
        fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
            let mut msg_bytes = Vec::with_capacity(digits.len() / 2);
        
            for nibble_pair in digits.chunks(2) {
                let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
                msg_bytes.push(byte);
            }
        
            msg_bytes
        }
        match self {
            CompressedStateObject::Hash(h) => {
                let bal: [u8; 32] = nib_to_byte_array(h).try_into().unwrap();
                let bal: [u8; 20] = bal[12..32].try_into().unwrap();
                bal.to_vec()
            }
            CompressedStateObject::U256(n) => {
                let n = extern_bigint_to_nibbles(*n);
                let bal: [u8; 32] = nib_to_byte_array(&n).try_into().unwrap();
                bal.to_vec()
            }
        }
    }

    // Deserialize wots-signed byte array to object
    pub(crate)  fn deserialize_from_byte_array(byte_array: Vec<u8>) -> Self {
        assert!(byte_array.len() == 20 || byte_array.len() == 32);
        fn byte_array_to_nib(bytes: &[u8]) -> Vec<u8> {
            let mut nibbles = Vec::with_capacity(bytes.len() * 2);
            for &b in bytes {
                let high = b >> 4;
                let low = b & 0x0F;
                nibbles.push(low);
                nibbles.push(high);
            }
            nibbles
        }
       if byte_array.len() == 20 {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; 40] = nib_arr.try_into().unwrap();
            let mut padded_nibs = [0u8; 64]; // initialize with zeros
            padded_nibs[24..64].copy_from_slice(&nib_arr[0..40]);
            CompressedStateObject::Hash(padded_nibs)
       } else {
            let nib_arr = byte_array_to_nib(&byte_array);
            let nib_arr: [u8; 64] = nib_arr.try_into().unwrap();
            let fint = extern_nibbles_to_bigint(nib_arr);
            CompressedStateObject::U256(fint)
       }
    }


}

impl DataType {
    // Blake3 Hash data types
    // For U256Data (which is a single BigInteger) we do not hash but return as is
    // BigInt are used to represent groth16 proof
    pub fn to_hash(self) -> CompressedStateObject {
        match self {
            DataType::G2EvalData(r) => {
                let hash_t = r.hash_t();
                let hash_le = r.hash_le();
                let hash = extern_hash_nibbles(vec![hash_t, hash_le]);
                CompressedStateObject::Hash(hash)
            },
            DataType::Fp6Data(r) => {
                let hash = extern_hash_fps(
                    r.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>(),
                );
                CompressedStateObject::Hash(hash)
            }
            DataType::U256Data(f) => {
                CompressedStateObject::U256(f)
            },
            DataType::G1Data(r) => {
                let hash = extern_hash_fps(vec![r.x, r.y]);
                CompressedStateObject::Hash(hash)
            }
        }
    }

    pub fn output_is_field_element(&self) -> bool {
        matches!(self, DataType::U256Data(_))
    }

    // hashing pre-image for the DataType
    pub(crate) fn to_witness(&self, elem_type: ElementType) -> Vec<Hint> {
        match (elem_type, self) {
            (ElementType::G2EvalPoint, DataType::G2EvalData(g)) => {
                as_hints_g2evalpointtype_g2evaldata(*g)
            },
            (ElementType::G2EvalMul, DataType::G2EvalData(g)) => {
                as_hints_g2evalmultype_g2evaldata(*g)
            },
            (ElementType::G2Eval, DataType::G2EvalData(g)) => {
                as_hints_g2evaltype_g2evaldata(*g)
            },
            (ElementType::Fp6, DataType::Fp6Data(r)) => {
                as_hints_fq6type_fq6data(*r)
            },
            (ElementType::G1, DataType::G1Data(r)) => {
                as_hints_g1type_g1data(*r)
            },
            (ElementType::FieldElem, DataType::U256Data(r)) => {
                as_hints_fieldelemtype_u256data(*r)
            },
            (ElementType::ScalarElem, DataType::U256Data(r)) => {
                as_hints_scalarelemtype_u256data(*r)
            }
            _ => {
                println!("Unhandled ElementType {:?} ", elem_type);
                panic!()
            }
        }
    }
}

// /// This trait defines the intermediate values
// pub(crate) trait ElementTrait: Debug {
//     /// Fill data by a specific value
//     fn fill_with_data(&mut self, x: DataType);
//     /// Convert the intermediate values to witness
//     fn to_witness(&self) -> Vec<Hint>;
//     /// Convert the intermediate values from witness.
//     /// If witness is none, return none.
//     fn to_data(&self) -> Option<DataType>;
//     /// Hash witness by blake3, return witness of Hash
//     fn to_hash(&self) -> CompressedStateObject;
//     /// Size of element by Fq
//     fn size(&self) -> usize;
//     /// Witness size of element by u32
//     fn witness_size(&self) -> usize;
//     /// Return the name of identity.
//     fn id(&self) -> &str;
//     /// Return the name of identity.
//     fn type_name(&self) -> &ElementType;
// }


// macro_rules! impl_element_trait {
//     ($element_type:ident, $element_type_name:ident, $data_type:ident, $size:expr, $as_hints:expr) => {
//         #[derive(Clone, Debug)]
//         pub struct $element_type(FqElement);

//         impl $element_type {
//             /// Create a new element by using bitcommitment assigner
//             pub fn new<F: BCAssigner>(assigner: &mut F, id: &str) -> Self {
//                 assigner.create_hash(id);
//                 Self {
//                     0: FqElement {
//                         identity: id.to_owned(),
//                         size: $size,
//                         witness_data: vec![],
//                         data: None,
//                         of_type: $element_type_name,
//                     },
//                 }
//             }

//             pub fn new_with_data(x: DataType) -> Self {
//                 let mut y = $element_type(
//                     FqElement {
//                         identity: "".to_owned(),
//                         size: $size,
//                         witness_data: vec![],
//                         data: Some(x),
//                         of_type: $element_type_name,
//                     }
//                 );
//                 y.fill_with_data(x);
//                 y
//             }

//             pub fn empty() -> Self {
//                 let y = $element_type(
//                     FqElement {
//                         identity: "".to_owned(),
//                         size: $size,
//                         witness_data: vec![],
//                         data: None,
//                         of_type: $element_type_name,
//                     }
//                 );
//                 y
//             }
//         }

//         /// impl element for Fq6
//         impl ElementTrait for $element_type {
//             fn fill_with_data(&mut self, x: DataType) {
//                 match x {
//                     DataType::$data_type(fq6_data) => {
//                         self.0.witness_data = $as_hints(fq6_data);
//                         self.0.data = Some(x)
//                     }
//                     _ => panic!("fill wrong data {:?}", x.type_id()),
//                 }
//             }

//             fn to_witness(&self) -> Vec<Hint> {
//                 self.0.witness_data.clone()
//             }

//             fn to_data(&self) -> Option<DataType> {
//                 self.0.data.clone()
//             }

//             fn to_hash(&self) -> CompressedStateObject {
//                 assert!(self.0.data.is_some());
//                 self.0.data.unwrap().to_hash()
//             }

//             fn size(&self) -> usize {
//                 self.0.size
//             }

//             fn witness_size(&self) -> usize {
//                 self.0.witness_size()
//             }

//             fn id(&self) -> &str {
//                 &self.0.identity
//             }

//             fn type_name(&self) -> &ElementType {
//                 &self.0.of_type
//             }
//         }
//     };
// }



// impl_element_trait!(Fp6Type, Fp6, Fp6Data, 6, as_hints_fq6type_fq6data);
// impl_element_trait!(G2EvalPointType, G2EvalPoint, G2EvalData, 4+1, as_hints_g2evalpointtype_g2evaldata);
// impl_element_trait!(G2EvalMulType, G2EvalMul, G2EvalData, 14+1, as_hints_g2evalmultype_g2evaldata);
// impl_element_trait!(G2EvalType, G2Eval, G2EvalData, 14+4, as_hints_g2evaltype_g2evaldata);
// impl_element_trait!(FieldElemType, FieldElem, U256Data, 1, as_hints_fieldelemtype_u256data);
// impl_element_trait!(ScalarElemType, ScalarElem, U256Data, 1, as_hints_scalarelemtype_u256data);
// impl_element_trait!(G1Type, G1, G1Data, 2, as_hints_g1type_g1data);



fn as_hints_fq6type_fq6data(elem: ark_bn254::Fq6) -> Vec<Hint> {
    let hints: Vec<Hint> = elem.to_base_prime_field_elements().map(Hint::Fq).collect();
    hints
}

fn as_hints_g2evalpointtype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let hints = vec![
        Hint::Fq(g.t.x.c0),
        Hint::Fq(g.t.x.c1),
        Hint::Fq(g.t.y.c0),
        Hint::Fq(g.t.y.c1),
        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
    ];
    hints
}

fn as_hints_g2evalmultype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let mut hints: Vec<Hint> = g.apb
        .iter()
        .flat_map(|pt| [pt.c0, pt.c1]) // each point gives two values
        .chain(g.ab.to_base_prime_field_elements())
        .chain(g.p2le.iter().flat_map(|pt| [pt.c0, pt.c1]))
        .chain(g.res_hint.to_base_prime_field_elements())
        .map(Hint::Fq)
        .collect();
    hints.push(Hint::Hash(extern_nibbles_to_limbs(g.hash_t())));
    hints
}

fn as_hints_g2evaltype_g2evaldata(g: ElemG2Eval) -> Vec<Hint> {
    let mut hints = vec![
        Hint::Fq(g.t.x.c0),
        Hint::Fq(g.t.x.c1),
        Hint::Fq(g.t.y.c0),
        Hint::Fq(g.t.y.c1),
        Hint::Hash(extern_nibbles_to_limbs(g.hash_le())),
    ];
    let and_hints: Vec<Hint> = g.apb
        .iter()
        .flat_map(|pt| [pt.c0, pt.c1]) // each point gives two values
        .chain(g.ab.to_base_prime_field_elements())
        .chain(g.p2le.iter().flat_map(|pt| [pt.c0, pt.c1]))
        .chain(g.res_hint.to_base_prime_field_elements())
        .map(Hint::Fq)
        .collect();
    hints.extend_from_slice(&and_hints);
    hints
}


fn as_hints_fieldelemtype_u256data(elem: ark_ff::BigInt<4>) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_scalarelemtype_u256data(elem: ark_ff::BigInt<4>) -> Vec<Hint> {
    let v: BigUint = elem.into();
    let v = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, v);
    let hints = vec![Hint::U256(v)];
    hints
}

fn as_hints_g1type_g1data(r: ark_bn254::G1Affine) -> Vec<Hint> {
    let hints = vec![Hint::Fq(r.x), Hint::Fq(r.y)];
    hints
}



#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ElemG2Eval {
    pub(crate) t: ark_bn254::G2Affine,
    pub(crate) p2le: [ark_bn254::Fq2;2],
    pub(crate) ab: ark_bn254::Fq6,
    pub(crate) apb: [ark_bn254::Fq2;2],
    pub(crate) res_hint: ark_bn254::Fq6,
    //g+f, fg, p2le
}

impl ElemG2Eval {
    pub(crate) fn hash_t(&self) -> HashBytes {
        extern_hash_fps(vec![self.t.x.c0, self.t.x.c1, self.t.y.c0, self.t.y.c1])
    }

    pub(crate) fn hash_le(&self) -> HashBytes {
        let mut le = vec![];
        le.extend_from_slice(&[self.apb[0].c0, self.apb[0].c1, self.apb[1].c0, self.apb[1].c1]);
        le.extend_from_slice(&self.ab.to_base_prime_field_elements().collect::<Vec<ark_bn254::Fq>>());
        le.extend_from_slice(&[self.p2le[0].c0, self.p2le[0].c1, self.p2le[1].c0, self.p2le[1].c1]);
        extern_hash_fps(le)
    }

    pub(crate) fn mock() -> Self {
        let q4xc0: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("18327300221956260726652878806040774028373651771658608258634994907375058801387").unwrap());
        let q4xc1: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("2791853351403597124265928925229664715548948431563105825401192338793643440152").unwrap());
        let q4yc0: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("9203020065248672543175273161372438565462224153828027408202959864555260432617").unwrap());
        let q4yc1: ark_bn254::Fq = ark_bn254::Fq::from(BigUint::from_str("21242559583226289516723159151189961292041850314492937202099045542257932723954").unwrap());
        let tx = ark_bn254::Fq2::new(q4xc0, q4xc1);
        let ty =  ark_bn254::Fq2::new(q4yc0, q4yc1);
        let t = ark_bn254::G2Affine::new(tx, ty);
        ElemG2Eval { t, p2le: [ark_bn254::Fq2::ONE; 2], apb:[ark_bn254::Fq2::ONE; 2], ab: ark_bn254::Fq6::ONE, res_hint: ark_bn254::Fq6::ONE }
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use bitcoin_script::script;
    use crate::{bn254::{fp254impl::Fp254Impl, fq::Fq}, chunk::{blake3compiled::hash_messages, elements::ElementType}, execute_script};


    #[test]
    fn test_hash_witness() {
        let mut prng = ChaCha20Rng::seed_from_u64(117);
        let fld = ark_bn254::Fq6::rand(&mut prng);
        let elem = super::DataType::Fp6Data(fld);

        let preim = elem.to_witness(ElementType::Fp6);
        let scr = script!(
            for p in preim {
                {p.push()}
            }
            {elem.to_hash().as_hint_type().push()}
            {Fq::toaltstack()}
            {hash_messages(vec![ElementType::Fp6])}
        );
        let res = execute_script(scr);
        assert!(!res.success && res.final_stack.len() == 1);
    }
}