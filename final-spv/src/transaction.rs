/// Code is taken from Citrea
/// https://github.com/chainwayxyz/citrea/blob/0acb887b1a766fac1a482a68c6d51ecf9661f538/crates/bitcoin-da/src/spec/transaction.rs
///
use core::ops::{Deref, DerefMut};

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::utils::calculate_double_sha256;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct CircuitTransaction(pub Transaction);

impl CircuitTransaction {
    pub fn from(transaction: Transaction) -> Self {
        Self(transaction)
    }

    pub fn inner(&self) -> &Transaction {
        &self.0
    }

    /// Returns the transaction id, in big-endian byte order. One must be careful when dealing with
    /// Bitcoin transaction ids, as they are little-endian in the Bitcoin protocol.
    pub fn txid(&self) -> [u8; 32] {
        let mut tx_bytes_vec = vec![];
        self.inner()
            .version
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .input
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .output
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        self.inner()
            .lock_time
            .consensus_encode(&mut tx_bytes_vec)
            .unwrap();
        calculate_double_sha256(&tx_bytes_vec)
    }
}

impl BorshSerialize for CircuitTransaction {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0.version.0, writer)?;
        BorshSerialize::serialize(&self.0.lock_time.to_consensus_u32(), writer)?;
        BorshSerialize::serialize(&self.0.input.len(), writer)?;
        for input in &self.0.input {
            serialize_txin(input, writer)?;
        }
        BorshSerialize::serialize(&self.0.output.len(), writer)?;
        for output in &self.0.output {
            serialize_txout(output, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for CircuitTransaction {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let version = Version(i32::deserialize_reader(reader)?);
        let lock_time = LockTime::from_consensus(u32::deserialize_reader(reader)?);
        let input_len = usize::deserialize_reader(reader)?;
        let mut input = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            input.push(deserialize_txin(reader)?);
        }
        let output_len = usize::deserialize_reader(reader)?;
        let mut output = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            output.push(deserialize_txout(reader)?);
        }

        let tx = Transaction {
            version,
            lock_time,
            input,
            output,
        };

        Ok(Self(tx))
    }
}

fn serialize_txin<W: borsh::io::Write>(txin: &TxIn, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txin.previous_output.txid.to_byte_array(), writer)?;
    BorshSerialize::serialize(&txin.previous_output.vout, writer)?;
    BorshSerialize::serialize(&txin.script_sig.as_bytes(), writer)?;
    BorshSerialize::serialize(&txin.sequence.0, writer)?;
    BorshSerialize::serialize(&txin.witness.to_vec(), writer)
}

fn deserialize_txin<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxIn> {
    let txid = bitcoin::Txid::from_byte_array(<[u8; 32]>::deserialize_reader(reader)?);
    let vout = u32::deserialize_reader(reader)?;
    let script_sig = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);
    let sequence = Sequence(u32::deserialize_reader(reader)?);
    let witness = Witness::from(Vec::<Vec<u8>>::deserialize_reader(reader)?);

    Ok(TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence,
        witness,
    })
}

fn serialize_txout<W: borsh::io::Write>(txout: &TxOut, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(&txout.value.to_sat(), writer)?;
    BorshSerialize::serialize(&txout.script_pubkey.as_bytes(), writer)
}

fn deserialize_txout<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<TxOut> {
    let value = Amount::from_sat(u64::deserialize_reader(reader)?);
    let script_pubkey = ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?);

    Ok(TxOut {
        value,
        script_pubkey,
    })
}

impl Deref for CircuitTransaction {
    type Target = Transaction;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CircuitTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Transaction> for CircuitTransaction {
    fn from(tx: Transaction) -> Self {
        Self(tx)
    }
}

impl Into<Transaction> for CircuitTransaction {
    fn into(self) -> Transaction {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txid_legacy() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000").unwrap()).unwrap());
        let mut txid = tx.txid();
        txid.reverse();
        assert_eq!(
            hex::encode(txid),
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
        );
    }

    #[test]
    fn test_txid_segwit() {
        let tx = CircuitTransaction(bitcoin::consensus::deserialize(&hex::decode("0100000000010142ec43062180882d239799f134f7d8e9d104f37d87643e35fda84c47e4fc67a00000000000ffffffff026734000000000000225120e86c9c8c6777f28af40ef0c4cbd8308d27b60c7adf4f668d2433113616ddaa33cf660000000000001976a9149893ea81967d770f07f9bf0f659e3bce155be99a88ac01418a3d2a2182154dfd083cf48bfcd9f7dfb9d09eb46515e0043cdf39b688e9e711a2ce47f0f535191368be52fd706d77eb82eacd293a6a881491cdadf99b1df4400100000000").unwrap()).unwrap());
        let mut txid = tx.txid();
        txid.reverse();
        assert_eq!(
            hex::encode(txid),
            "a6a150fcdbabaf26040f4dea78ff53d794da2807d8600ead4758b065c5339324"
        );
    }

    #[test]
    fn test_from_transaction() {
        let original_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        };

        let bridge_tx = CircuitTransaction::from(original_tx.clone());
        assert_eq!(bridge_tx.inner(), &original_tx);

        let bridge_tx2: CircuitTransaction = original_tx.clone().into();
        assert_eq!(bridge_tx2.inner(), &original_tx);
        assert_eq!(bridge_tx.txid(), bridge_tx2.txid());
        assert_eq!(bridge_tx.txid(), bridge_tx2.txid());
    }

    #[test]
    fn test_into_transaction() {
        let bridge_tx = CircuitTransaction(Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        });

        let original_tx: Transaction = bridge_tx.clone().into();
        assert_eq!(&original_tx, bridge_tx.inner());
        assert_eq!(original_tx.compute_txid().to_byte_array(), bridge_tx.txid());
    }

    #[test]
    fn test_borsh_serialization() {
        let original_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        };
        let bridge_tx = CircuitTransaction(original_tx);

        // Serialize
        let serialized = borsh::to_vec(&bridge_tx).unwrap();

        // Deserialize
        let deserialized: CircuitTransaction = borsh::from_slice(&serialized).unwrap();

        assert_eq!(bridge_tx, deserialized);
        assert_eq!(bridge_tx.txid(), deserialized.txid());
    }

    #[test]
    fn test_deref_traits() {
        let mut bridge_tx = CircuitTransaction(Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![],
            output: vec![],
        });

        assert_eq!(bridge_tx.version, Version(1));

        bridge_tx.version = Version(2);
        assert_eq!(bridge_tx.version, Version(2));
    }

    #[test]
    fn test_complex_transaction() {
        let script_sig = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        let script_pubkey = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);

        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0; 32]),
                    vout: 0,
                },
                script_sig: script_sig.clone(),
                sequence: Sequence(0xffffffff),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: script_pubkey.clone(),
            }],
        };

        let bridge_tx = CircuitTransaction(tx.clone());

        assert_eq!(bridge_tx.version, tx.version);
        assert_eq!(bridge_tx.lock_time, tx.lock_time);
        assert_eq!(bridge_tx.input.len(), 1);
        assert_eq!(bridge_tx.output.len(), 1);
        assert_eq!(bridge_tx.input[0].script_sig, script_sig);
        assert_eq!(bridge_tx.output[0].script_pubkey, script_pubkey);
        assert_eq!(bridge_tx.output[0].value, Amount::from_sat(50000));
        assert_eq!(bridge_tx.txid(), tx.compute_txid().to_byte_array());
    }
}
