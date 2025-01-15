use crate::{merkle_tree::BlockInclusionProof, transaction::CircuitTransaction};
use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::{
    header_chain::CircuitBlockHeader, mmr_guest::MMRGuest, mmr_native::MMRInclusionProof,
};

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct SPV {
    pub transaction: CircuitTransaction,
    pub block_inclusion_proof: BlockInclusionProof,
    pub block_header: CircuitBlockHeader,
    pub mmr_inclusion_proof: MMRInclusionProof,
}

impl SPV {
    pub fn new(
        transaction: CircuitTransaction,
        block_inclusion_proof: BlockInclusionProof,
        block_header: CircuitBlockHeader,
        mmr_inclusion_proof: MMRInclusionProof,
    ) -> Self {
        SPV {
            transaction,
            block_inclusion_proof,
            block_header,
            mmr_inclusion_proof,
        }
    }

    pub fn verify(&self, mmr_guest: MMRGuest) -> bool {
        let txid: [u8; 32] = self.transaction.txid();
        println!("txid: {:?}", txid);
        let block_merkle_root = self.block_inclusion_proof.get_root(txid);
        println!("block_merkle_root: {:?}", block_merkle_root);
        assert_eq!(block_merkle_root, self.block_header.merkle_root);
        let block_hash = self.block_header.compute_block_hash();
        mmr_guest.verify_proof(block_hash, &self.mmr_inclusion_proof)
    }
}

#[cfg(test)]
mod tests {
    use borsh::BorshDeserialize;
    use header_chain::{
        header_chain::CircuitBlockHeader, mmr_guest::MMRGuest, mmr_native::MMRNative,
    };
    use hex_literal::hex;

    use crate::{
        merkle_tree::{verify_merkle_proof, BitcoinMerkleTree, BlockInclusionProof},
        spv::SPV,
        transaction::CircuitTransaction,
    };

    // Mainnet block headers from 0 to 16
    const MAINNET_BLOCK_HEADERS: [[u8; 80]; 16] = [
        hex!("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"),
        hex!("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299"),
        hex!("010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61"),
        hex!("01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d"),
        hex!("010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9"),
        hex!("0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477"),
        hex!("01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97"),
        hex!("010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86"),
        hex!("010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666"),
        hex!("01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53"),
        hex!("010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565"),
        hex!("01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8"),
        hex!("010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c"),
        hex!("010000005e2b8043bd9f8db558c284e00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86"),
        hex!("0100000089304d4ba5542a22fb616d1ca019e94222ee45c1ad95a83120de515c00000000560164b8bad7675061aa0f43ced718884bdd8528cae07f24c58bb69592d8afe185d36649ffff001d29cbad24"),
        hex!("01000000378a6f6593e2f0251132d96616e837eb6999bca963f6675a0c7af180000000000d080260d107d269ccba9247cfc64c952f1d13514b49e9f1230b3a197a8b7450fa276849ffff001d38d8fb98"),
    ];

    // Mainnet block transactions from 0 to 16, one for each block.
    const MAINNET_BLOCK_TRANSACTIONS: [&[u8]; 16] = [
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010bffffffff0100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010effffffff0100f2052a0100000043410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aaac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d011affffffff0100f2052a01000000434104184f32b212815c6e522e66686324030ff7e5bf08efb21f8b00614fb7690e19131dd31304c54f37baa40db231c918106bb9fd43373e37ae31a0befc6ecaefb867ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0120ffffffff0100f2052a0100000043410456579536d150fbce94ee62b47db2ca43af0a730a0467ba55c79e2a7ec9ce4ad297e35cdbb8e42a4643a60eef7c9abee2f5822f86b1da242d9c2301c431facfd8ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0123ffffffff0100f2052a0100000043410408ce279174b34c077c7b2043e3f3d45a588b85ef4ca466740f848ead7fb498f0a795c982552fdfa41616a7c0333a269d62108588e260fd5a48ac8e4dbf49e2bcac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d012bffffffff0100f2052a01000000434104a59e64c774923d003fae7491b2a7f75d6b7aa3f35606a8ff1cf06cd3317d16a41aa16928b1df1f631f31f28c7da35d4edad3603adb2338c4d4dd268f31530555ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d012cffffffff0100f2052a01000000434104cc8d85f5e7933cb18f13b97d165e1189c1fb3e9c98b0dd5446b2a1989883ff9e740a8a75da99cc59a21016caf7a7afd3e4e9e7952983e18d1ff70529d62e0ba1ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0134ffffffff0100f2052a0100000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0136ffffffff0100f2052a01000000434104fcc2888ca91cf0103d8c5797c256bf976e81f280205d002d85b9b622ed1a6f820866c7b5fe12285cfa78c035355d752fc94a398b67597dc4fbb5b386816425ddac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d013bffffffff0100f2052a010000004341046cc86ddcd0860b7cef16cbaad7fe31fda1bf073c25cb833fa9e409e7f51e296f39b653a9c8040a2f967319ff37cf14b0991b86173462a2d5907cb6c5648b5b76ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010cffffffff0100f2052a0100000043410478ebe2c28660cd2fa1ba17cc04e58d6312679005a7cad1fd56a7b7f4630bd700bcdb84a888a43fe1a2738ea1f3d2301d02faef357e8a5c35a706e4ae0352a6adac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d013cffffffff0100f2052a01000000434104c5a68f5fa2192b215016c5dfb384399a39474165eea22603cd39780e653baad9106e36947a1ba3ad5d3789c5cead18a38a538a7d834a8a2b9f0ea946fb4e6f68ac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d013effffffff0100f2052a010000004341043e8ac6b8ea64e85928b6469f17db0096de0bcae7d09a4497413d9bba49c00ffdf9cb0ce07c404784928b3976f0beea42fe2691a8f0430bcb2b0daaf5aa02b30eac00000000"),
        &hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010affffffff0100f2052a01000000434104e0041b4b4d9b6feb7221803a35d997efada6e2b5d24f5fc7205f2ea6b62a1adc9983a7a7dab7e93ea791bed5928e7a32286fa4facadd16313b75b467aea77499ac00000000"),
    ];

    #[test]
    fn test_spv() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();
        let block_headers = MAINNET_BLOCK_HEADERS
            .iter()
            .map(|header| CircuitBlockHeader::try_from_slice(header).unwrap())
            .collect::<Vec<CircuitBlockHeader>>();
        let txs = MAINNET_BLOCK_TRANSACTIONS
            .iter()
            .map(|tx| {
                println!("{:?}", tx);
                CircuitTransaction(bitcoin::consensus::deserialize(*tx).unwrap())
            })
            .collect::<Vec<CircuitTransaction>>();
        let mut bitcoin_merkle_proofs: Vec<BlockInclusionProof> = vec![];
        for tx in txs.iter() {
            let txid = tx.txid();
            println!("txid: {:?}", txid);
            let bitcoin_merkle_tree = BitcoinMerkleTree::new(vec![txid]);
            let bitcoin_merkle_proof = bitcoin_merkle_tree.generate_proof(0);
            assert!(verify_merkle_proof(
                txid,
                &bitcoin_merkle_proof,
                bitcoin_merkle_tree.root()
            ));
            bitcoin_merkle_proofs.push(bitcoin_merkle_proof);
        }
        for (i, header) in block_headers.iter().enumerate() {
            mmr_native.append(header.compute_block_hash());
            mmr_guest.append(header.compute_block_hash());
            for j in 0..i {
                let (mmr_leaf, mmr_proof) = mmr_native.generate_proof(j as u32);
                assert!(mmr_native.verify_proof(mmr_leaf, &mmr_proof));
                assert_eq!(mmr_leaf, block_headers[j].compute_block_hash());
                let spv = SPV::new(
                    txs[j].clone(),
                    bitcoin_merkle_proofs[j].clone(),
                    block_headers[j].clone(),
                    mmr_proof,
                );
                assert!(spv.verify(mmr_guest.clone()));
            }
        }
    }
}
