use crate::bn254::g2_subgroup_check::ScriptContext;
use ark_bn254::Fq;
use arrayref::array_ref;
use bitcoin::hex::DisplayHex;
use blake3::platform::Platform;
use blake3::Hash;

const CHUNK_LEN: u32 = 1024;
const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;
const BLOCK_LEN: usize = 64;

// While iterating the compression function within a chunk, the CV is
// represented as words, to avoid doing two extra endianness conversions for
// each compression in the portable implementation. But the hash_many interface
// needs to hash both input bytes and parent nodes, so its better for its
// output CVs to be represented as bytes.
type CVWords = [u32; 8];
type CVBytes = [u8; 32]; // little-endian

const IV: &CVWords = &[
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// Hash a complete input all at once. Unlike compress_subtree_wide() and
// compress_subtree_to_parent_node(), this function handles the 1 chunk case.
pub fn blake3_1chunk(
    input: &[u8],
    script_input: &[u8],
) -> (Hash, Vec<ScriptContext<ark_bn254::Fq>>) {
    let platform = Platform::detect();

    // If the whole subtree is one chunk, hash it directly with a ChunkState.
    return ChunkState::new(IV, 0, 0, platform).update(input, script_input);
}

struct ChunkState {
    cv: CVWords,
    chunk_counter: u64,
    blocks_compressed: u8,
    flags: u8,
    platform: Platform,
}

impl ChunkState {
    fn new(key: &CVWords, chunk_counter: u64, flags: u8, platform: Platform) -> Self {
        Self {
            cv: *key,
            chunk_counter,
            blocks_compressed: 0,
            flags,
            platform,
        }
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    // Try to avoid buffering as much as possible, by compressing directly from
    // the input slice when full blocks are available.
    fn update(
        &mut self,
        mut input: &[u8],
        mut script_input: &[u8],
    ) -> (Hash, Vec<ScriptContext<ark_bn254::Fq>>) {
        let mut script_contexts = vec![];

        while input.len() > BLOCK_LEN {
            let mut add_context = ScriptContext::default();

            // store input
            let script_input_len = script_input.len();

            println!("script_input_len = {:?}", script_input_len);

            for i in 0..64 {
                add_context
                    .auxiliary
                    .push(script_input[script_input_len - 64 + i] as usize);
            }

            if self.blocks_compressed == 0 {
                for i in 0..8 {
                    let a = IV[7 - i].to_le_bytes();
                    add_context.auxiliary.push(a[3] as usize);
                    add_context.auxiliary.push(a[2] as usize);
                    add_context.auxiliary.push(a[1] as usize);
                    add_context.auxiliary.push(a[0] as usize);
                }
            } else {
                for i in 0..8 {
                    let a = self.cv[7 - i].to_le_bytes();
                    add_context.auxiliary.push(a[3] as usize);
                    add_context.auxiliary.push(a[2] as usize);
                    add_context.auxiliary.push(a[1] as usize);
                    add_context.auxiliary.push(a[0] as usize);
                }
            }

            let block_flags = self.flags | self.start_flag(); // borrowck
            self.platform.compress_in_place(
                &mut self.cv,
                array_ref!(input, 0, BLOCK_LEN),
                BLOCK_LEN as u8,
                self.chunk_counter,
                block_flags,
            );

            // store output
            let hash: Hash = blake3::Hash::from(blake3::platform::le_bytes_from_words_32(&self.cv));

            let hex: String = hash
                .to_string()
                .chars()
                .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
                .collect();

            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>();

            for i in 0..32 {
                add_context.auxiliary_output.push(bytes[31 - i] as usize);
            }
            script_contexts.push(add_context);

            self.blocks_compressed += 1;
            input = &input[BLOCK_LEN..];
            script_input = &script_input[..(script_input_len - BLOCK_LEN)];
        }

        let mut add_context = ScriptContext::default();

        // store input
        assert_eq!(script_input.len(), BLOCK_LEN);
        assert_eq!(input.len(), BLOCK_LEN);

        for i in 0..64 {
            add_context.auxiliary.push(script_input[i] as usize);
        }

        if self.blocks_compressed == 0 {
            for i in 0..8 {
                //add_context.auxiliary.push(IV[ 7 - i] as usize);
                let a = IV[7 - i].to_le_bytes();
                add_context.auxiliary.push(a[3] as usize);
                add_context.auxiliary.push(a[2] as usize);
                add_context.auxiliary.push(a[1] as usize);
                add_context.auxiliary.push(a[0] as usize);
            }
        } else {
            for i in 0..8 {
                let a = self.cv[7 - i].to_le_bytes();
                add_context.auxiliary.push(a[3] as usize);
                add_context.auxiliary.push(a[2] as usize);
                add_context.auxiliary.push(a[1] as usize);
                add_context.auxiliary.push(a[0] as usize);
            }
        }

        let block_flags = self.flags | self.start_flag() | CHUNK_END;

        self.platform.compress_in_place(
            &mut self.cv,
            array_ref!(input, 0, BLOCK_LEN),
            BLOCK_LEN as u8,
            0,
            block_flags | ROOT,
        );

        let hash: Hash = blake3::Hash::from(blake3::platform::le_bytes_from_words_32(&self.cv));

        let hex: String = hash
            .to_string()
            .chars()
            .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
            .collect();

        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();

        // store output
        for i in 0..32 {
            add_context.auxiliary_output.push(bytes[31 - i] as usize);
        }
        script_contexts.push(add_context);

        (hash, script_contexts)
    }
}

#[cfg(test)]
mod tests {

    use crate::hash::blake3_u32_split::blake3_native;

    #[test]
    fn test_generate_blake3_exptect_output() {
        let mut input = vec![];

        for i in 0..32 {
            input.push(1);
            input.push(0);
            input.push(0);
            input.push(0);
        }

        let output = blake3::hash(&input);

        let expect_str = output.to_string();

        println!("output_str: {:?} \n", expect_str);

        let inputs = (0..32_u32)
            .into_iter()
            .flat_map(|i| 1_u32.to_le_bytes())
            .collect::<Vec<_>>();

        //let output = blake3::hash(&inputs);

        let (actual_str, _) = blake3_native::blake3_1chunk(&inputs, &input);

        println!("output_str: {:?} \n", actual_str.to_string());

        assert_eq!(expect_str, actual_str.to_string());
    }
}
