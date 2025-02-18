use crate::treepp::*;

/// Calculates ceil(log_base(n))
pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 { 
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

/// Converts the number to given base, smallest digit being at the start (returns `digit_count` smallest digits of it, and standard base representation of it if `digit_count` = -1)
pub(super) fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }   
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    digits
}

/// Converts the given bytes to 'len' `u32`'s, each consisting of given number of bits
pub(crate) fn bytes_to_u32s(len: u32, bits_per_item: u32, bytes: &Vec<u8>) -> Vec<u32> {
    assert!(bytes.len() as u32 * 8 <= len * bits_per_item, "Message length is too large for the given length"); 
    let mut res = vec![0u32; len as usize];
    let mut cur_index: u32 = 0;
    let mut cur_bit: u32 = 0;
    for byte in bytes {
        let mut x: u8 = *byte;
        for _ in 0..8 {
            if cur_bit == bits_per_item {
                cur_bit = 0;
                cur_index += 1;
            }
            res[cur_index as usize] |= ((x & 1) as u32) << cur_bit;
            x >>= 1;
            cur_bit += 1;
        }
    }
    res
}

/// Merges (binary concatenates) the `DIGIT_COUNT` stack elements (each consisting of `LOG_D` bits), most significant one being at the top
pub fn digits_to_number<const DIGIT_COUNT: usize, const LOG_D: usize>() -> Script {
  script!(
      for _ in 0..DIGIT_COUNT - 1 {
        OP_TOALTSTACK
      }
      for _ in 0..DIGIT_COUNT - 1 {
          for _ in 0..LOG_D {
              OP_DUP OP_ADD
          }
          OP_FROMALTSTACK
          OP_ADD
      }
  )
}

/// Converts number to vector of bytes and removes trailing zeroes
pub fn u32_to_le_bytes_minimal(a: u32) -> Vec<u8> {
    let mut a_bytes = a.to_le_bytes().to_vec();
    while let Some(&0) = a_bytes.last() {
        a_bytes.pop(); // Remove trailing zeros
    }
    a_bytes
}

#[cfg(test)]
mod test {
    use super::u32_to_le_bytes_minimal;

    #[test]
    fn test_u32_to_bytes_minimal() {
        let a = 0xfe00u32;
        let a_bytes = u32_to_le_bytes_minimal(a);

        assert_eq!(a_bytes, vec![0x00u8, 0xfeu8]);
    }
}
