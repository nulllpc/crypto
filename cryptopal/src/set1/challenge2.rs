//! Cryptopals Set 1, Challenge 2: Fixed XOR
//!
//! # Overall Strategy
//! 1. **Fail Fast**: Instantly panic if the input hex strings are not of equal length.
//! 2. **Decode & XOR**: Convert both hex strings to raw byte arrays. Iterate through 
//!    them simultaneously using `.zip()` and combine them with the bitwise XOR (`^`) operator.
//! 3. **Encode to Hex**: Split each resulting byte into two 4-bit nibbles (using `>> 4` and `& 0x0F`). 
//!    Convert each nibble back into a hex character using a branchless mathematical offset.
//!
//! # Core Cypherpunk Lessons Learned
//! 1. **Branchless Programming**: High-level branching (`if/else`, `match`) forces the CPU 
//!    to guess paths, leaking execution time variations that attackers can measure (Timing Attacks). 
//!    By using pure math and boolean casting (e.g., `is_letter * 87`), we execute a flat, 
//!    constant-time operation that leaks absolutely nothing.
//! 2. **Predictable Memory Allocation**: Using `String::with_capacity` isn't just for 
//!    performance. Dynamic memory allocation causes massive execution time spikes. 
//!    Pre-allocating exact capacities ensures a flat execution profile, closing another 
//!    potential side-channel.
//! 3. **Fail Fast**: Validating constraints (like `len() != len()`) at the very beginning 
//!    of a function prevents wasted CPU cycles and unpredictable state changes deeper in the stack.

use crate::set1::challenge1::hex_to_bytes;

pub fn fixed_xor(hex1: &str, hex2: &str) -> String {
    if hex1.len() != hex2.len() {
        panic!("Input strings must be of equal length");
    }
    
    let bytes_1 = hex_to_bytes(hex1);
    let bytes_2 = hex_to_bytes(hex2);

    let mut xor_bytes = Vec::new();

    for (byte_from_1, byte_from_2) in bytes_1.iter().zip(bytes_2.iter()) {
        xor_bytes.push(byte_from_1 ^ byte_from_2);
    }

    bytes_to_hex(&xor_bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter() {
        let high_nibble = byte >> 4;
        let low_nibble = byte & 0x0F;

        hex_str.push(u8_to_hex_char(high_nibble));
        hex_str.push(u8_to_hex_char(low_nibble));
    }
    
    hex_str
}

pub fn u8_to_hex_char(byte: u8) -> char {
    let is_letter = (byte >= 10) as u8;

    let offset = (is_letter * 87) + ((1 - is_letter) * 48);

    (byte + offset) as char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cryptopals_fixed_xor() {
        let input1 = "1c0111001f010100061a024b53535009181c";
        let input2 = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";
        assert_eq!(fixed_xor(input1, input2), expected);
    }

    #[test]
    #[should_panic(expected = "Input strings must be of equal length")]
    fn test_fixed_xor_unequal_length() {
        fixed_xor("1a2b", "1a2b3c");
    }

    #[test]
    fn test_fixed_xor_self_annihilation() {
        // Cryptographic Property: A ^ A = 0
        assert_eq!(fixed_xor("deadbeef", "deadbeef"), "00000000");
    }

    #[test]
    fn test_fixed_xor_identity() {
        // Cryptographic Property: A ^ 0 = A
        assert_eq!(fixed_xor("deadbeef", "00000000"), "deadbeef");
    }

    // --- bytes_to_hex Tests ---

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x00, 0x0a, 0xff, 0x42];
        assert_eq!(bytes_to_hex(&bytes), "000aff42");
    }

    #[test]
    fn test_bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_u8_to_hex_char() {
        // Test lower bounds and boundary crossings
        assert_eq!(u8_to_hex_char(0), '0');
        assert_eq!(u8_to_hex_char(9), '9');
        assert_eq!(u8_to_hex_char(10), 'a');
        assert_eq!(u8_to_hex_char(15), 'f');
    }
}