//! Cryptopals Set 1, Challenge 1: Convert hex to base64
//! 
//! # Overall Strategy
//! 1. **Hex to Bytes**: Parse the incoming hex string into raw bytes. To avoid bulky lookup tables, 
//!    we use an O(1) ASCII math trick (e.g., subtracting `b'0'` or `b'a'`) to find the numeric value.
//! 2. **Bytes to Base64**: Group the raw bytes into 3-byte (24-bit) chunks. Bit-shift these 
//!    24 bits into four 6-bit values. Map each 6-bit value to the Base64 alphabet, padding 
//!    with `=` if the input bytes don't divide evenly by 3.
//!
//! # Core Cypherpunk Lessons Learned
//! 1. **Encodings are just repackaging**: Different encoding schemes are simply different ways 
//!    to pack the same bytes. Conversion boils down to extracting raw bytes and splitting 
//!    them again into another scheme.
//! 2. **Think in bits and bytes**: When programming from a high level, we think in objects. 
//!    In cryptography, we must think in raw bits and bytes to understand data flow.
//! 3. **Encoding is NOT Encryption**: Base64 and Hex obscure data to the human eye, but offer 
//!    zero cryptographic security. It's strictly for format compatibility.
//! 4. **Padding is where attackers live**: Math is perfect, but data has physical boundaries. 
//!    Edge cases and padding logic (like the `=` in Base64) are often the weakest links in an algorithm.
//! 5. **High-level abstractions leak info**: High-level operations (like standard string comparisons) 
//!    often fail-fast, leaking timing data. Controlling the raw bytes allows us to write secure, 
//!    constant-time code.

const BASE64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn hex_to_base64(hex_string: &str) -> String {
    let bytes = hex_to_bytes(hex_string);
    let mut b64_string = String::new();

    // Create the lookup table once, before the loop starts.
    let b64_chars: Vec<char> = BASE64_ALPHABET.chars().collect();

    for chunk in bytes.chunks(3) {
        // Make a 24-bit number from the 3-byte chunk
        let mut n: u32 = 0;
        n |= (chunk[0] as u32) << 16;
        if chunk.len() > 1 {
            n |= (chunk[1] as u32) << 8;
        }
        if chunk.len() > 2 {
            n |= chunk[2] as u32;
        }

        // Divide into four 6-bit values
        let b64_val1 = (n >> 18) & 0b111111;
        let b64_val2 = (n >> 12) & 0b111111;
        let b64_val3 = (n >> 6) & 0b111111;
        let b64_val4 = n & 0b111111;

        // Push characters directly to the final string
        b64_string.push(b64_chars[b64_val1 as usize]);
        b64_string.push(b64_chars[b64_val2 as usize]);

        if chunk.len() > 1 {
            b64_string.push(b64_chars[b64_val3 as usize]);
        } else {
            b64_string.push('=');
        }

        if chunk.len() > 2 {
            b64_string.push(b64_chars[b64_val4 as usize]);
        } else {
            b64_string.push('=');
        }
    }

    b64_string
}

pub fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    if !hex_string.len().is_multiple_of(2) {
        panic!("Hex string must have an even length");
    }

    let char_vec: Vec<char> = hex_string.chars().collect();
    let mut bytes = Vec::new();

    for chunk in char_vec.chunks(2) {
        // Combine the two 4-bit nibbles into a single 8-bit byte
        let high_nibble = hex_char_to_u8(chunk[0]);
        let low_nibble = hex_char_to_u8(chunk[1]);

        bytes.push((high_nibble << 4) | low_nibble);
    }

    bytes
}

pub fn hex_char_to_u8(c: char) -> u8 {
    // Hexadecimal is case-insensitive, so we normalize to lowercase.
    // This allows a single match arm ('a'..='f') to handle both 'A'-'F' and 'a'-'f'.
    match c.to_ascii_lowercase() {
        // For '0'-'9': ASCII values are contiguous. Subtracting b'0' (ASCII 48)
        // from the char's ASCII value directly yields its numerical value (e.g., '4' (52) - '0' (48) = 4).
        // The `lower_c @` syntax binds the matched value to the `lower_c` variable.
        lower_c @ '0'..='9' => lower_c as u8 - b'0',
        // For 'a'-'f': ASCII values are also contiguous. Subtracting b'a' (ASCII 97)
        // gives a 0-indexed value ('a'->0, 'b'->1, etc.). We then add 10 because
        // 'a' in hex represents decimal 10.
        // (e.g., 'c' (99) - 'a' (97) + 10 = 2 + 10 = 12).
        lower_c @ 'a'..='f' => lower_c as u8 - b'a' + 10,
        _ => panic!("Invalid hex char"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for hex_char_to_u8
    #[test]
    pub fn test_hex_char_to_u8_digits() {
        assert_eq!(hex_char_to_u8('0'), 0);
        assert_eq!(hex_char_to_u8('5'), 5);
        assert_eq!(hex_char_to_u8('9'), 9);
    }

    #[test]
    pub fn test_hex_char_to_u8_lowercase_letters() {
        assert_eq!(hex_char_to_u8('a'), 10);
        assert_eq!(hex_char_to_u8('c'), 12);
        assert_eq!(hex_char_to_u8('f'), 15);
    }

    #[test]
    pub fn test_hex_char_to_u8_uppercase_letters() {
        assert_eq!(hex_char_to_u8('A'), 10);
        assert_eq!(hex_char_to_u8('C'), 12);
        assert_eq!(hex_char_to_u8('F'), 15);
    }

    #[test]
    #[should_panic(expected = "Invalid hex char")]
    pub fn test_hex_char_to_u8_invalid_char() {
        hex_char_to_u8('g');
    }

    // Tests for hex_to_bytes
    #[test]
    pub fn test_hex_to_bytes_simple() {
        assert_eq!(hex_to_bytes("49"), vec![0x49]);
        assert_eq!(hex_to_bytes("4927"), vec![0x49, 0x27]);
        assert_eq!(hex_to_bytes("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    pub fn test_hex_to_bytes_empty() {
        assert_eq!(hex_to_bytes(""), vec![]);
    }

    #[test]
    #[should_panic(expected = "Hex string must have an even length")]
    pub fn test_hex_to_bytes_odd_length() {
        hex_to_bytes("4");
    }

    // Tests for hex_to_base64
    #[test]
    pub fn test_hex_to_base64_cryptopals_challenge1() {
        let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(hex_to_base64(hex_input), expected_b64);
    }

    #[test]
    pub fn test_hex_to_base64_padding_one_equals() {
        // 2 bytes of input should result in 3 B64 chars + one '='
        assert_eq!(hex_to_base64("4927"), "SSc=");
    }

    #[test]
    pub fn test_hex_to_base64_padding_two_equals() {
        // 1 byte of input should result in 2 B64 chars + two '=='
        assert_eq!(hex_to_base64("49"), "SQ==");
    }

    #[test]
    pub fn test_hex_to_base64_full_block() {
        // 3 bytes of input should result in 4 B64 chars with no padding
        assert_eq!(hex_to_base64("49276d"), "SSdt");
    }

    #[test]
    pub fn test_hex_to_base64_empty() {
        assert_eq!(hex_to_base64(""), "");
    }
}
