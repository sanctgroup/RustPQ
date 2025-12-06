use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub fn shake256_into(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

pub fn shake256_absorb_twice_into(a: &[u8], b: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(a);
    hasher.update(b);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

pub fn shake256_128(input: &[u8]) -> [u8; 16] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 16];
    reader.read(&mut output);
    output
}

pub fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);
    output
}

pub fn crh(out: &mut [u8; 64], input: &[u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_into() {
        let input = b"test";
        let mut output = [0u8; 32];
        shake256_into(input, &mut output);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_shake256_64() {
        let input = b"test";
        let output = shake256_64(input);
        assert_eq!(output.len(), 64);
    }
}
