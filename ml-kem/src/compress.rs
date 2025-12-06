use crate::params::Q32;

#[inline]
pub fn compress<const D: usize>(x: i16) -> u16 {
    let mut u = x as i32;
    u += (u >> 15) & Q32;
    ((((u << D) + Q32 / 2) / Q32) & ((1 << D) - 1)) as u16
}

#[inline]
pub fn decompress<const D: usize>(x: u16) -> i16 {
    (((x as i32 * Q32) + (1 << (D - 1))) >> D) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Q;

    #[test]
    fn test_compress_decompress_roundtrip() {
        for x in 0..Q {
            let c = compress::<10>(x);
            let d = decompress::<10>(c);
            let abs_diff = (x as i32 - d as i32).abs();
            let mod_diff = abs_diff.min(Q32 - abs_diff);
            assert!(
                mod_diff <= Q32 / (1 << 10) + 1,
                "diff too large for {}: {}",
                x,
                mod_diff
            );
        }
    }

    #[test]
    fn test_compress_range() {
        for x in 0..Q {
            let c4 = compress::<4>(x);
            let c10 = compress::<10>(x);
            let c11 = compress::<11>(x);
            assert!(c4 < 16);
            assert!(c10 < 1024);
            assert!(c11 < 2048);
        }
    }
}
