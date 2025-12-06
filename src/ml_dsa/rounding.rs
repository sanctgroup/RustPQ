use crate::ml_dsa::params::{D, Q};

pub fn power2round(a: i32) -> (i32, i32) {
    let d = 1 << D;
    let mut a1 = (a + (d >> 1) - 1) >> D;
    let a0 = a - (a1 << D);
    a1 = a1 - ((Q - 1) / d) * ((d >> 1) - a0 >> 31);
    (a1, a0)
}

pub fn decompose<const GAMMA2: usize>(a: i32) -> (i32, i32) {
    let rp = crate::ml_dsa::reduce::freeze(a);
    let mut r1 = (rp + 127) >> 7;
    r1 = if GAMMA2 == (Q as usize - 1) / 32 {
        let tmp = (r1 * 1025 + (1 << 21)) >> 22;
        tmp & 15
    } else if GAMMA2 == (Q as usize - 1) / 88 {
        let tmp = (r1 * 11275 + (1 << 23)) >> 24;
        tmp ^ (((43 - tmp) >> 31) & tmp)
    } else {
        panic!("Invalid GAMMA2");
    };

    let mut r0 = rp - r1 * 2 * GAMMA2 as i32;
    r0 = r0 - ((((Q - 1) / 2 - r0) >> 31) & Q);

    (r1, r0)
}

pub fn highbits<const GAMMA2: usize>(a: i32) -> i32 {
    decompose::<GAMMA2>(a).0
}

pub fn lowbits<const GAMMA2: usize>(a: i32) -> i32 {
    decompose::<GAMMA2>(a).1
}

pub fn make_hint<const GAMMA2: usize>(a0: i32, a1: i32) -> bool {
    if a0 > GAMMA2 as i32 || a0 < -(GAMMA2 as i32) || (a0 == -(GAMMA2 as i32) && a1 != 0) {
        return true;
    }
    false
}

pub fn use_hint<const GAMMA2: usize>(a: i32, hint: bool) -> i32 {
    let (a1, a0) = decompose::<GAMMA2>(a);

    if !hint {
        return a1;
    }

    if GAMMA2 == (Q as usize - 1) / 32 {
        if a0 > 0 {
            return (a1 + 1) & 15;
        }
        return (a1 - 1) & 15;
    } else {
        if a0 > 0 {
            if a1 == 43 {
                return 0;
            }
            return a1 + 1;
        } else {
            if a1 == 0 {
                return 43;
            }
            return a1 - 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round() {
        let a = 1000;
        let (a1, a0) = power2round(a);
        assert_eq!(a, a1 * (1 << D) + a0);
    }

    #[test]
    fn test_decompose() {
        const GAMMA2: usize = (Q as usize - 1) / 88;
        let a = 1000;
        let (_, a0) = decompose::<GAMMA2>(a);
        assert!(a0.abs() <= GAMMA2 as i32);
    }

    #[test]
    fn test_make_use_hint() {
        const GAMMA2: usize = (Q as usize - 1) / 88;
        let a = 100000;
        let (a1, a0) = decompose::<GAMMA2>(a);
        let hint = make_hint::<GAMMA2>(a0, a1);
        let _recovered = use_hint::<GAMMA2>(a, hint);
    }
}
