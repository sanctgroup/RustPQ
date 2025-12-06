#!/usr/bin/env python3

Q = 8380417
ZETA = 1753
R = 2**32
N = 256

def bitrev8(x):
    """Bit-reverse an 8-bit integer."""
    result = 0
    for i in range(8):
        if x & (1 << i):
            result |= 1 << (7 - i)
    return result

def pow_mod(base, exp, mod):
    """Modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result

def to_montgomery(x):
    """Convert to Montgomery form: x * R mod q"""
    return (x * R) % Q

zetas = []
for i in range(256):
    br_idx = bitrev8(i)
    power = pow_mod(ZETA, br_idx, Q)
    mont_val = to_montgomery(power)
    zetas.append(mont_val)

print("pub const ZETAS: [i32; 256] = [")
for i in range(0, 256, 8):
    row = ", ".join(f"{zetas[j]:8}" for j in range(i, min(i + 8, 256)))
    print(f"    {row},")
print("];")

print(f"\nFirst few values:")
for i in range(16):
    print(f"zetas[{i:2}] = {zetas[i]:8} (bitrev({i:2}) = {bitrev8(i):3}, ζ^{bitrev8(i):3} mod q)")
