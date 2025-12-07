use rand::rngs::OsRng;
use rustpq::ml_kem_hybrid::x25519_mlkem768::{
    decapsulate, encapsulate, generate, CIPHERTEXT_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES,
    SHARED_SECRET_BYTES,
};

fn main() {
    println!("=== X25519-ML-KEM-768 Hybrid KEM ===\n");
    println!("Security: NIST Level 3 (classical + post-quantum)\n");

    let (pk, sk) = generate(&mut OsRng);

    println!("Generated hybrid keypair:");
    println!("  Public key:  {} bytes", PUBLIC_KEY_BYTES);
    println!("  Secret key:  {} bytes", SECRET_KEY_BYTES);

    let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);

    println!("\nEncapsulated:");
    println!("  Ciphertext:  {} bytes", CIPHERTEXT_BYTES);
    println!(
        "  Raw secret:  {} bytes (concatenated)",
        SHARED_SECRET_BYTES
    );

    let ss_receiver = decapsulate(&sk, &ct);

    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    println!("\nShared secrets match!");

    println!("\n--- Raw Shared Secret (64 bytes) ---");
    println!(
        "ML-KEM component (32 bytes): {:02x?}",
        ss_sender.mlkem_shared_secret()
    );
    println!(
        "X25519 component (32 bytes): {:02x?}",
        ss_sender.x25519_shared_secret()
    );

    let derived_key = ss_sender.derive_key();
    println!("\n--- Derived Key (SHA3-256, 32 bytes) ---");
    println!("{:02x?}", derived_key);

    println!("\nUse derive_key() for a ready-to-use symmetric key.");
    println!("Use as_bytes() for protocol integration or custom KDF.");
}
