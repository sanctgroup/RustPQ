use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rustpq::ml_dsa::mldsa65::{
    generate as dsa_generate, sign, verify, PublicKey as DsaPublicKey, SecretKey as DsaSecretKey,
    Signature,
};
use rustpq::ml_kem_hybrid::x25519_mlkem768::{
    decapsulate, encapsulate, generate as kem_generate, Ciphertext, PublicKey as KemPublicKey,
    SecretKey as KemSecretKey,
};

struct Identity {
    kem_pk: KemPublicKey,
    kem_sk: KemSecretKey,
    dsa_pk: DsaPublicKey,
    dsa_sk: DsaSecretKey,
}

impl Identity {
    fn new() -> Self {
        let (kem_pk, kem_sk) = kem_generate(&mut OsRng);
        let (dsa_pk, dsa_sk) = dsa_generate(&mut OsRng);
        Self {
            kem_pk,
            kem_sk,
            dsa_pk,
            dsa_sk,
        }
    }
}

struct EncryptedMessage {
    kem_ciphertext: Ciphertext,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    signature: Signature,
}

fn send_message(
    sender: &Identity,
    recipient_kem_pk: &KemPublicKey,
    message: &[u8],
) -> EncryptedMessage {
    let (kem_ct, shared_secret) = encapsulate(recipient_kem_pk, &mut OsRng);
    let key = shared_secret.derive_key();

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key should be 32 bytes");

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message).expect("encryption failed");

    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&kem_ct.as_bytes());
    data_to_sign.extend_from_slice(&nonce_bytes);
    data_to_sign.extend_from_slice(&ciphertext);

    let signature =
        sign(&sender.dsa_sk, &data_to_sign, b"e2ee-message", &mut OsRng).expect("signing failed");

    EncryptedMessage {
        kem_ciphertext: kem_ct,
        nonce: nonce_bytes,
        ciphertext,
        signature,
    }
}

fn receive_message(
    recipient: &Identity,
    sender_dsa_pk: &DsaPublicKey,
    encrypted: &EncryptedMessage,
) -> Result<Vec<u8>, &'static str> {
    let mut data_to_verify = Vec::new();
    data_to_verify.extend_from_slice(&encrypted.kem_ciphertext.as_bytes());
    data_to_verify.extend_from_slice(&encrypted.nonce);
    data_to_verify.extend_from_slice(&encrypted.ciphertext);

    verify(
        sender_dsa_pk,
        &data_to_verify,
        b"e2ee-message",
        &encrypted.signature,
    )
    .map_err(|_| "signature verification failed")?;

    let shared_secret = decapsulate(&recipient.kem_sk, &encrypted.kem_ciphertext);
    let key = shared_secret.derive_key();

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key should be 32 bytes");
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| "decryption failed")?;

    Ok(plaintext)
}

fn main() {
    println!("=== Post-Quantum End-to-End Encryption Demo ===\n");

    println!("[Setup] Generating identities...\n");
    let alice = Identity::new();
    let bob = Identity::new();

    println!("Alice's keys:");
    println!(
        "  KEM public key:  {} bytes (X25519 + ML-KEM-768)",
        alice.kem_pk.as_bytes().len()
    );
    println!(
        "  DSA public key:  {} bytes (ML-DSA-65)",
        alice.dsa_pk.as_bytes().len()
    );

    println!("\nBob's keys:");
    println!(
        "  KEM public key:  {} bytes (X25519 + ML-KEM-768)",
        bob.kem_pk.as_bytes().len()
    );
    println!(
        "  DSA public key:  {} bytes (ML-DSA-65)",
        bob.dsa_pk.as_bytes().len()
    );

    let secret_message = b"Hello Bob! This message is encrypted with post-quantum cryptography.";

    println!("\n[Alice] Sending encrypted message to Bob...");
    println!(
        "  Original message: \"{}\"",
        String::from_utf8_lossy(secret_message)
    );

    let encrypted = send_message(&alice, &bob.kem_pk, secret_message);

    println!("\n[Encrypted Payload]");
    println!(
        "  KEM ciphertext:  {} bytes",
        encrypted.kem_ciphertext.as_bytes().len()
    );
    println!("  Nonce:           {} bytes", encrypted.nonce.len());
    println!("  Ciphertext:      {} bytes", encrypted.ciphertext.len());
    println!(
        "  Signature:       {} bytes",
        encrypted.signature.as_bytes().len()
    );
    println!(
        "  Total:           {} bytes",
        encrypted.kem_ciphertext.as_bytes().len()
            + encrypted.nonce.len()
            + encrypted.ciphertext.len()
            + encrypted.signature.as_bytes().len()
    );

    println!("\n[Bob] Receiving message from Alice...");

    match receive_message(&bob, &alice.dsa_pk, &encrypted) {
        Ok(plaintext) => {
            println!("  Signature verified: Alice is authenticated");
            println!(
                "  Decrypted message: \"{}\"",
                String::from_utf8_lossy(&plaintext)
            );
        }
        Err(e) => {
            println!("  ERROR: {}", e);
        }
    }

    println!("\n[Security Test] Eve tries to read the message...");
    let eve = Identity::new();
    match receive_message(&eve, &alice.dsa_pk, &encrypted) {
        Ok(_) => println!("  ERROR: Eve decrypted the message!"),
        Err(e) => println!("  Blocked: {} (Eve doesn't have Bob's secret key)", e),
    }

    println!("\n[Security Test] Mallory tries to forge a message...");
    let mallory = Identity::new();
    let forged = send_message(&mallory, &bob.kem_pk, b"Fake message from Alice");
    match receive_message(&bob, &alice.dsa_pk, &forged) {
        Ok(_) => println!("  ERROR: Forged message accepted!"),
        Err(e) => println!("  Blocked: {} (Mallory can't sign as Alice)", e),
    }

    println!("\n=== Demo Complete ===");
    println!("\nThis example demonstrates:");
    println!("  - Hybrid KEM (X25519 + ML-KEM-768) for key encapsulation");
    println!("  - ChaCha20-Poly1305 for authenticated encryption");
    println!("  - ML-DSA-65 for message authentication");
    println!("  - Defense against eavesdropping (Eve) and forgery (Mallory)");
}
