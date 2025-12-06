use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rustpq::ml_kem::mlkem1024::{decapsulate, encapsulate, generate};

fn main() {
    let message = b"Hello World";
    println!(
        "Original message: {:?}",
        std::str::from_utf8(message).unwrap()
    );

    let (pk, sk) = generate(&mut OsRng);
    println!("\nGenerated ML-KEM-1024 keypair");
    println!("  Public key:  {} bytes", pk.as_bytes().len());
    println!("  Secret key:  {} bytes", sk.as_bytes().len());

    let (ct_kem, ss_sender) = encapsulate(&pk, &mut OsRng);
    println!("\nEncapsulated shared secret");
    println!("  KEM ciphertext: {} bytes", ct_kem.as_bytes().len());

    let cipher = Aes256Gcm::new_from_slice(ss_sender.as_bytes()).unwrap();
    let nonce = Nonce::from_slice(b"unique nonce");

    let ciphertext = cipher.encrypt(nonce, message.as_ref()).unwrap();
    println!("\nEncrypted with AES-256-GCM");
    println!("  Ciphertext: {} bytes", ciphertext.len());
    println!("  Ciphertext (hex): {}", hex::encode(&ciphertext));

    let ss_receiver = decapsulate(&sk, &ct_kem);
    println!("\nDecapsulated shared secret");

    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    println!("  Shared secrets match!");

    let cipher = Aes256Gcm::new_from_slice(ss_receiver.as_bytes()).unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

    println!(
        "\nDecrypted message: {:?}",
        std::str::from_utf8(&plaintext).unwrap()
    );
    assert_eq!(plaintext, message);
}
