use rand::rngs::OsRng;
use rustpq::ml_kem::mlkem768::{decapsulate, encapsulate, generate};

fn main() {
    let (pk, sk) = generate(&mut OsRng);

    println!("Generated keypair");
    println!("  Public key:  {} bytes", pk.as_bytes().len());
    println!("  Secret key:  {} bytes", sk.as_bytes().len());

    let (ct, ss_sender) = encapsulate(&pk, &mut OsRng);

    println!("\nEncapsulated shared secret");
    println!("  Ciphertext:  {} bytes", ct.as_bytes().len());

    let ss_receiver = decapsulate(&sk, &ct);

    println!("\nDecapsulated shared secret");

    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
    println!("\nShared secrets match: {:?}", ss_sender.as_bytes());
}
