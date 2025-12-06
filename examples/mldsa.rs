use rand::rngs::OsRng;
use rustpq::ml_dsa::sign::mldsa44::{generate, sign, verify};

fn main() {
    println!("ML-DSA-44 Digital Signature Example\n");

    println!("[1] Generating keypair...");
    let (public_key, secret_key) = generate(&mut OsRng);
    println!("    Public key:  {} bytes", public_key.as_bytes().len());
    println!("    Secret key:  {} bytes", secret_key.as_bytes().len());

    let message = b"Hello World";
    let context = b"";

    println!(
        "\n[2] Signing message: {:?}",
        core::str::from_utf8(message).unwrap()
    );
    let signature = sign(&secret_key, message, context, &mut OsRng).expect("signing failed");
    println!("    Signature:   {} bytes", signature.as_bytes().len());

    println!("\n[3] Verifying signature...");
    match verify(&public_key, message, context, &signature) {
        Ok(()) => println!("    Verification: SUCCESS"),
        Err(e) => println!("    Verification: FAILED ({:?})", e),
    }

    println!("\n[4] Testing invalid signature detection...");
    let wrong_message = b"Tampered message!";
    match verify(&public_key, wrong_message, context, &signature) {
        Ok(()) => println!("    Should have failed!"),
        Err(_) => println!("    Correctly rejected tampered message"),
    }

    println!("\nDone!");
}
