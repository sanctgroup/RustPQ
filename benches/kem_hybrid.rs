use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use std::hint::black_box;

#[cfg(feature = "x25519-mlkem768")]
fn bench_x25519_mlkem768(c: &mut Criterion) {
    use rustpq::ml_kem_hybrid::x25519_mlkem768::*;

    let mut group = c.benchmark_group("x25519_mlkem768");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    let ss = decapsulate(&sk, &ct);

    group.bench_function("derive_key", |b| b.iter(|| black_box(&ss).derive_key()));

    group.finish();
}

#[cfg(feature = "p256-mlkem768")]
fn bench_p256_mlkem768(c: &mut Criterion) {
    use rustpq::ml_kem_hybrid::p256_mlkem768::*;

    let mut group = c.benchmark_group("p256_mlkem768");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    let ss = decapsulate(&sk, &ct);

    group.bench_function("derive_key", |b| b.iter(|| black_box(&ss).derive_key()));

    group.finish();
}

#[cfg(feature = "p384-mlkem1024")]
fn bench_p384_mlkem1024(c: &mut Criterion) {
    use rustpq::ml_kem_hybrid::p384_mlkem1024::*;

    let mut group = c.benchmark_group("p384_mlkem1024");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    let ss = decapsulate(&sk, &ct);

    group.bench_function("derive_key", |b| b.iter(|| black_box(&ss).derive_key()));

    group.finish();
}

#[cfg(feature = "x25519-mlkem768")]
criterion_group!(bench_x25519, bench_x25519_mlkem768);

#[cfg(feature = "p256-mlkem768")]
criterion_group!(bench_p256, bench_p256_mlkem768);

#[cfg(feature = "p384-mlkem1024")]
criterion_group!(bench_p384, bench_p384_mlkem1024);

#[cfg(all(
    feature = "x25519-mlkem768",
    feature = "p256-mlkem768",
    feature = "p384-mlkem1024"
))]
criterion_main!(bench_x25519, bench_p256, bench_p384);

#[cfg(all(
    feature = "x25519-mlkem768",
    feature = "p256-mlkem768",
    not(feature = "p384-mlkem1024")
))]
criterion_main!(bench_x25519, bench_p256);

#[cfg(all(
    feature = "x25519-mlkem768",
    not(feature = "p256-mlkem768"),
    not(feature = "p384-mlkem1024")
))]
criterion_main!(bench_x25519);
