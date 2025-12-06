use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use std::hint::black_box;

fn bench_mlkem512(c: &mut Criterion) {
    use rustpq::ml_kem::mlkem512::*;

    let mut group = c.benchmark_group("mlkem512");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    group.finish();
}

fn bench_mlkem768(c: &mut Criterion) {
    use rustpq::ml_kem::mlkem768::*;

    let mut group = c.benchmark_group("mlkem768");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    group.finish();
}

fn bench_mlkem1024(c: &mut Criterion) {
    use rustpq::ml_kem::mlkem1024::*;

    let mut group = c.benchmark_group("mlkem1024");

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| encapsulate(black_box(&pk), &mut OsRng))
    });

    let (ct, _) = encapsulate(&pk, &mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| decapsulate(black_box(&sk), black_box(&ct)))
    });

    group.finish();
}

criterion_group!(benches, bench_mlkem512, bench_mlkem768, bench_mlkem1024);
criterion_main!(benches);
