use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use std::hint::black_box;

fn bench_mldsa44(c: &mut Criterion) {
    use rustpq::ml_dsa::sign::mldsa44::*;

    let mut group = c.benchmark_group("mldsa44");
    let msg = b"Hello World";
    let ctx = b"";

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("sign", |b| {
        b.iter(|| sign(black_box(&sk), black_box(msg), black_box(ctx), &mut OsRng))
    });

    let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            verify(
                black_box(&pk),
                black_box(msg),
                black_box(ctx),
                black_box(&sig),
            )
        })
    });

    group.finish();
}

fn bench_mldsa65(c: &mut Criterion) {
    use rustpq::ml_dsa::sign::mldsa65::*;

    let mut group = c.benchmark_group("mldsa65");
    let msg = b"Hello World";
    let ctx = b"";

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("sign", |b| {
        b.iter(|| sign(black_box(&sk), black_box(msg), black_box(ctx), &mut OsRng))
    });

    let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            verify(
                black_box(&pk),
                black_box(msg),
                black_box(ctx),
                black_box(&sig),
            )
        })
    });

    group.finish();
}

fn bench_mldsa87(c: &mut Criterion) {
    use rustpq::ml_dsa::sign::mldsa87::*;

    let mut group = c.benchmark_group("mldsa87");
    let msg = b"Hello World";
    let ctx = b"";

    group.bench_function("keygen", |b| b.iter(|| generate(black_box(&mut OsRng))));

    let (pk, sk) = generate(&mut OsRng);

    group.bench_function("sign", |b| {
        b.iter(|| sign(black_box(&sk), black_box(msg), black_box(ctx), &mut OsRng))
    });

    let sig = sign(&sk, msg, ctx, &mut OsRng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            verify(
                black_box(&pk),
                black_box(msg),
                black_box(ctx),
                black_box(&sig),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_mldsa44, bench_mldsa65, bench_mldsa87);
criterion_main!(benches);
