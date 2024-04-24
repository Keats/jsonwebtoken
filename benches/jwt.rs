use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

fn bench_encode(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned() };
    let key = EncodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_encode", |b| {
        b.iter(|| encode(black_box(&Header::default()), black_box(&claim), black_box(&key)))
    });
}

fn bench_decode(c: &mut Criterion) {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    let key = DecodingKey::from_secret("secret".as_ref());

    let mut group = c.benchmark_group("decode");
    group.throughput(criterion::Throughput::Bytes(token.len() as u64));

    group.bench_function("str", |b| {
        b.iter(|| {
            decode::<Claims>(
                black_box(token),
                black_box(&key),
                black_box(&Validation::new(Algorithm::HS256)),
            )
        })
    });

    drop(group);
    let mut group = c.benchmark_group("header");
    group.throughput(criterion::Throughput::Bytes(token.len() as u64));

    group.bench_function("str", |b| {
        b.iter(|| {
            decode_header(
                // Simulate the cost of validating &str before decoding
                black_box(token),
            )
        })
    });
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
