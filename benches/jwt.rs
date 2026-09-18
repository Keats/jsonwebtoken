use criterion::{Criterion, criterion_group, criterion_main};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Extras, Header, Validation, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::hint::black_box;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: u64,
}

fn bench_encode(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 2532524891 };
    let key = EncodingKey::from_secret("secret".as_ref());

    c.bench_function("bench_encode", |b| {
        b.iter(|| {
            encode(black_box(&Header::default()), black_box(&claim), black_box(&key)).unwrap()
        })
    });
}

fn bench_encode_custom_extra_headers(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 2532524891 };
    let key = EncodingKey::from_secret("secret".as_ref());
    let mut extras = Extras::default();
    extras.insert("custom".to_string(), "header".to_string());
    let header = &Header { extras, ..Default::default() };

    c.bench_function("bench_encode_custom_extra_headers", |b| {
        b.iter(|| encode(black_box(header), black_box(&claim), black_box(&key)).unwrap());
    });
}

fn bench_decode(c: &mut Criterion) {
    let claim = Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 2532524891 };
    let encoding_key = EncodingKey::from_secret(b"secret");
    let key = DecodingKey::from_secret(b"secret");
    let validation = Validation::new(Algorithm::HS256);
    let mut extras = Extras::default();
    extras.insert("custom", "header");

    for (name, header) in [
        ("bench_decode", Header::default()),
        ("bench_decode_custom_extra_headers", Header { extras, ..Default::default() }),
    ] {
        let token = encode(&header, &claim, &encoding_key).unwrap();
        let decoded = decode::<Claims>(&token, &key, &validation).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.claims, claim);

        c.bench_function(name, |b| {
            b.iter(|| {
                decode::<Claims>(black_box(&token), black_box(&key), black_box(&validation))
                    .unwrap()
            })
        });
    }
}

criterion_group!(benches, bench_encode, bench_encode_custom_extra_headers, bench_decode);
criterion_main!(benches);
