/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Criterion benchmarks for the FAST primitives.
//!
//! Two groups covering the operations a market-data decode loop repeats per
//! field: stop-bit integer and ASCII codecs, and the presence map.
//!
//! Every fixture is produced by this crate's own encoder, so the bytes fed to
//! the decoders are exactly the encodings they accept.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ironfix_fast::{FastDecoder, FastEncoder, PresenceMap, PresenceMapBuilder};

/// Stop-bit encodes a single unsigned value.
fn encoded_uint(value: u64) -> Vec<u8> {
    let mut e = FastEncoder::new();
    e.encode_uint(value);
    e.finish()
}

/// Stop-bit encodes a single signed value.
fn encoded_int(value: i64) -> Vec<u8> {
    let mut e = FastEncoder::new();
    e.encode_int(value);
    e.finish()
}

/// Stop-bit encodes a single ASCII string.
fn encoded_ascii(value: &str) -> Vec<u8> {
    let mut e = FastEncoder::new();
    e.encode_ascii(value).expect("fixture is ASCII");
    e.finish()
}

/// Builds a presence map with `len` alternating bits.
fn pmap_of(len: usize) -> PresenceMap {
    let mut builder = PresenceMapBuilder::new();
    for i in 0..len {
        builder = builder.bit(i % 3 != 0);
    }
    builder.build()
}

fn bench_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast/primitives");

    // One byte, two bytes, and a value that needs the full continuation chain.
    for (name, value) in [
        ("uint_1byte", 42u64),
        ("uint_2byte", 8_192),
        ("uint_max", u64::MAX),
    ] {
        let data = encoded_uint(value);
        group.bench_with_input(BenchmarkId::new("decode_uint", name), &data, |b, data| {
            b.iter(|| {
                let mut offset = 0usize;
                black_box(
                    FastDecoder::decode_uint(black_box(data.as_slice()), &mut offset)
                        .expect("fixture decodes"),
                )
            });
        });

        group.bench_with_input(BenchmarkId::new("encode_uint", name), &value, |b, value| {
            let mut e = FastEncoder::with_capacity(16);
            b.iter(|| {
                e.clear();
                e.encode_uint(black_box(*value));
                black_box(e.len())
            });
        });
    }

    for (name, value) in [("int_positive", 12_345i64), ("int_negative", -12_345)] {
        let data = encoded_int(value);
        group.bench_with_input(BenchmarkId::new("decode_int", name), &data, |b, data| {
            b.iter(|| {
                let mut offset = 0usize;
                black_box(
                    FastDecoder::decode_int(black_box(data.as_slice()), &mut offset)
                        .expect("fixture decodes"),
                )
            });
        });
    }

    let symbol = encoded_ascii("AAPL");
    group.bench_function("decode_ascii/symbol", |b| {
        b.iter(|| {
            let mut offset = 0usize;
            black_box(
                FastDecoder::decode_ascii(black_box(symbol.as_slice()), &mut offset)
                    .expect("fixture decodes"),
            )
        });
    });

    group.bench_function("encode_ascii/symbol", |b| {
        let mut e = FastEncoder::with_capacity(16);
        b.iter(|| {
            e.clear();
            e.encode_ascii(black_box("AAPL")).expect("ASCII input");
            black_box(e.len())
        });
    });

    group.finish();
}

fn bench_pmap(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast/pmap");

    // 7 bits fits one byte; 14 and 35 exercise the multi-byte continuation.
    for bits in [7usize, 14, 35] {
        let map = pmap_of(bits);
        let encoded = map.encode().expect("fixture encodes");

        group.bench_with_input(BenchmarkId::new("decode", bits), &encoded, |b, encoded| {
            b.iter(|| {
                let mut offset = 0usize;
                black_box(
                    PresenceMap::decode(black_box(encoded.as_slice()), &mut offset)
                        .expect("fixture decodes"),
                )
            });
        });

        group.bench_with_input(BenchmarkId::new("encode", bits), &map, |b, map| {
            b.iter(|| black_box(black_box(map).encode().expect("fixture encodes")));
        });

        // Bit-at-a-time consumption, the way a template walk reads it.
        group.bench_with_input(BenchmarkId::new("next_bit_walk", bits), &map, |b, map| {
            b.iter_batched_ref(
                || map.clone(),
                |map| {
                    let mut set = 0usize;
                    while let Ok(present) = map.next_bit() {
                        set += usize::from(present);
                    }
                    black_box(set)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_primitives, bench_pmap);
criterion_main!(benches);
