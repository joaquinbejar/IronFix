/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Criterion benchmarks for the `SofhCodec` framing loop.
//!
//! The codec sits between the socket and the payload decoder, so it runs once
//! per frame on every inbound byte. The shapes covered:
//!
//! - a buffer already holding a batch of whole frames, drained to empty, for a
//!   small payload (the size of a typical SBE order-entry message) and a
//!   larger one;
//! - a partial frame, which must be recognised as "read more" without
//!   consuming anything;
//! - framing a batch of borrowed payloads into one write buffer.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use bytes::BytesMut;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ironfix_sofh::{EncodingType, SofhCodec};
use tokio_util::codec::{Decoder, Encoder};

/// A payload of `len` bytes with a non-trivial pattern.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Frames `count` payloads of `payload_len` bytes into one read-sized buffer.
fn batch(count: usize, payload_len: usize) -> BytesMut {
    let body = payload(payload_len);
    let mut codec = SofhCodec::new();
    let mut buf = BytesMut::new();
    for _ in 0..count {
        if let Err(error) = codec.encode((EncodingType::SbeV1LittleEndian, &body[..]), &mut buf) {
            panic!("bench frame encodes: {error}");
        }
    }
    buf
}

/// Decodes every frame in `buf`, returning the payload bytes seen.
fn drain(codec: &mut SofhCodec, buf: &mut BytesMut) -> usize {
    let mut seen = 0usize;
    loop {
        match codec.decode(black_box(buf)) {
            Ok(Some(frame)) => seen += black_box(frame).payload().len(),
            Ok(None) => return seen,
            Err(error) => panic!("fixture frames decode: {error}"),
        }
    }
}

fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sofh/framing");

    for (payload_len, counts) in [(64usize, [1usize, 8, 64]), (4096, [1, 8, 64])] {
        for count in counts {
            let source = batch(count, payload_len);
            group.throughput(Throughput::Bytes(source.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("decode_batch/{payload_len}B"), count),
                &source,
                |b, source| {
                    b.iter_batched_ref(
                        || source.clone(),
                        |buf| {
                            let mut codec = SofhCodec::new();
                            black_box(drain(&mut codec, buf))
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    // A frame split across two reads: the codec must decide "incomplete"
    // without consuming or copying. This runs on every partial socket read.
    let mut whole = batch(1, 64);
    let partial = whole.split_to(whole.len() / 2);
    group.throughput(Throughput::Bytes(partial.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("decode_partial", partial.len()),
        &partial,
        |b, partial| {
            b.iter_batched_ref(
                || partial.clone(),
                |buf| {
                    let mut codec = SofhCodec::new();
                    match codec.decode(black_box(buf)) {
                        Ok(result) => black_box(result.is_none()),
                        Err(error) => panic!("a partial frame is not an error: {error}"),
                    }
                },
                BatchSize::SmallInput,
            );
        },
    );

    // Framing borrowed payloads into one write buffer, as an outbound path
    // would before a socket write.
    for count in [1usize, 8, 64] {
        let body = payload(64);
        let capacity = count * (body.len() + 6);
        group.throughput(Throughput::Bytes(capacity as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_batch/64B", count),
            &body,
            |b, body| {
                b.iter_batched_ref(
                    || BytesMut::with_capacity(capacity),
                    |dst| {
                        let mut codec = SofhCodec::new();
                        for _ in 0..count {
                            if let Err(error) = codec.encode(
                                (EncodingType::SbeV1LittleEndian, black_box(&body[..])),
                                dst,
                            ) {
                                panic!("bench payload encodes: {error}");
                            }
                        }
                        black_box(dst.len())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_framing);
criterion_main!(benches);
