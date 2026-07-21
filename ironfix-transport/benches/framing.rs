/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Criterion benchmarks for the `FixCodec` framing loop.
//!
//! The codec sits between the socket and the decoder, so it runs once per
//! frame on every inbound byte. Two shapes are covered:
//!
//! - a buffer already holding a batch of whole frames, drained to empty;
//! - a partial frame, which must be recognised as "read more" without
//!   consuming anything.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use bytes::BytesMut;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ironfix_tagvalue::Encoder;
use ironfix_transport::FixCodec;
use tokio_util::codec::Decoder;

const BEGIN_STRING: &str = "FIX.4.4";

/// Builds one ExecutionReport frame with a self-consistent length and checksum.
fn frame(seq: u64) -> BytesMut {
    let mut e = Encoder::with_capacity(BEGIN_STRING, 512);
    e.put_str(35, "8");
    e.put_str(49, "ACCEPTOR");
    e.put_str(56, "INITIATOR");
    e.put_uint(34, seq);
    e.put_str(52, "20260721-10:15:30.123");
    e.put_str(37, "ORD-0000000042");
    e.put_str(11, "CLORD-0000000042");
    e.put_str(17, "EXEC-0000000042");
    e.put_str(150, "F");
    e.put_str(39, "2");
    e.put_str(55, "AAPL");
    e.put_char(54, '1');
    e.put_uint(38, 10_000);
    e.put_str(44, "150.50");
    e.put_uint(32, 10_000);
    e.put_str(31, "150.49");
    e.put_str(60, "20260721-10:15:30.120");
    e.finish()
}

/// Concatenates `count` frames into a single read-sized buffer.
fn batch(count: u64) -> BytesMut {
    let mut buf = BytesMut::new();
    for seq in 1..=count {
        buf.extend_from_slice(&frame(seq));
    }
    buf
}

fn bench_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport/framing");

    for count in [1u64, 8, 64] {
        let source = batch(count);
        group.throughput(Throughput::Bytes(source.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("decode_batch", count),
            &source,
            |b, source| {
                b.iter_batched_ref(
                    || source.clone(),
                    |buf| {
                        let mut codec = FixCodec::new();
                        let mut frames = 0usize;
                        while let Some(f) = codec.decode(black_box(buf)).expect("fixture frames") {
                            frames += black_box(f).len();
                        }
                        black_box(frames)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decode_batch_no_checksum", count),
            &source,
            |b, source| {
                b.iter_batched_ref(
                    || source.clone(),
                    |buf| {
                        let mut codec = FixCodec::new().with_checksum_validation(false);
                        let mut frames = 0usize;
                        while let Some(f) = codec.decode(black_box(buf)).expect("fixture frames") {
                            frames += black_box(f).len();
                        }
                        black_box(frames)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    // A frame split across two reads: the codec must decide "incomplete"
    // without consuming or copying. This runs on every partial socket read.
    let mut whole = frame(1);
    let partial = whole.split_to(whole.len() / 2);
    group.throughput(Throughput::Bytes(partial.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("decode_partial", partial.len()),
        &partial,
        |b, partial| {
            b.iter_batched_ref(
                || partial.clone(),
                |buf| {
                    let mut codec = FixCodec::new();
                    black_box(
                        codec
                            .decode(black_box(buf))
                            .expect("partial is not an error"),
                    )
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

criterion_group!(benches, bench_framing);
criterion_main!(benches);
