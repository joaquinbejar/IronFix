/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Criterion benchmarks for the `FixCodec` framing loop.
//!
//! The codec sits between the socket and the decoder, so it runs once per
//! frame on every inbound byte. The shapes covered:
//!
//! - a buffer already holding a batch of whole frames, drained to empty, with
//!   garbled-frame recovery off and on (the engines run with it on);
//! - a batch in which every eighth frame is garbled (a bad CheckSum, a bad
//!   BodyLength, or preceding noise dense in near-anchors), drained with
//!   recovery on;
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
    let mut out = BytesMut::new();
    match e.finish_into(&mut out) {
        Ok(()) => out,
        Err(err) => panic!("bench frame encodes: {err}"),
    }
}

/// Concatenates `count` frames into a single read-sized buffer.
fn batch(count: u64) -> BytesMut {
    let mut buf = BytesMut::new();
    for seq in 1..=count {
        buf.extend_from_slice(&frame(seq));
    }
    buf
}

/// How a frame in a garbled batch is damaged.
#[derive(Clone, Copy)]
enum Garbling {
    /// The CheckSum (10) value is off by one: the frame is consumed whole.
    CheckSum,
    /// BodyLength (9) is one short: the trailer is not where it points, so the
    /// codec resynchronises through the body.
    BodyLength,
    /// The frame is preceded by noise dense in near-anchors (`8`, `<SOH>8`,
    /// `8=FIX`, tags `8xx`), each of which the resync scan must reject.
    DenseNoise,
}

/// Noise built from almost-frame-starts, prepended for [`Garbling::DenseNoise`].
const DENSE_NOISE: &[u8] =
    b"8=FIX8=FIX.4.4\x018\x0188=FIX.4.\x01851=8\x01828=0\x01880=X\x018=FIX.4.4\x0135=0\x01x8=FIXT.1.";

/// Returns `frame` with its CheckSum value off by one.
fn with_bad_checksum(frame: &[u8]) -> BytesMut {
    let digits_at = frame.len() - 4;
    let declared: u16 = std::str::from_utf8(&frame[digits_at..frame.len() - 1])
        .expect("checksum digits are ASCII")
        .parse()
        .expect("checksum digits are decimal");
    let mut out = BytesMut::from(&frame[..digits_at]);
    out.extend_from_slice(format!("{:03}\x01", (declared + 1) % 256).as_bytes());
    out
}

/// Returns `frame` with its BodyLength one short of the real body.
fn with_bad_body_length(frame: &[u8]) -> BytesMut {
    let start = frame
        .windows(3)
        .position(|w| w == b"\x019=")
        .expect("frame has BodyLength")
        + 3;
    let end = start
        + frame[start..]
            .iter()
            .position(|&b| b == 0x01)
            .expect("BodyLength is terminated");
    let declared: usize = std::str::from_utf8(&frame[start..end])
        .expect("BodyLength is ASCII")
        .parse()
        .expect("BodyLength is decimal");
    let mut out = BytesMut::from(&frame[..start]);
    out.extend_from_slice((declared - 1).to_string().as_bytes());
    out.extend_from_slice(&frame[end..]);
    out
}

/// A batch of `count` frames in which every eighth one is garbled by `kind`.
fn garbled_batch(count: u64, kind: Garbling) -> BytesMut {
    let mut buf = BytesMut::new();
    for seq in 1..=count {
        let good = frame(seq);
        if seq % 8 != 0 {
            buf.extend_from_slice(&good);
            continue;
        }
        match kind {
            Garbling::CheckSum => buf.extend_from_slice(&with_bad_checksum(&good)),
            Garbling::BodyLength => buf.extend_from_slice(&with_bad_body_length(&good)),
            Garbling::DenseNoise => {
                buf.extend_from_slice(DENSE_NOISE);
                buf.extend_from_slice(&good);
            }
        }
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

        // The same clean batch with garbled-frame recovery on, which is how
        // both engines configure the codec: the happy path should not change.
        group.bench_with_input(
            BenchmarkId::new("decode_batch_recovery", count),
            &source,
            |b, source| {
                b.iter_batched_ref(
                    || source.clone(),
                    |buf| {
                        let mut codec = FixCodec::new().with_garbled_recovery(true);
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

    // Recovery under garbling: 64 frames with every eighth one damaged, drained
    // in one pass. Each case exercises a different skip path: a whole-frame
    // consume, a resync through a body, and a resync that must reject many
    // near-anchors.
    for (name, kind) in [
        ("decode_garbled_checksum", Garbling::CheckSum),
        ("decode_garbled_body_length", Garbling::BodyLength),
        ("decode_garbled_dense_noise", Garbling::DenseNoise),
    ] {
        let source = garbled_batch(64, kind);
        group.throughput(Throughput::Bytes(source.len() as u64));
        group.bench_with_input(BenchmarkId::new(name, 64), &source, |b, source| {
            b.iter_batched_ref(
                || source.clone(),
                |buf| {
                    let mut codec = FixCodec::new().with_garbled_recovery(true);
                    let mut frames = 0usize;
                    while let Some(f) = codec
                        .decode(black_box(buf))
                        .expect("recovery skips garbled frames")
                    {
                        frames += black_box(f).len();
                    }
                    black_box((frames, codec.take_garbled_count()))
                },
                criterion::BatchSize::SmallInput,
            );
        });
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
