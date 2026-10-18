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
//! - `decode_batch`: a read buffer already holding a batch of whole frames,
//!   drained to empty, for a small payload (the size of a typical SBE
//!   order-entry message) and a 4 KiB one. The buffer is shared before the
//!   timed call, as a real read buffer is once a first frame has been split
//!   off it.
//! - `decode_partial`: an incomplete frame in a buffer that already has room
//!   for all of it, so only the "read more" decision is timed.
//! - `decode_split_reads`: 4 KiB-payload frames arriving in 1460-byte reads
//!   (one TCP segment of payload on a 1500-byte MTU) into one reused read
//!   buffer, decoding after every read.
//! - `decode_split_reads_retain4`: the same, keeping the last four frames
//!   alive, which forces each refill that runs out of room to reallocate and
//!   copy (see "Retaining frames" in the codec docs).
//! - `encode_batch` and `encode_frame`: framing payloads into a reused 8 KiB
//!   write buffer that is advanced on every simulated flush, as a socket
//!   writer does.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use bytes::{Buf, BytesMut};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ironfix_sofh::{EncodingType, SofhCodec, SofhFrame};
use tokio_util::codec::{Decoder, Encoder};

/// Bytes of payload in one TCP segment on a 1500-byte MTU (IPv4, no options).
const SEGMENT: usize = 1460;

/// Initial capacity of a `tokio_util` `Framed` read or write buffer.
const IO_BUFFER: usize = 8 * 1024;

/// SOFH header length in bytes.
const HEADER: usize = 6;

/// A payload of `len` bytes with a non-trivial pattern.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Frames `count` payloads of `payload_len` bytes back to back.
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

/// Returns a copy of `source` whose allocation is already shared, as a read
/// buffer is after its first frame has been split off.
fn shared_copy(source: &BytesMut) -> BytesMut {
    let mut buf = source.clone();
    drop(buf.split_to(0));
    buf
}

/// Decodes every complete frame in `buf` and drops it, returning the payload
/// bytes seen.
fn drain(codec: &mut SofhCodec, buf: &mut BytesMut) -> usize {
    let mut seen = 0usize;
    loop {
        match codec.decode(black_box(&mut *buf)) {
            Ok(Some(frame)) => seen += black_box(frame).payload().len(),
            Ok(None) => return seen,
            Err(error) => panic!("fixture frames decode: {error}"),
        }
    }
}

/// Decodes every complete frame in `buf`, keeping the most recent ones alive
/// in `kept` (a ring), returning the payload bytes seen.
fn drain_retaining(
    codec: &mut SofhCodec,
    buf: &mut BytesMut,
    kept: &mut [Option<SofhFrame>],
    next: &mut usize,
) -> usize {
    let mut seen = 0usize;
    loop {
        match codec.decode(black_box(&mut *buf)) {
            Ok(Some(frame)) => {
                seen += frame.payload().len();
                if let Some(slot) = kept.get_mut(*next) {
                    *slot = Some(frame);
                }
                *next = (*next + 1) % kept.len();
            }
            Ok(None) => return seen,
            Err(error) => panic!("fixture frames decode: {error}"),
        }
    }
}

/// Simulates a socket flush: everything written so far leaves the buffer.
fn flush(dst: &mut BytesMut) {
    black_box(&dst[..]);
    let written = dst.len();
    dst.advance(written);
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("sofh/decode");

    for payload_len in [64usize, 4096] {
        for count in [1usize, 8, 64] {
            let source = batch(count, payload_len);
            group.throughput(Throughput::Bytes(source.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("decode_batch/{payload_len}B"), count),
                &source,
                |b, source| {
                    b.iter_batched_ref(
                        || shared_copy(source),
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

    // An incomplete frame in a buffer with room for all of it: the reserve
    // is a no-op, so only the "read more" decision is timed. This runs on
    // every partial socket read.
    let whole = batch(1, 64);
    let frame_len = whole.len();
    let partial_len = frame_len / 2;
    group.throughput(Throughput::Bytes(partial_len as u64));
    group.bench_with_input(
        BenchmarkId::new("decode_partial", partial_len),
        &whole,
        |b, whole| {
            b.iter_batched_ref(
                || {
                    let Some(partial) = whole.get(..partial_len) else {
                        panic!("the partial read is inside the frame");
                    };
                    let mut buf = BytesMut::with_capacity(frame_len);
                    buf.extend_from_slice(partial);
                    buf
                },
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

    // 4 KiB frames arriving one TCP segment at a time into one read buffer
    // that lives as long as the connection, decoding after every read.
    for count in [1usize, 8] {
        let source = batch(count, 4096);
        group.throughput(Throughput::Bytes(source.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("decode_split_reads/4096B", count),
            &source,
            |b, source| {
                let mut codec = SofhCodec::new();
                let mut buf = BytesMut::with_capacity(IO_BUFFER);
                b.iter(|| {
                    let mut seen = 0usize;
                    for segment in source.chunks(SEGMENT) {
                        buf.extend_from_slice(black_box(segment));
                        seen += drain(&mut codec, &mut buf);
                    }
                    black_box(seen)
                });
            },
        );
    }

    // The same stream while the last four frames are kept alive: each refill
    // that runs out of room reallocates and copies the unread tail.
    let source = batch(16, 4096);
    group.throughput(Throughput::Bytes(source.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("decode_split_reads_retain4/4096B", 16),
        &source,
        |b, source| {
            let mut codec = SofhCodec::new();
            let mut buf = BytesMut::with_capacity(IO_BUFFER);
            let mut kept: [Option<SofhFrame>; 4] = [None, None, None, None];
            let mut next = 0usize;
            b.iter(|| {
                let mut seen = 0usize;
                for segment in source.chunks(SEGMENT) {
                    buf.extend_from_slice(black_box(segment));
                    seen += drain_retaining(&mut codec, &mut buf, &mut kept, &mut next);
                }
                black_box(seen)
            });
        },
    );

    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("sofh/encode");

    // Borrowed payloads framed into a reused 8 KiB write buffer, flushed
    // whenever the next frame would not fit and at the end of the batch.
    for count in [1usize, 8, 64] {
        let body = payload(64);
        let frame_len = body.len() + HEADER;
        group.throughput(Throughput::Bytes((count * frame_len) as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_batch/64B", count),
            &body,
            |b, body| {
                let mut codec = SofhCodec::new();
                let mut dst = BytesMut::with_capacity(IO_BUFFER);
                b.iter(|| {
                    for _ in 0..count {
                        if dst.spare_capacity_mut().len() < frame_len {
                            flush(&mut dst);
                        }
                        if let Err(error) = codec.encode(
                            (EncodingType::SbeV1LittleEndian, black_box(&body[..])),
                            &mut dst,
                        ) {
                            panic!("bench payload encodes: {error}");
                        }
                    }
                    flush(&mut dst);
                });
            },
        );
    }

    // An owned frame written back byte for byte, as a relay forwards what it
    // decoded. The clone handed to the encoder shares the payload.
    for payload_len in [64usize, 4096] {
        let frame = match SofhFrame::new(EncodingType::SbeV1LittleEndian, payload(payload_len)) {
            Ok(frame) => frame,
            Err(error) => panic!("bench frame is valid: {error}"),
        };
        let frame_len = payload_len + HEADER;
        group.throughput(Throughput::Bytes(frame_len as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_frame", format!("{payload_len}B")),
            &frame,
            |b, frame| {
                let mut codec = SofhCodec::new();
                let mut dst = BytesMut::with_capacity(IO_BUFFER);
                b.iter_batched(
                    || frame.clone(),
                    |owned| {
                        if let Err(error) = codec.encode(black_box(owned), &mut dst) {
                            panic!("bench frame encodes: {error}");
                        }
                        flush(&mut dst);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode);
criterion_main!(benches);
