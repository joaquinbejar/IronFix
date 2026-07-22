/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Criterion benchmarks for the tag=value hot path.
//!
//! The groups covered:
//!
//! - `tagvalue/decode` — full `Decoder::decode` and bare field iteration over
//!   two pinned message literals (a Logon and an ExecutionReport), captured once
//!   from the crate's `Encoder` so the decode input does not silently track a
//!   later encoder change.
//! - `tagvalue/encode` — a full `finish()` and the reused-buffer append path,
//!   built inline by the `Encoder` under test.
//! - `tagvalue/checksum` — `calculate_checksum` across payload sizes, with the
//!   scalar `format`/`parse` of the tag 10 field in `tagvalue/checksum_field`.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ironfix_tagvalue::checksum::{format_checksum, parse_checksum};
use ironfix_tagvalue::{Decoder, Encoder, calculate_checksum};

const BEGIN_STRING: &str = "FIX.4.4";

/// Pinned Logon (35=A) — the shortest message a real session exchanges.
///
/// Captured once from the crate's own `Encoder` and kept as a literal, so the
/// decode benches measure a fixed input rather than tracking the encoder's
/// current output. `BodyLength` (9) and `CheckSum` (10) are self-consistent as
/// written.
const LOGON: &[u8] = b"8=FIX.4.4\x019=72\x0135=A\x0149=INITIATOR\x0156=ACCEPTOR\x0134=1\x0152=20260721-10:15:30.123\x0198=0\x01108=30\x0110=247\x01";

/// Pinned ExecutionReport (35=8) — a representative application message.
///
/// Captured the same way as [`LOGON`]: a literal, not a live `Encoder` call.
const EXECUTION_REPORT: &[u8] = b"8=FIX.4.4\x019=253\x0135=8\x0149=ACCEPTOR\x0156=INITIATOR\x0134=4242\x0152=20260721-10:15:30.123\x0137=ORD-0000000042\x0111=CLORD-0000000042\x0117=EXEC-0000000042\x01150=F\x0139=2\x0155=AAPL\x0154=1\x0138=10000\x0144=150.50\x0132=10000\x0131=150.49\x0114=10000\x016=150.49\x01151=0\x0160=20260721-10:15:30.120\x011=ACCOUNT-01\x01207=XNAS\x0110=199\x01";

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagvalue/decode");

    for (name, msg) in [("logon", LOGON), ("execution_report", EXECUTION_REPORT)] {
        group.throughput(Throughput::Bytes(msg.len() as u64));

        group.bench_with_input(BenchmarkId::new("decode", name), &msg, |b, &msg| {
            b.iter(|| {
                let mut decoder = Decoder::new(black_box(msg));
                black_box(decoder.decode().expect("fixture decodes"))
            });
        });

        // Checksum validation off isolates the scan from the trailer arithmetic.
        group.bench_with_input(
            BenchmarkId::new("decode_no_checksum", name),
            &msg,
            |b, &msg| {
                b.iter(|| {
                    let mut decoder = Decoder::new(black_box(msg)).with_checksum_validation(false);
                    black_box(decoder.decode().expect("fixture decodes"))
                });
            },
        );

        // Field iteration alone, without the header/trailer structural checks.
        group.bench_with_input(BenchmarkId::new("next_field", name), &msg, |b, &msg| {
            b.iter(|| {
                let mut decoder = Decoder::new(black_box(msg));
                let mut count = 0usize;
                while let Some(field) = decoder.next_field().expect("fixture scans") {
                    count += black_box(field).value.len();
                }
                black_box(count)
            });
        });
    }

    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagvalue/encode");

    group.bench_function("logon_finish", |b| {
        b.iter(|| {
            let mut e = Encoder::with_capacity(BEGIN_STRING, 256);
            e.put_str(35, black_box("A"));
            e.put_str(49, black_box("INITIATOR"));
            e.put_str(56, black_box("ACCEPTOR"));
            e.put_uint(34, black_box(1));
            e.put_str(52, black_box("20260721-10:15:30.123"));
            e.put_str(98, black_box("0"));
            e.put_uint(108, black_box(30));
            black_box(e.finish())
        });
    });

    // Field-append cost on a reused buffer: clear() then the put_* calls, one
    // buffer refilled per iteration. It stops at body_len(), so it times the
    // append path only — not finish()'s length/checksum pass — and does not by
    // itself prove that path allocates nothing.
    group.bench_function("execution_report_body_reused_buffer", |b| {
        let mut e = Encoder::with_capacity(BEGIN_STRING, 512);
        b.iter(|| {
            e.clear();
            e.put_str(35, black_box("8"));
            e.put_str(49, black_box("ACCEPTOR"));
            e.put_str(56, black_box("INITIATOR"));
            e.put_uint(34, black_box(4242));
            e.put_str(52, black_box("20260721-10:15:30.123"));
            e.put_str(37, black_box("ORD-0000000042"));
            e.put_str(11, black_box("CLORD-0000000042"));
            e.put_str(17, black_box("EXEC-0000000042"));
            e.put_str(150, black_box("F"));
            e.put_str(39, black_box("2"));
            e.put_str(55, black_box("AAPL"));
            e.put_char(54, black_box('1'));
            e.put_uint(38, black_box(10_000));
            e.put_str(44, black_box("150.50"));
            black_box(e.body_len())
        });
    });

    group.finish();
}

fn bench_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagvalue/checksum");

    for size in [64usize, 256, 1024, 4096] {
        let payload = vec![b'7'; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("calculate", size),
            &payload,
            |b, payload| {
                b.iter(|| black_box(calculate_checksum(black_box(payload.as_slice()))));
            },
        );
    }

    group.finish();

    // `format`/`parse` operate on the fixed three-byte tag 10 field, not on a
    // payload, so they carry no byte throughput. They live in their own group to
    // keep the per-size `Throughput::Bytes` above from labelling them.
    let mut group = c.benchmark_group("tagvalue/checksum_field");

    group.bench_function("format", |b| {
        b.iter(|| black_box(format_checksum(black_box(213))));
    });

    group.bench_function("parse", |b| {
        b.iter(|| black_box(parse_checksum(black_box(b"213"))));
    });

    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode, bench_checksum);
criterion_main!(benches);
