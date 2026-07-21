/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Criterion benchmarks for the tag=value hot path.
//!
//! Three groups, each over a fixture built by the crate's own `Encoder` so the
//! `BodyLength` and `CheckSum` fields are always self-consistent:
//!
//! - `tagvalue/decode` — full `Decoder::decode` and bare field iteration.
//! - `tagvalue/encode` — a full `finish()` and the reused-buffer append path.
//! - `tagvalue/checksum` — `calculate_checksum` across payload sizes.
//!
//! This harness only makes measurement possible. It records no baseline and
//! asserts no latency or throughput figure: run `make bench` to obtain numbers
//! on your own hardware.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ironfix_tagvalue::checksum::{format_checksum, parse_checksum};
use ironfix_tagvalue::{Decoder, Encoder, calculate_checksum};

const BEGIN_STRING: &str = "FIX.4.4";

/// Builds a Logon (35=A) — the shortest message a real session exchanges.
fn logon() -> Vec<u8> {
    let mut e = Encoder::new(BEGIN_STRING);
    e.put_str(35, "A");
    e.put_str(49, "INITIATOR");
    e.put_str(56, "ACCEPTOR");
    e.put_uint(34, 1);
    e.put_str(52, "20260721-10:15:30.123");
    e.put_str(98, "0");
    e.put_uint(108, 30);
    e.finish().to_vec()
}

/// Builds an ExecutionReport (35=8) — a representative application message.
fn execution_report() -> Vec<u8> {
    let mut e = Encoder::new(BEGIN_STRING);
    e.put_str(35, "8");
    e.put_str(49, "ACCEPTOR");
    e.put_str(56, "INITIATOR");
    e.put_uint(34, 4242);
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
    e.put_uint(14, 10_000);
    e.put_str(6, "150.49");
    e.put_uint(151, 0);
    e.put_str(60, "20260721-10:15:30.120");
    e.put_str(1, "ACCOUNT-01");
    e.put_str(207, "XNAS");
    e.finish().to_vec()
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagvalue/decode");

    for (name, msg) in [("logon", logon()), ("execution_report", execution_report())] {
        group.throughput(Throughput::Bytes(msg.len() as u64));

        group.bench_with_input(BenchmarkId::new("decode", name), &msg, |b, msg| {
            b.iter(|| {
                let mut decoder = Decoder::new(black_box(msg.as_slice()));
                black_box(decoder.decode().expect("fixture decodes"))
            });
        });

        // Checksum validation off isolates the scan from the trailer arithmetic.
        group.bench_with_input(
            BenchmarkId::new("decode_no_checksum", name),
            &msg,
            |b, msg| {
                b.iter(|| {
                    let mut decoder =
                        Decoder::new(black_box(msg.as_slice())).with_checksum_validation(false);
                    black_box(decoder.decode().expect("fixture decodes"))
                });
            },
        );

        // Field iteration alone, without the header/trailer structural checks.
        group.bench_with_input(BenchmarkId::new("next_field", name), &msg, |b, msg| {
            b.iter(|| {
                let mut decoder = Decoder::new(black_box(msg.as_slice()));
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

    // The zero-allocation path: one buffer, cleared and refilled per message.
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
