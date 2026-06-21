# shakeupwrap-rs

A Rust front-end for ShakeUpWrap that links **XKCP** for the cryptography and
expresses the multi-core parallelism with **Rayon**. It exists to answer the
question "is it cleaner to do the multithreading in Rust and link against
XKCP?".

It implements the exact same on-disk format as the C `parallel_pipe_suw`
branch (32-byte salt header, 4 MiB independent chunks, AAD = `salt || index ||
final`, 64-byte key/tag, capacity 512), so the two are **interoperable**:
ciphertext produced by one decrypts with the other.

## How it links XKCP

* `c_shim/suw_ffi.c` exposes a tiny, struct-agnostic ABI over XKCP's
  `SHAKE_Wrap_*` functions (`suw_dwrap_init/clone/wrap/unwrap`), plus
  `suw_dwrap_size()` so Rust never has to mirror the C struct layout.
* `build.rs` compiles that shim with the `cc` crate (against the installed XKCP
  headers) and links the prebuilt `libXKCP.a`.
* `src/xkcp.rs` is a safe wrapper: the DWrap instance is held as an opaque byte
  buffer; cloning it is a plain `Vec<u8>` copy, which is exactly what
  `SHAKE_Wrap_Clone` does (the instance is plain old data). Each worker clones
  the keyed base and mutates only its own copy, so concurrent FFI calls are
  sound.

## The parallel core

The pipeline overlaps reading, parallel crypto, and writing:

```
reader thread  ->  bounded channel  ->  N worker threads  ->  ordered atomic writer
```

A dedicated reader streams chunks into a bounded `crossbeam` channel (back-
pressure keeps memory bounded regardless of file size); a pool of workers wraps/
unwraps in parallel; the main thread reassembles results in sequence order and
writes them. Each worker clones the keyed base instance and mutates only its own
copy. There is no manual mutex/condvar slot machine — `crossbeam` channels plus
scoped threads express the same pipeline the C `parallel_pipe_suw` branch builds
by hand, with ordering and data-race freedom guaranteed by the compiler.

## Build

```sh
# 1. Build the XKCP static library from the repo root
make x86-64/libXKCP.a
# 2. Build this crate (build.rs finds ../../../bin/x86-64/libXKCP.a)
cd util/ShakeUpWrap/shakeupwrap-rs
cargo build --release
```

Override locations with `XKCP_DIR` and `XKCP_TARGET` if needed.

## Usage

```sh
shakeupwrap-rs -e -k KEYFILE [-o OUTFILE] < plaintext
shakeupwrap-rs -d -k KEYFILE [-o OUTFILE] < ciphertext
```

## Status

This implements a streaming pipeline (reader thread → bounded channel → worker
pool → ordered writer) that overlaps I/O with compute, so it keeps pace with the
C `parallel_pipe_suw` pipeline on large files (~2.9–3.0 GiB/s encrypt on a
24-core host, vs the C pipeline's ~2.5–3.0 GiB/s). Output is written atomically
via a temp file + rename, and refuses to overwrite an existing target.

It passes the same `bats` conformance suite as the C tool:

```sh
SUW_BIN=$(pwd)/target/release/shakeupwrap-rs bats ../tests
```
