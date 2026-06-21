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

The entire parallel encrypt is, in effect:

```rust
let cts: Vec<Vec<u8>> = chunks.par_iter().enumerate()
    .map(|(i, p)| {
        let mut inst = base.clone();
        inst.wrap(&mut out, &make_aad(&salt, i, final_flag(i)), p);
        out
    })
    .collect(); // results are already in order
```

`par_iter().collect()` gives ordered, data-race-free results for free — there is
no mutex, condvar, slot ring or hand-written ordered writer like the C version.

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

## Status / limitations

This is a prototype to evaluate ergonomics. It reads the whole input into
memory and then runs read → parallel-compute → write, so it does **not** overlap
I/O with compute the way the C `parallel_pipe_suw` pipeline does — hence it is
somewhat slower on large files despite identical per-core crypto. A
`crossbeam`-channel pipeline (reader thread → Rayon pool → reorder writer) would
recover that overlap while staying far simpler and safer than the C
mutex/condvar version. Output is written via `create_new` (refuses to
overwrite) rather than the C tool's atomic temp-file + rename.

It passes the same `bats` conformance suite as the C tool:

```sh
SUW_BIN=$(pwd)/target/release/shakeupwrap-rs bats ../tests
```
