# ShakeUpWrap

`ShakeUpWrap` is a small command-line encryption/decryption tool built on XKCP's ShakingUpAE interface.

It is designed as a streaming filter:

* plaintext is read from `stdin` during encryption
* ciphertext is read from `stdin` during decryption
* output is written to `stdout` unless `-o` is specified
* the raw encryption key is stored separately in a key file specified by `-k`

## Build

From the XKCP repository root:

```sh
make x86-64/ShakeUpWrap
```

If the build system files are missing, initialize submodules first:

```sh
git submodule update --init --recursive
```

The resulting binary is expected at:

```sh
bin/x86-64/ShakeUpWrap
```

The exact path may vary depending on the selected XKCP target.

## Usage

```sh
ShakeUpWrap -e -k KEYFILE [-o OUTFILE]
ShakeUpWrap -d -k KEYFILE [-o OUTFILE]
```

Options:

```text
-e, --encrypt       Encrypt stdin to stdout or OUTFILE
-d, --decrypt       Decrypt stdin to stdout or OUTFILE
-k, --key KEYFILE   Key file path
-o, --output FILE   Output file path
-h, --help          Show help
```

Exactly one of `-e` or `-d` must be specified.

`-k KEYFILE` is always required.

No positional input filename is accepted. Use shell redirection or pipes for input.

## Encryption

Encrypt plaintext from `stdin` and write ciphertext to `stdout`:

```sh
ShakeUpWrap -e -k key.bin < plaintext.dat > ciphertext.suw
```

Encrypt plaintext from `stdin` and write ciphertext to a file:

```sh
ShakeUpWrap -e -k key.bin -o ciphertext.suw < plaintext.dat
```

During encryption:

* `KEYFILE` must not already exist
* a fresh 64-byte key is generated
* the key is written to `KEYFILE` in binary mode
* ciphertext is written to `stdout` or `OUTFILE`

The key file is created with restrictive permissions.

## Decryption

Decrypt ciphertext from `stdin` and write plaintext to `stdout`:

```sh
ShakeUpWrap -d -k key.bin < ciphertext.suw > plaintext.dat
```

Decrypt ciphertext from `stdin` and write plaintext to a file:

```sh
ShakeUpWrap -d -k key.bin -o plaintext.dat < ciphertext.suw
```

During decryption:

* `KEYFILE` must already exist
* `KEYFILE` must contain exactly one 64-byte key
* ciphertext is read from `stdin`
* plaintext is written to `stdout` or `OUTFILE`
* authentication failure causes decryption to fail

## Output file behavior

When `-o OUTFILE` is specified, `ShakeUpWrap` refuses to overwrite an existing output file.

For file output, the tool writes to a temporary file first and renames it to `OUTFILE` only after successful completion. This avoids leaving a partial output file after a failed encryption/decryption operation.

This protection does not apply when using shell redirection, because the shell opens the output file before `ShakeUpWrap` starts:

```sh
ShakeUpWrap -d -k key.bin < ciphertext.suw > plaintext.dat
```

For safer decryption to a file, prefer:

```sh
ShakeUpWrap -d -k key.bin -o plaintext.dat < ciphertext.suw
```

## Streaming format

`ShakeUpWrap` uses a fixed chunk size:

```text
256 MiB
```

There is no file header and no written chunk header. All format parameters are hardcoded by the tool.

Each chunk is encrypted as an authenticated message using ShakingUpAE. The associated data is reconstructed during encryption and decryption and contains:

```text
chunk_index || final_flag
```

where:

* `chunk_index` is the zero-based chunk number
* `final_flag` is `0` for non-final chunks
* `final_flag` is `1` for the final chunk

The final flag is authenticated. This prevents a valid ciphertext prefix from being accepted as a complete file.

The encoding follows an age-style final-chunk rule:

* empty plaintext is encoded as one empty final chunk
* if the plaintext size is exactly a multiple of 256 MiB, the last full chunk is marked final
* no extra empty final chunk is emitted for non-empty plaintext
* an empty final chunk is valid only for empty plaintext

This requires one-chunk lookahead during encryption and decryption. With 256 MiB chunks, memory usage is roughly:

```text
encryption: 2 plaintext chunks + 1 ciphertext chunk
decryption: 2 ciphertext chunks + 1 plaintext chunk
```

or about:

```text
768 MiB plus overhead
```

## Large-file behavior

`ShakeUpWrap` is intended for large sequential files.

The fixed 256 MiB chunk size is chosen for high throughput on large files. The tag overhead is small:

```text
64 bytes per 256 MiB chunk
```

For a 900 GB file, this is only a few hundred KiB of authentication-tag overhead.

## Security notes

The key file is the secret. Anyone with the key file can decrypt the ciphertext.

Keep the key file secure:

```sh
chmod 600 key.bin
```

Do not transmit or store the key file beside the ciphertext unless that is part of the intended security model.

The ciphertext does not include recipient information, password wrapping, public-key encryption, metadata, or key derivation. `ShakeUpWrap` is a low-level symmetric encryption utility around a raw 64-byte key file.

Because there is no file header, the ciphertext does not self-identify as a `ShakeUpWrap` file and does not carry version information. A wrong file, wrong key, or corrupted ciphertext is reported as an authentication or ciphertext-format failure.

## Examples

Encrypt a large file:

```sh
ShakeUpWrap -e -k backup.key -o backup.suw < backup.tar
```

Decrypt it:

```sh
ShakeUpWrap -d -k backup.key -o backup.tar < backup.suw
```

Verify round trip:

```sh
cmp backup.original backup.tar
```

Pipe through another command:

```sh
tar cf - directory | ShakeUpWrap -e -k archive.key -o archive.tar.suw
```

Decrypt and extract:

```sh
ShakeUpWrap -d -k archive.key < archive.tar.suw | tar xf -
```

## Tests

A Bats test suite is recommended for CLI-level regression testing.

Suggested layout:

```text
util/ShakeUpWrap/tests/
  shakeupwrap_basic.bats
  shakeupwrap_large.bats
```

The basic test suite should cover:

* `--help`
* missing mode
* missing key path
* multiple modes
* unexpected positional arguments
* empty input
* 1-byte input
* small round-trip encryption/decryption
* existing key rejection during encryption
* missing key rejection during decryption
* output overwrite rejection
* corrupted ciphertext rejection
* truncated ciphertext rejection
* no partial `-o` output after failed decryption

The large test suite should cover chunk-boundary cases:

```text
256 MiB - 1 byte
256 MiB - 1 MiB
256 MiB
256 MiB + 1 byte
256 MiB + 1 MiB
2 * 256 MiB
2 * 256 MiB + 1 byte
```

Example:

```sh
SUW_BIN=./bin/x86-64/ShakeUpWrap bats util/ShakeUpWrap/tests/shakeupwrap_basic.bats
```

Run the large boundary tests separately because they generate multiple large files:

```sh
SUW_BIN=./bin/x86-64/ShakeUpWrap bats util/ShakeUpWrap/tests/shakeupwrap_large.bats
```

For manual throughput testing on very large files, use a separate shell script instead of Bats.

## Exit status

The process exits with status `0` on success.

Any error returns a nonzero exit status and prints a diagnostic message to `stderr`.

No diagnostic messages are printed to `stdout`, because `stdout` may contain ciphertext or plaintext.
