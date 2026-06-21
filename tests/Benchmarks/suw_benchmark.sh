#!/usr/bin/env bash
#
# ShakeUpWrap I/O benchmark.
#
# Times encryption (and optionally decryption) of large plaintext files for one
# or more ShakeUpWrap binaries, so different async-I/O implementations (plain
# synchronous, pthread reader, io_uring reader) can be compared on identical
# inputs.
#
# Usage:
#   suw_benchmark.sh [options] LABEL=BINARY [LABEL=BINARY ...]
#
# Options:
#   -s SIZES   Comma separated file sizes (suffixes K/M/G).   Default: 256M,512M,1G
#   -r RUNS    Timed repetitions per size.                    Default: 3
#   -d DIR     Working directory for test data.              Default: ./suw-bench-data
#   -c         Drop the page cache before every timed run (cold I/O, needs sudo).
#   -D         Also benchmark decryption.
#   -h         Show this help.
#
# Example:
#   suw_benchmark.sh -c -s 512M,1G sync=/tmp/suw_sync pthread=/tmp/suw_pthread
set -euo pipefail

SIZES="256M,512M,1G"
RUNS=3
DATADIR="./suw-bench-data"
DROP_CACHES=0
DO_DECRYPT=0

usage() { sed -n '2,30p' "$0"; }

while getopts "s:r:d:cDh" opt; do
    case "$opt" in
        s) SIZES="$OPTARG" ;;
        r) RUNS="$OPTARG" ;;
        d) DATADIR="$OPTARG" ;;
        c) DROP_CACHES=1 ;;
        D) DO_DECRYPT=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
    echo "error: provide at least one LABEL=BINARY pair" >&2
    usage
    exit 1
fi

declare -a LABELS=()
declare -a BINS=()
for pair in "$@"; do
    label="${pair%%=*}"
    bin="${pair#*=}"
    if [[ -z "$label" || -z "$bin" || "$label" == "$pair" ]]; then
        echo "error: bad LABEL=BINARY pair: $pair" >&2
        exit 1
    fi
    if [[ ! -x "$bin" ]]; then
        echo "error: not executable: $bin" >&2
        exit 1
    fi
    LABELS+=("$label")
    BINS+=("$bin")
done

mkdir -p "$DATADIR"

to_bytes() {
    local v="$1" n="${1%[KMG]}" suf="${1: -1}"
    case "$suf" in
        K) echo $((n * 1024)) ;;
        M) echo $((n * 1024 * 1024)) ;;
        G) echo $((n * 1024 * 1024 * 1024)) ;;
        *) echo "$v" ;;
    esac
}

drop_caches() {
    [[ "$DROP_CACHES" -eq 1 ]] || return 0
    sync
    if [[ "$(id -u)" -eq 0 ]]; then
        echo 3 > /proc/sys/vm/drop_caches
    else
        echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    fi
}

# Median of a list of floating point numbers passed as arguments.
median() {
    local sorted
    sorted=$(printf '%s\n' "$@" | sort -n)
    local count
    count=$(printf '%s\n' "$sorted" | wc -l)
    local mid=$((count / 2))
    if (( count % 2 == 1 )); then
        printf '%s\n' "$sorted" | sed -n "$((mid + 1))p"
    else
        local a b
        a=$(printf '%s\n' "$sorted" | sed -n "${mid}p")
        b=$(printf '%s\n' "$sorted" | sed -n "$((mid + 1))p")
        awk -v a="$a" -v b="$b" 'BEGIN{printf "%.4f", (a + b) / 2}'
    fi
}

throughput_mb() { # bytes seconds
    awk -v b="$1" -v s="$2" 'BEGIN{ if (s <= 0) s = 1e-9; printf "%.1f", (b / 1048576.0) / s }'
}

echo "ShakeUpWrap benchmark"
echo "  sizes      : $SIZES"
echo "  runs       : $RUNS"
echo "  data dir   : $DATADIR"
echo "  drop caches: $((DROP_CACHES)) (1 = cold I/O)"
echo "  decryption : $((DO_DECRYPT))"
echo "  binaries   :"
for i in "${!LABELS[@]}"; do
    echo "    ${LABELS[$i]} -> ${BINS[$i]}"
done
echo

IFS=',' read -ra SIZE_LIST <<< "$SIZES"

for size in "${SIZE_LIST[@]}"; do
    bytes=$(to_bytes "$size")
    pt="$DATADIR/plain_$size.bin"
    if [[ ! -f "$pt" || "$(stat -c '%s' "$pt")" -ne "$bytes" ]]; then
        echo "Generating $size test file ..."
        dd if=/dev/urandom of="$pt" bs=1M count=$((bytes / 1048576)) status=none
        rem=$((bytes % 1048576))
        if (( rem > 0 )); then
            dd if=/dev/urandom of="$pt" bs=1 count="$rem" oflag=append conv=notrunc status=none
        fi
    fi

    echo "=== file size: $size ($bytes bytes) ==="
    printf '%-12s %-12s %12s %12s\n' "impl" "op" "median_s" "MB/s"

    for i in "${!LABELS[@]}"; do
        label="${LABELS[$i]}"
        bin="${BINS[$i]}"

        # Encryption.
        enc_times=()
        ct="$DATADIR/ct_${label}_$size.bin"
        for ((r = 0; r < RUNS; r++)); do
            key="$DATADIR/key_${label}_$size"
            rm -f "$key" "$ct"
            drop_caches
            start=$(date +%s.%N)
            "$bin" -e -k "$key" -o "$ct" < "$pt"
            end=$(date +%s.%N)
            enc_times+=("$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.4f", b - a}')")
        done
        emed=$(median "${enc_times[@]}")
        printf '%-12s %-12s %12s %12s\n' "$label" "encrypt" "$emed" "$(throughput_mb "$bytes" "$emed")"

        # Decryption (optional). Uses the ciphertext + key from the last encrypt run.
        if [[ "$DO_DECRYPT" -eq 1 ]]; then
            dec_times=()
            out="$DATADIR/out_${label}_$size.bin"
            key="$DATADIR/key_${label}_$size"
            for ((r = 0; r < RUNS; r++)); do
                rm -f "$out"
                drop_caches
                start=$(date +%s.%N)
                "$bin" -d -k "$key" -o "$out" < "$ct"
                end=$(date +%s.%N)
                dec_times+=("$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.4f", b - a}')")
            done
            dmed=$(median "${dec_times[@]}")
            printf '%-12s %-12s %12s %12s\n' "$label" "decrypt" "$dmed" "$(throughput_mb "$bytes" "$dmed")"
            cmp -s "$pt" "$out" || echo "  WARNING: roundtrip mismatch for $label/$size"
            rm -f "$out"
        fi

        rm -f "$ct" "$DATADIR/key_${label}_$size"
    done
    echo
done
