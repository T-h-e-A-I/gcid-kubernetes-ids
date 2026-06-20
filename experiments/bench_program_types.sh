#!/bin/bash
# =============================================================================
# bench_program_types.sh -- Experiment B (micro): eBPF program-type overhead
# -----------------------------------------------------------------------------
# Reproduces the Bertinatto et al. comparison of eBPF program-type overhead
# (base vs kprobe vs tracepoint vs raw tracepoint). This is the empirical
# justification for using kprobes in production (plan decision #2): we show the
# overhead of each mechanism on identical syscall-tracing work.
#
# Methodology: run a fixed, syscall-heavy workload and measure its throughput
# (operations completed in a fixed wall-clock window) with each tracer attached.
# Lower throughput == higher tracing overhead.
#
# We measure the throughput of a tight getpid()/openat loop, since those are
# the syscalls our probes hook. Each tracer is attached via bpftrace one-liners
# (kprobe / tracepoint) and via the BCC raw-tracepoint program for raw-tp.
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
DURATION="${DURATION:-10}"     # seconds per measurement
REPEATS="${REPEATS:-5}"
mkdir -p "$RESULTS_DIR"
OUT="$RESULTS_DIR/program_types.csv"
echo "variant,repeat,ops_per_sec" > "$OUT"

# ---- workload: count how many openat() calls complete in $DURATION seconds --
# A small C microbenchmark is the cleanest; we inline-compile it once.
WORK=$(mktemp /tmp/work_XXXX.c)
cat > "$WORK" <<'EOF'
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    double dur = atof(argv[1]);
    struct timespec s, n;
    unsigned long long ops = 0;
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);  /* exercises openat path */
        if (fd >= 0) close(fd);
        ops++;
        if ((ops & 0xFFFF) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &n);
            double el = (n.tv_sec - s.tv_sec) + (n.tv_nsec - s.tv_nsec)/1e9;
            if (el >= dur) { printf("%.0f\n", ops/el); break; }
        }
    }
    return 0;
}
EOF
WORKBIN=$(mktemp /tmp/workbin_XXXX)
cc -O2 -o "$WORKBIN" "$WORK"

measure() {  # $1=variant label, runs workload while tracer (already started) runs
    local label="$1"
    for r in $(seq 1 "$REPEATS"); do
        local ops
        ops=$("$WORKBIN" "$DURATION")
        echo "$label,$r,$ops" >> "$OUT"
        echo "  [$label] repeat $r: $ops ops/sec"
    done
}

echo "=== base (no eBPF tracer) ==="
measure base

echo "=== kprobe on sys_openat (bpftrace) ==="
sudo bpftrace -e 'kprobe:__x64_sys_openat { @=count(); }' >/dev/null 2>&1 &
BTPID=$!; sleep 1
measure kprobe
sudo kill "$BTPID" 2>/dev/null || true; wait "$BTPID" 2>/dev/null || true

echo "=== tracepoint on sys_enter_openat (bpftrace) ==="
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @=count(); }' >/dev/null 2>&1 &
BTPID=$!; sleep 1
measure tracepoint
sudo kill "$BTPID" 2>/dev/null || true; wait "$BTPID" 2>/dev/null || true

echo "=== raw tracepoint on sys_enter (BCC, our variant) ==="
sudo python3 "$(dirname "$0")/../analysis/load_rawtp.py" >/dev/null 2>&1 &
RTPID=$!; sleep 3   # allow BCC compile + attach
measure raw_tracepoint
sudo kill "$RTPID" 2>/dev/null || true; wait "$RTPID" 2>/dev/null || true

rm -f "$WORK" "$WORKBIN"
echo ""
echo "Results -> $OUT"
echo "Plot/table: python3 analysis/score.py --program-types $OUT"
