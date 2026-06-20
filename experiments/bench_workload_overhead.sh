#!/bin/bash
# =============================================================================
# bench_workload_overhead.sh -- Experiment B (macro, PRIMARY): workload overhead
# -----------------------------------------------------------------------------
# Measures the overhead each monitoring approach imposes ON A FIXED WORKLOAD
# (Bertinatto-style), rather than the agent's own CPU.
#
# WHY PER-SYSCALL WORKLOADS: a syscall's monitoring cost only shows up when the
# workload is DOMINATED by that syscall. A fork+execve loop is dominated by the
# ~1 ms fork/exec, so it cannot reveal the (few-us) cost of monitoring a cheap
# syscall like openat. We therefore measure TWO workloads in a single run:
#   - execve : fork+execve("/bin/true")              (exercises the execve rule/probe)
#   - openat : tight open("/dev/null")+close loop     (exercises the open/openat rule/probe)
# The openat workload is where auditd's "log every syscall" cost is largest
# (it floods audit.log), so it is the clearest eBPF-vs-auditd contrast.
#
# Connect is deliberately NOT included: a tight TCP-connect loop exhausts
# ephemeral ports / piles up TIME_WAIT sockets, so its throughput is dominated
# by socket recycling rather than monitoring overhead -- it would measure the
# kernel's socket teardown, not the agent. (Documented limitation; the detection
# run already exercises the connect path for capability comparison.)
#
# Usage:  bench_workload_overhead.sh <condition>
#   condition = baseline | ebpf | auditd   (you set the condition up yourself)
#
# ONE invocation runs BOTH workloads back-to-back, so you only run it three
# times total (one per condition):
#
#   # (a) baseline -- no monitoring
#   sudo auditctl -D
#   ./experiments/bench_workload_overhead.sh baseline
#
#   # (b) eBPF -- agent running in another terminal, audit rules off
#   sudo auditctl -D
#   ./experiments/bench_workload_overhead.sh ebpf
#
#   # (c) auditd -- both rules loaded so BOTH workloads are monitored, eBPF off
#   sudo auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor
#   sudo auditctl -a always,exit -F arch=b64 -S openat -S open -k file_monitor
#   ./experiments/bench_workload_overhead.sh auditd
#
#   python3 analysis/score.py --workload results/workload_overhead.csv
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
COND="${1:-${CONDITION:-unlabeled}}"
DURATION="${DURATION:-10}"
REPEATS="${REPEATS:-5}"
# Which workloads to run (space-separated). Default: both. Override to e.g.
# WORKLOADS="openat" to run a single one.
WORKLOADS="${WORKLOADS:-execve openat}"
mkdir -p "$RESULTS_DIR"
# OUT is overridable so a separate comparator (e.g. Falco) can be collected into
# its OWN CSV (workload_overhead_falco.csv) and scored into its own table,
# keeping the eBPF-vs-auditd result untouched. The scorer derives the output
# name from this filename (see analysis/score.py _csv_tag).
OUT="${OUT:-$RESULTS_DIR/workload_overhead.csv}"
HDR="condition,workload,repeat,ops_per_sec"
if [ ! -f "$OUT" ]; then
    echo "$HDR" > "$OUT"
elif [ "$(head -n1 "$OUT")" != "$HDR" ]; then
    # A stale file with an old/mismatched header (e.g. the 3-column
    # `condition,repeat,execs_per_sec`) would misalign columns. Correct the
    # header line in place so old + new rows share the current 4-column schema
    # (the scorer parses positionally, so pre-existing rows still read fine).
    echo "  [warn] fixing stale CSV header in $OUT ($(head -n1 "$OUT")) -> $HDR"
    sed -i "1s|.*|$HDR|" "$OUT"
fi

# ---- sanity: report the monitoring state actually in effect ----------------
echo "=== Condition: $COND | Workloads: $WORKLOADS ==="
pgrep -f "python3 .*ebpf_agent.py" >/dev/null \
    && echo "  eBPF agent   : RUNNING" || echo "  eBPF agent   : not running"
pgrep -x falco >/dev/null \
    && echo "  falco        : RUNNING" || echo "  falco        : not running"
if sudo auditctl -l 2>/dev/null | grep -qE "S (execve|openat|open)"; then
    echo "  audit rules  : $(sudo auditctl -l 2>/dev/null | grep -oE 'S [a-z]+' | tr '\n' ' ')"
else
    echo "  audit rules  : none"
fi
echo ""

# ---- emit the C source for a given workload to stdout ----------------------
emit_src() {
  case "$1" in
    execve)
      cat <<'EOF'
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    double dur = atof(argv[1]);
    struct timespec s, n; unsigned long long ops = 0;
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (;;) {
        pid_t p = fork();
        if (p == 0) { execl("/bin/true", "true", (char *)0); _exit(127); }
        else if (p > 0) { waitpid(p, 0, 0); ops++; }
        if ((ops & 0x3FF) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &n);
            double el = (n.tv_sec - s.tv_sec) + (n.tv_nsec - s.tv_nsec) / 1e9;
            if (el >= dur) { printf("%.0f\n", ops / el); break; }
        }
    }
    return 0;
}
EOF
      ;;
    openat)
      cat <<'EOF'
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    double dur = atof(argv[1]);
    struct timespec s, n; unsigned long long ops = 0;
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);   /* exercises the openat path */
        if (fd >= 0) close(fd);
        ops++;
        if ((ops & 0xFFFF) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &n);
            double el = (n.tv_sec - s.tv_sec) + (n.tv_nsec - s.tv_nsec) / 1e9;
            if (el >= dur) { printf("%.0f\n", ops / el); break; }
        }
    }
    return 0;
}
EOF
      ;;
    *)
      echo "ERROR: unknown workload '$1' (use execve|openat)" >&2; return 1;;
  esac
}

# ---- run each workload REPEATS times --------------------------------------
for WL in $WORKLOADS; do
    WORK=$(mktemp /tmp/wlbench_XXXX.c)
    BIN=$(mktemp /tmp/wlbench_XXXX)
    if ! emit_src "$WL" > "$WORK"; then rm -f "$WORK" "$BIN"; exit 1; fi
    cc -O2 -o "$BIN" "$WORK"

    echo "Running $REPEATS x ${DURATION}s ($WL) throughput measurements..."
    for r in $(seq 1 "$REPEATS"); do
        ops=$("$BIN" "$DURATION")
        echo "$COND,$WL,$r,$ops" >> "$OUT"
        echo "  [$COND/$WL] repeat $r: $ops ops/sec"
    done
    rm -f "$WORK" "$BIN"
    echo ""
done

echo "Appended to $OUT. After all three conditions (baseline/ebpf/auditd):"
echo "  python3 analysis/score.py --workload $OUT"
