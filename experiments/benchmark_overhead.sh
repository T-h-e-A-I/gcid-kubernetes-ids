#!/bin/bash
# =============================================================================
# benchmark_overhead.sh -- Experiment B (macro): agent CPU/memory overhead
# -----------------------------------------------------------------------------
# Compares the runtime resource footprint of the eBPF agent vs the auditd
# baseline agent under a noisy, syscall-heavy Kubernetes workload, using
# pidstat. Produces per-second samples written to CSV for analysis/score.py to
# aggregate (mean +/- std) and test for significance.
#
# Usage:
#   1. Terminal A: sudo python3 src/ebpf_agent.py   --metrics /dev/null
#   2. Terminal B: sudo python3 src/auditd_agent.py --metrics /dev/null
#   3. Terminal C: ./experiments/benchmark_overhead.sh
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
SAMPLES="${SAMPLES:-60}"        # seconds of sampling
mkdir -p "$RESULTS_DIR"

echo "=== Deploying a noisy syscall generator pod ==="
# Workload must generate events BOTH agents actually process, or the comparison
# is meaningless. An openat flood (`ls -laR`) does NOT work: the eBPF agent
# filters openat in-kernel and auditd has no openat rule, so both stay idle
# (first macro run: both ~0.1% CPU, p=0.11). An EXECVE flood is the right
# stressor: auditd's `-S execve` rule logs every exec -> its user-space parser
# does real work; the eBPF agent's execve probe filters non-shell execs
# in-kernel -> it stays ~0%. That contrast is exactly the thesis claim.
# This benchmark measures the AGENT'S OWN resource footprint (CPU/RSS). Under a
# non-shell execve flood the eBPF agent filters every event IN-KERNEL, so its
# user-space process stays at ~0% CPU -- which is the honest, favourable result:
# in-kernel filtering means the user-space agent does essentially no work. (The
# eBPF cost that DOES exist is the in-kernel probe, captured by the program-type
# micro-benchmark and the workload-throughput benchmark, not here.) This table
# is therefore a SECONDARY result (agent footprint); the primary overhead
# comparison is experiments/bench_workload_overhead.sh.
kubectl run noise-generator --image=busybox --restart=Never -- \
    /bin/sh -c "for i in 1 2 3 4 5 6 7 8; do (while true; do /bin/true; done) & done; wait" || true
kubectl wait --for=condition=Ready pod/noise-generator --timeout=60s || true

# Select the actual python3 interpreter PID, NOT the `sudo python3 ...` wrapper.
# `pgrep -f ebpf_agent.py` matches both (the sudo process cmdline also contains
# the script path); the wrapper has comm=sudo and ~0% CPU, so profiling it gave
# a bogus overhead number (plan P0-C). ps -C python3 restricts to the
# interpreter by command name, then awk picks the one running our script.
EBPF_PID=$(ps -C python3 -o pid=,args= | awk '/ebpf_agent\.py/{print $1; exit}')
AUDIT_PID=$(ps -C python3 -o pid=,args= | awk '/auditd_agent\.py/{print $1; exit}')

if [ -z "$EBPF_PID" ] || [ -z "$AUDIT_PID" ]; then
    echo "ERROR: could not find both agents running as python3."
    echo "  ebpf_agent.py PID  = '$EBPF_PID'"
    echo "  auditd_agent.py PID= '$AUDIT_PID'"
    kubectl delete pod noise-generator --wait=false 2>/dev/null || true
    exit 1
fi
# Sanity-check we picked python, not sudo.
for p in "$EBPF_PID" "$AUDIT_PID"; do
    c=$(cat /proc/"$p"/comm 2>/dev/null)
    [ "$c" = "python3" ] || echo "[warn] PID $p comm=$c (expected python3)"
done

echo "eBPF agent PID : $EBPF_PID"
echo "auditd agent PID: $AUDIT_PID"
echo "Sampling ${SAMPLES}s of CPU (%) and RSS (KB) for both agents..."

# Fine-grained per-second %CPU from /proc/<pid>/stat (utime+stime jiffies).
# pidstat's %CPU rounds sub-1% usage to 0.00, which floored the eBPF agent to a
# meaningless "0% / 100% reduction". Reading CPU *time* gives 0.001 resolution,
# so the eBPF agent's genuinely tiny (but non-zero) cost is captured.
CLK=$(getconf CLK_TCK)
cpu_ticks() {                       # echo utime+stime ticks for $1 (robust to
    local s; s=$(< /proc/"$1"/stat) # spaces in comm: strip up to ") ")
    s=${s##*) }; set -- $s          # remaining: state=$1 ... utime=${12} stime=${13}
    echo $(( ${12} + ${13} ))       # NB: ${12} not $12 (which is $1 followed by "2")
}
sample_cpu() {                      # $1=pid $2=outfile -> one %CPU/line for SAMPLES s
    local pid=$1 out=$2 prev cur i
    : > "$out"; prev=$(cpu_ticks "$pid")
    for ((i=0; i<SAMPLES; i++)); do
        sleep 1
        cur=$(cpu_ticks "$pid" 2>/dev/null || echo "$prev")
        awk -v d=$((cur - prev)) -v clk="$CLK" 'BEGIN{printf "%.3f\n",(d/clk)*100}' >> "$out"
        prev=$cur
    done
}
sample_cpu "$EBPF_PID"  "$RESULTS_DIR/overhead_ebpf_cpu.txt"  &
sample_cpu "$AUDIT_PID" "$RESULTS_DIR/overhead_auditd_cpu.txt" &
# Memory still via pidstat -r (RSS parsed fine).
pidstat -r -p "$EBPF_PID"  1 "$SAMPLES" > "$RESULTS_DIR/overhead_ebpf_mem.txt"  &
pidstat -r -p "$AUDIT_PID" 1 "$SAMPLES" > "$RESULTS_DIR/overhead_auditd_mem.txt" &
wait

echo "=== Cleaning up ==="
kubectl delete pod noise-generator --wait=false 2>/dev/null || true
echo "Per-second %CPU (fine-grained) -> $RESULTS_DIR/overhead_*_cpu.txt"
echo "Aggregate + significance test:"
echo "  python3 analysis/score.py --overhead $RESULTS_DIR/overhead_ebpf_cpu.txt $RESULTS_DIR/overhead_auditd_cpu.txt"
