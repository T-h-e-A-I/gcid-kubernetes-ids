#!/bin/bash
# =============================================================================
# bench_falco_overhead.sh -- Task 2.1: agent footprint, eBPF agent vs Falco
# -----------------------------------------------------------------------------
# Same macro methodology as experiments/benchmark_overhead.sh, but the comparator
# is the FALCO process (host install) instead of the auditd agent. Produces a
# SEPARATE result (metrics_overhead_falco.json) so the eBPF-vs-auditd table is
# untouched.
#
# Honesty note: Falco's modern_ebpf data plane is mature; we are NOT claiming to
# beat it on raw data-plane cost. This contextualizes the agent footprint; the
# thesis differentiator is the correlation layer (see docs/COMPARISON_METHODOLOGY.md).
#
# Prereqs (run simultaneously, profiled under the same syscall flood):
#   - Terminal A: sudo python3 src/ebpf_agent.py --metrics /dev/null ...
#   - Falco running as a host service (./experiments/falco/install_falco.sh)
#   - Terminal B: ./experiments/falco/bench_falco_overhead.sh
#
# Score (note the SECOND file 'falco' drives the separate output name):
#   python3 analysis/score.py --overhead \
#       results/overhead_ebpf_cpu.txt results/overhead_falco_cpu.txt
#   -> results/metrics_overhead_falco.json + results/fig_overhead_falco.png
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
SAMPLES="${SAMPLES:-60}"
mkdir -p "$RESULTS_DIR"

echo "=== Deploying a noisy syscall generator pod ==="
kubectl run noise-generator --image=busybox --restart=Never -- \
    /bin/sh -c "for i in 1 2 3 4 5 6 7 8; do (while true; do /bin/true; done) & done; wait" || true
kubectl wait --for=condition=Ready pod/noise-generator --timeout=60s || true

# eBPF agent: the python3 interpreter (not the sudo wrapper) -- see P0-C.
EBPF_PID=$(ps -C python3 -o pid=,args= | awk '/ebpf_agent\.py/{print $1; exit}')
# Falco: the host daemon process.
FALCO_PID=$(pgrep -x falco | tail -1)

if [ -z "$EBPF_PID" ] || [ -z "$FALCO_PID" ]; then
    echo "ERROR: need BOTH the eBPF agent and falco running."
    echo "  ebpf_agent.py PID = '$EBPF_PID'"
    echo "  falco PID         = '$FALCO_PID'  (host install? 'systemctl status falco')"
    echo "  If Falco runs as a k8s DaemonSet, profile its container instead, or"
    echo "  reinstall as a host package: ./experiments/falco/install_falco.sh"
    kubectl delete pod noise-generator --wait=false 2>/dev/null || true
    exit 1
fi
for p in "$EBPF_PID" "$FALCO_PID"; do
    c=$(cat /proc/"$p"/comm 2>/dev/null); echo "  PID $p comm=$c"
done

echo "eBPF agent PID : $EBPF_PID"
echo "falco PID      : $FALCO_PID"
echo "Sampling ${SAMPLES}s of CPU (%) and RSS (KB) for both..."

# Fine-grained per-second %CPU from /proc/<pid>/stat (sub-1% resolution; pidstat
# rounds sub-1% to 0.00). Identical sampler to benchmark_overhead.sh.
CLK=$(getconf CLK_TCK)
cpu_ticks() {
    local s; s=$(< /proc/"$1"/stat)
    s=${s##*) }; set -- $s
    echo $(( ${12} + ${13} ))
}
sample_cpu() {
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
sample_cpu "$FALCO_PID" "$RESULTS_DIR/overhead_falco_cpu.txt" &
pidstat -r -p "$EBPF_PID"  1 "$SAMPLES" > "$RESULTS_DIR/overhead_ebpf_mem.txt"  &
pidstat -r -p "$FALCO_PID" 1 "$SAMPLES" > "$RESULTS_DIR/overhead_falco_mem.txt" &
wait

echo "=== Cleaning up ==="
kubectl delete pod noise-generator --wait=false 2>/dev/null || true
echo "Per-second %CPU -> $RESULTS_DIR/overhead_{ebpf,falco}_cpu.txt"
echo "Score (separate from auditd):"
echo "  python3 analysis/score.py --overhead $RESULTS_DIR/overhead_ebpf_cpu.txt $RESULTS_DIR/overhead_falco_cpu.txt"
