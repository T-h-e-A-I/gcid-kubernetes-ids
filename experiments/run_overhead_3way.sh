#!/bin/bash
# Run the workload-overhead micro-benchmark for all THREE conditions in one
# sitting (baseline / eBPF / auditd) so the comparison is internally consistent,
# then score. Substantiates the paper's auditd-vs-eBPF overhead claim with our
# own number (P1 #6).
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
OUT=results/workload_overhead.csv
LOG=results/overhead_3way.log
: > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

# fresh CSV (back up the old one)
[ -f "$OUT" ] && cp "$OUT" "results/workload_overhead.pre3way_$(date +%Y%m%d).csv.bak"
rm -f "$OUT"

# ---- (a) baseline: no eBPF agent, no audit rules ----
log "BASELINE: clearing monitors"
pkill -INT -f "ebpf_agent.py" 2>/dev/null || true; sleep 3
auditctl -D >/dev/null 2>&1 || true
log "BASELINE: running bench"
./experiments/bench_workload_overhead.sh baseline >>"$LOG" 2>&1

# ---- (b) eBPF: agent attached, audit rules off ----
log "EBPF: starting agent"
auditctl -D >/dev/null 2>&1 || true
python3 src/ebpf_agent.py --metrics /dev/null \
    --pod-cidr 10.42.0.0/24 --svc-cidr 10.43.0.0/16 >results/overhead_ebpf_agent.log 2>&1 &
AGENT=$!
for i in $(seq 1 40); do bpftool prog show 2>/dev/null | grep -q syscall__openat && break; sleep 2; done
log "EBPF: agent attached (pid $AGENT); running bench"
./experiments/bench_workload_overhead.sh ebpf >>"$LOG" 2>&1
log "EBPF: stopping agent"
kill -INT "$AGENT" 2>/dev/null || true; sleep 4; kill -KILL "$AGENT" 2>/dev/null || true

# ---- (c) auditd: both rules loaded, eBPF off ----
log "AUDITD: loading rules"
auditctl -D >/dev/null 2>&1 || true
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor >/dev/null 2>&1 || true
auditctl -a always,exit -F arch=b64 -S openat -S open -k file_monitor >/dev/null 2>&1 || true
log "AUDITD: rules now: $(auditctl -l 2>/dev/null | tr '\n' ';')"
./experiments/bench_workload_overhead.sh auditd >>"$LOG" 2>&1
log "AUDITD: clearing rules"
auditctl -D >/dev/null 2>&1 || true

# ---- score ----
log "SCORING"
python3 analysis/score.py --workload "$OUT" >>"$LOG" 2>&1 || true
log "DONE"
echo "=== final CSV conditions ===" | tee -a "$LOG"
cut -d, -f1 "$OUT" | sort | uniq -c | tee -a "$LOG"
