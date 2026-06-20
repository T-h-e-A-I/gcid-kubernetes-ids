#!/bin/bash
# =============================================================================
# run_full_clean.sh -- authoritative N=100 re-run on the A7-corrected setup
# -----------------------------------------------------------------------------
# Self-contained: ensures Falco is stopped, starts the (namespace-aware) eBPF
# agent, runs the full FRESH N=100 evaluation with a long benign window (B4),
# stops the agent, and scores -> one coherent, reproducible archive that
# resolves A6 (provenance), A2 (FPR denominator from the SAME run), B4 (tight
# FPR CI) and A7 (genuine cross-namespace lateral). Crash-safe via
# run_evaluation.sh checkpoint/resume.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft

# Env-overridable so the same script drives a quick 2h run or a full-day run:
#   TRIALS           trials per scenario (default 100)
#   BENIGN_SECONDS   benign baseline length for FPR CI (default 600)
#   DIR              output archive dir (default results/run_<date>)
TRIALS="${TRIALS:-100}"
BENIGN_SECONDS="${BENIGN_SECONDS:-600}"
DIR="${DIR:-results/run_$(date +%Y%m%d)}"
mkdir -p "$DIR"
# kubectl needs an explicit kubeconfig under systemd (no login env).
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
# Under systemd we already run as root -> no sudo needed (and sudo without a tty
# can fail). Interactively (non-root) keep sudo.
if [ "$(id -u)" = "0" ]; then SUDO=""; else SUDO="sudo"; fi
POD_CIDR=$(kubectl get node ubuntu-s-4vcpu-8gb-blr1 -o jsonpath='{.spec.podCIDR}')

echo "[$(date +%T)] ensuring leftover Falco is stopped (A7 contamination)"
$SUDO systemctl stop falco-modern-bpf.service falcoctl-artifact-follow.service 2>/dev/null || true

# Preserve the current canonical detection/FPR metrics before scoring overwrites
# them (raw provenance already lives in results/archive_2026*).
for f in metrics_detection.json metrics_fpr.json; do
    [ -f "results/$f" ] && cp "results/$f" "results/${f%.json}.pre_run20260617.bak"
done

echo "[$(date +%T)] starting namespace-aware agent -> $DIR"
# Pass PATH + KUBECONFIG THROUGH sudo so the agent's in-process kubectl
# (PodResolver._refresh_ipns -> IP->namespace map for cross-ns suppression)
# works under a clean systemd environment, not just an interactive login.
$SUDO env "PATH=$PATH" "KUBECONFIG=$KUBECONFIG" python3 src/ebpf_agent.py \
    --metrics "$DIR/alerts.jsonl" \
    --record-events "$DIR/events.jsonl" --summary-out "$DIR/summary.json" \
    --graph-out "$DIR/graph.json" \
    --pod-cidr "$POD_CIDR" --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
for i in $(seq 1 40); do grep -qi "Listening" "$DIR/agent.log" 2>/dev/null && break; sleep 2; done
echo "[$(date +%T)] agent attached; launching N=$TRIALS evaluation (${BENIGN_SECONDS}s benign)"

FRESH=1 TRIALS="$TRIALS" BENIGN_SECONDS="$BENIGN_SECONDS" RESULTS_DIR="$DIR" \
    ./experiments/run_evaluation.sh > "$DIR/eval.log" 2>&1
EVAL_RC=$?

echo "[$(date +%T)] evaluation finished (rc=$EVAL_RC); stopping agent"
$SUDO pkill -INT -f "ebpf_agent.py" 2>/dev/null || true
sleep 6

echo "[$(date +%T)] scoring (detection + FPR from the SAME run)"
python3 analysis/score.py "$DIR/alerts.jsonl" "$DIR/ground_truth.jsonl" \
    --events "$DIR/events.jsonl" --benign-window "$BENIGN_SECONDS" > "$DIR/score.log" 2>&1
# Also stage a copy of the run's metrics inside the run dir for provenance.
cp results/metrics_detection.json "$DIR/metrics_detection.json" 2>/dev/null || true

echo "[$(date +%T)] DONE" | tee "$DIR/COMPLETE"
