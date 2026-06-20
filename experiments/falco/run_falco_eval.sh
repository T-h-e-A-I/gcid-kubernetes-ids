#!/bin/bash
# =============================================================================
# run_falco_eval.sh -- Task 2.1: run the SAME 7 scenarios through Falco
# -----------------------------------------------------------------------------
# Drives the existing attack scenarios (E1-E4, L1, L2) with Falco capturing, then
# converts Falco's events into the project alert schema and scores them with the
# SAME analysis/score.py against the SAME ground truth -- producing a SEPARATE
# eBPF-vs-Falco detection table (metrics_detection_falco.json), never merged into
# the auditd table.
#
# Prereqs:
#   - Falco installed + running (./experiments/falco/install_falco.sh), writing
#     JSON to $FALCO_LOG (default /var/log/falco/events.json).
#   - k3s + Online Boutique + attacker manifests provisioned (setup_env.sh).
#   - The eBPF agent does NOT need to be running (this measures Falco).
#
# Usage:
#   TRIALS=10 ./experiments/falco/run_falco_eval.sh
#   # one anchor data point is also defensible:  TRIALS=3 ...
#
# Env:
#   TRIALS      attack trials per scenario      (default 10)
#   FALCO_LOG   Falco JSON events file          (default /var/log/falco/events.json)
#   RESULTS_DIR output dir for this run         (default results_falco)
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TRIALS="${TRIALS:-10}"
FALCO_LOG="${FALCO_LOG:-/var/log/falco/events.json}"
RESULTS_DIR="${RESULTS_DIR:-results_falco}"
mkdir -p "$RESULTS_DIR"

EVENTS_SNAP="$RESULTS_DIR/falco_events.json"
ALERTS="$RESULTS_DIR/alerts_falco.jsonl"
GT="$RESULTS_DIR/ground_truth.jsonl"

echo "================================================================"
echo " Falco head-to-head (Task 2.1)"
echo "   trials/scenario : $TRIALS"
echo "   Falco log       : $FALCO_LOG"
echo "   results dir     : $RESULTS_DIR"
echo "================================================================"

# ---- sanity: Falco running + log writable ----------------------------------
if ! pgrep -x falco >/dev/null 2>&1; then
    echo "[warn] no 'falco' process found. Start it first:"
    echo "       sudo ./experiments/falco/install_falco.sh   (or: systemctl start falco-modern-bpf)"
fi
if [ ! -e "$FALCO_LOG" ]; then
    echo "ERROR: Falco log $FALCO_LOG not found. Check file_output in falco.yaml,"
    echo "       or pass FALCO_LOG=<path> (DaemonSet logs differ)." >&2
    exit 1
fi

# Mark our start offset in the Falco log so we only convert events from THIS run
# (avoids picking up earlier benign events on a long-lived log).
START_LINES=$(wc -l < "$FALCO_LOG" 2>/dev/null || echo 0)
echo "[info] Falco log currently has $START_LINES lines; capturing new events from here."

# ---- run the SAME orchestrator (writes $RESULTS_DIR/ground_truth.jsonl) ------
# run_evaluation.sh tries to SIGUSR1 the eBPF agent to reset state; with no agent
# running that simply no-ops (it warns and continues) -- fine, Falco is stateless
# across trials so it needs no reset.
echo ""
echo "=== Driving E1-E4, L1, L2 x $TRIALS trials (Falco capturing) ==="
FRESH=1 RESULTS_DIR="$RESULTS_DIR" TRIALS="$TRIALS" bash "$ROOT/experiments/run_evaluation.sh"

# ---- snapshot ONLY this run's Falco events ---------------------------------
echo ""
echo "=== Snapshotting Falco events for this run -> $EVENTS_SNAP ==="
tail -n +"$((START_LINES + 1))" "$FALCO_LOG" > "$EVENTS_SNAP"
echo "  captured $(wc -l < "$EVENTS_SNAP") Falco events"

# ---- convert + score with the SAME pipeline --------------------------------
echo ""
echo "=== Converting Falco events -> $ALERTS ==="
python3 "$ROOT/analysis/falco_adapter.py" "$EVENTS_SNAP" --out "$ALERTS"

echo ""
echo "=== Scoring (separate eBPF-vs-Falco detection table) ==="
python3 "$ROOT/analysis/score.py" "$ALERTS" "$GT"

echo ""
echo "================================================================"
echo " Done. Artifacts (SEPARATE from the auditd results):"
echo "   $ALERTS"
echo "   $GT"
echo "   $EVENTS_SNAP"
echo "   results/metrics_detection_falco.json   (E2 row -> 0.0 = the headline)"
echo "   results/fig_detection_falco.png"
echo ""
echo " Expectation: E1/E2b/E3/E4 detected; E2 (token-exfil chain) MISSED by"
echo " Falco; L1/L2 only if the idiomatic outbound rule fired. Compare against"
echo " results/metrics_detection.json (this work) for the Ch.6 eBPF-vs-Falco table."
echo "================================================================"
