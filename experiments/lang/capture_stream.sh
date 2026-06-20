#!/usr/bin/env bash
# =============================================================================
# capture_stream.sh -- record the post-filter event stream for the language
# study (todo/plan_lang_rewrite.md). Run on the VM (needs root + eBPF).
# -----------------------------------------------------------------------------
# This is just the LIVE agent with --record-events added, so the exact event
# stream the engine sees is dumped to results/events.jsonl. While this runs,
# drive the SAME Experiment-A workload+attacks in another terminal, e.g.:
#       RESULTS_DIR=results ./experiments/run_evaluation.sh
# Stop with Ctrl+C when the run completes. results/events.jsonl is then the
# byte-identical input replayed through both the Python and Go engines.
# =============================================================================
set -uo pipefail
HERE=$(cd "$(dirname "$0")"/../.. && pwd)
RESULTS_DIR="${RESULTS_DIR:-results}"; mkdir -p "$RESULTS_DIR"
POD_CIDR="${POD_CIDR:-10.42.0.0/16}"
SVC_CIDR="${SVC_CIDR:-10.43.0.0/16}"
KUBE_API="${KUBE_API:-10.43.0.1}"
echo "Recording post-filter events -> $RESULTS_DIR/events.jsonl"
echo "Now drive the workload+attacks in another terminal, then Ctrl+C here."
exec sudo python3 "$HERE/src/ebpf_agent.py" --no-enrich \
    --pod-cidr "$POD_CIDR" --svc-cidr "$SVC_CIDR" --kube-api "$KUBE_API" \
    --metrics "$RESULTS_DIR/alerts.jsonl" \
    --record-events "$RESULTS_DIR/events.jsonl" \
    --summary-out "$RESULTS_DIR/run_summary.json"
