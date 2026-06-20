#!/usr/bin/env bash
# =============================================================================
# run_lang_eval.sh -- language-comparison study (todo/plan_lang_rewrite.md).
# -----------------------------------------------------------------------------
# Replays one recorded event stream through BOTH the Python and the Go
# correlation engine and measures:
#   Phase 1  detection PARITY  -- identical alerts in/out (the validity control)
#   Phase 2  user-space OVERHEAD -- RSS + CPU at matched event rates
#
# The eBPF data plane is NOT involved: it is in-kernel C, language-neutral, so
# the fair comparison is of the user-space engine alone. Neither replay needs
# root. Reuses experiments/footprint_sample.sh for sampling and analysis/
# score.py for ground-truth scoring, exactly as the rest of the thesis does.
#
# Prereqs:
#   - results/events.jsonl  (record with experiments/lang/capture_stream.sh)
#   - go binary             (build with experiments/lang/build_go.sh)
#
# Usage:
#   STREAM=results/events.jsonl DUR=120 RATES="40 368" \
#       ./experiments/lang/run_lang_eval.sh
# =============================================================================
set -uo pipefail
HERE=$(cd "$(dirname "$0")"/../.. && pwd)

STREAM="${STREAM:-results/events.jsonl}"
DUR="${DUR:-120}"
RATES="${RATES:-40 368}"
RESULTS_DIR="${RESULTS_DIR:-results_lang}"
GROUND_TRUTH="${GROUND_TRUTH:-results/ground_truth.jsonl}"
GO_BIN="${GO_BIN:-$HERE/go_agent/langagent}"
SETTLE="${SETTLE:-2}"
POD_CIDR="${POD_CIDR:-10.42.0.0/16}"
SVC_CIDR="${SVC_CIDR:-10.43.0.0/16}"
KUBE_API="${KUBE_API:-10.43.0.1}"

mkdir -p "$RESULTS_DIR"
[ -f "$STREAM" ] || { echo "ERROR: stream '$STREAM' not found (record it with experiments/lang/capture_stream.sh)"; exit 1; }
[ -x "$GO_BIN" ] || { echo "ERROR: go binary '$GO_BIN' missing (build it with experiments/lang/build_go.sh)"; exit 1; }

PY_BASE=(python3 "$HERE/src/ebpf_agent.py" --replay "$STREAM" --pod-cidr "$POD_CIDR" --svc-cidr "$SVC_CIDR" --kube-api "$KUBE_API")
GO_BASE=("$GO_BIN" --replay "$STREAM" --pod-cidr "$POD_CIDR" --svc-cidr "$SVC_CIDR" --kube-api "$KUBE_API")

echo "############ Phase 1: detection parity (single pass, max rate) ############"
"${PY_BASE[@]}" --metrics "$RESULTS_DIR/alerts_python.jsonl" --summary-out "$RESULTS_DIR/summary_python.json" >/dev/null
"${GO_BASE[@]}" --metrics "$RESULTS_DIR/alerts_go.jsonl"     --summary-out "$RESULTS_DIR/summary_go.json"     >/dev/null
python3 "$HERE/analysis/lang_compare.py" --parity "$RESULTS_DIR/alerts_python.jsonl" "$RESULTS_DIR/alerts_go.jsonl"
PARITY_RC=$?
if [ -f "$GROUND_TRUTH" ]; then
    echo "--- score.py: Python replay vs ground truth ---"
    python3 "$HERE/analysis/score.py" "$RESULTS_DIR/alerts_python.jsonl" "$GROUND_TRUTH" 2>/dev/null || true
    echo "--- score.py: Go replay vs ground truth ---"
    python3 "$HERE/analysis/score.py" "$RESULTS_DIR/alerts_go.jsonl" "$GROUND_TRUTH" 2>/dev/null || true
else
    echo "(no $GROUND_TRUTH -- skipping ground-truth scoring; parity check above is the key control)"
fi

echo ""
echo "############ Phase 2: overhead (RSS/CPU) at rates: $RATES ############"
for rate in $RATES; do
    for eng in python go; do
        echo ">>> $eng @ ${rate} ev/s for ${DUR}s"
        if [ "$eng" = python ]; then
            "${PY_BASE[@]}" --metrics /dev/null --rate "$rate" --loop 1000000 >/dev/null 2>&1 &
        else
            "${GO_BASE[@]}" --metrics /dev/null --rate "$rate" --loop 1000000 >/dev/null 2>&1 &
        fi
        APID=$!
        sleep "$SETTLE"
        if ! kill -0 "$APID" 2>/dev/null; then
            echo "  WARN: $eng exited early (stream too short to sustain ${DUR}s?)"; continue
        fi
        PID="$APID" RESULTS_DIR="$RESULTS_DIR/${eng}_${rate}" DURATION="$DUR" \
            bash "$HERE/experiments/footprint_sample.sh" | tee "$RESULTS_DIR/footprint_${eng}_${rate}.txt"
        kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null
    done
done

echo ""
echo "############ Aggregate ############"
python3 "$HERE/analysis/lang_compare.py" --aggregate "$RESULTS_DIR" --rates "$RATES" \
    --out "$RESULTS_DIR/metrics_lang.json"
echo "Done -> $RESULTS_DIR/metrics_lang.json"
[ "${PARITY_RC:-0}" -eq 0 ] || echo "WARNING: detection parity FAILED -- investigate before reporting overhead."
