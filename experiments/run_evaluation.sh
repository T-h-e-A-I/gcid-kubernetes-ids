#!/bin/bash
# =============================================================================
# run_evaluation.sh -- Experiment A (detection effectiveness), repeated trials
# -----------------------------------------------------------------------------
# Runs a benign baseline (for FPR) followed by N independent trials of every
# attack scenario, and collects the agent's alerts + per-trial ground truth so
# analysis/score.py can report ADR / FPR / latency as mean +/- std over trials
# (CODAX 10-trial protocol -- see Roadmap/improvement-plan.md section 4).
#
# Independence between trials (essential -- see improvement plan):
#   - each attack script DELETES + RECREATES its pods, so every trial gets fresh
#     PIDs / cgroups; and
#   - we send SIGUSR1 to the agent between trials, which clears its BoSC windows,
#     dependency graph, token state and dedup table (DetectionEngine.reset_state).
#
# CHECKPOINT / RESUME (for large N, crash-safe):
#   Progress is recorded step-by-step in $RESULTS_DIR/run_state.txt. Each step
#   (the benign baseline, and each trial's escape/lateral phase) is marked done
#   only AFTER it completes, and its ground-truth records are staged in a temp
#   file and committed atomically on success. If the run is interrupted (Ctrl+C,
#   crash, VM reboot), just re-run this script: it skips already-completed steps
#   and continues from the midpoint. Ground truth is NOT re-truncated on resume.
#     - To start over cleanly:            FRESH=1 ./experiments/run_evaluation.sh
#     - To raise N and keep prior trials: TRIALS=30 ./experiments/run_evaluation.sh
#       (trials 1..done are skipped; only the new ones run).
#
#   IMPORTANT: if the AGENT also died, restart it with --append so prior alerts
#   are preserved (see RUNBOOK Experiment A). If only this script died and the
#   agent kept running, no agent action is needed.
#
# The agent runs in a separate terminal (cleaner profiling). Start it with:
#   sudo python3 src/ebpf_agent.py --metrics results/alerts.jsonl \
#        --pod-cidr <PodCIDR> --svc-cidr 10.43.0.0/16 --graph-out results/graph.json
# Then run this script. Score with:
#   python3 analysis/score.py results/alerts.jsonl results/ground_truth.jsonl
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
TRIALS="${TRIALS:-10}"
BENIGN_SECONDS="${BENIGN_SECONDS:-120}"
mkdir -p "$RESULTS_DIR"
GROUND_TRUTH="$RESULTS_DIR/ground_truth.jsonl"   # canonical (committed) GT
STATE="$RESULTS_DIR/run_state.txt"               # checkpoint of completed steps
HERE="$(dirname "$0")"

# ---- checkpoint helpers -----------------------------------------------------
mark_done() { echo "$1" >> "$STATE"; }
is_done()   { [ -f "$STATE" ] && grep -qxF "$1" "$STATE"; }

# Run one attack script as an ATOMIC, RESUMABLE step:
#   $1 = step id (e.g. t3_escape)   $2 = script path
# Ground truth is written to a temp file and only appended to the canonical
# ground_truth.jsonl (and the step marked done) AFTER the script returns, so a
# crash mid-step leaves no half-written ground truth -- the step simply re-runs.
run_step() {
    local id="$1" script="$2"
    if is_done "$id"; then
        echo "[resume] skipping completed step: $id"
        return 0
    fi
    local tmp_gt; tmp_gt="$(mktemp "${TMPDIR:-/tmp}/gt_${id}.XXXXXX")"
    local rc=0
    GROUND_TRUTH="$tmp_gt" bash "$script" || rc=$?
    if [ "$rc" -ne 0 ]; then
        # Script aborted (non-zero). Discard its staged ground truth and leave
        # the step UNMARKED so a later resume re-runs it cleanly (pods are
        # recreated per trial, so re-running is always safe/idempotent).
        echo "[warn] step $id failed (rc=$rc) -> not committed; will re-run on resume."
        rm -f "$tmp_gt"
        return 0           # keep going (other scenarios are independent)
    fi
    cat "$tmp_gt" >> "$GROUND_TRUTH"      # commit this step's ground truth
    rm -f "$tmp_gt"
    mark_done "$id"
}

# ---- fresh vs resume --------------------------------------------------------
if [ "${FRESH:-0}" = "1" ]; then
    echo "[fresh] FRESH=1 -> clearing checkpoint + ground truth for a new run."
    rm -f "$STATE"
fi
if [ -s "$STATE" ]; then
    RESUMING=1
    echo "[resume] checkpoint found ($(grep -cvE '^#' "$STATE") steps done) -> continuing."
else
    RESUMING=0
    : > "$GROUND_TRUTH"                   # fresh ground truth ONLY on a new run
    : > "$STATE"
    echo "# Experiment A run started $(date) trials=$TRIALS" >> "$STATE"
fi

# Locate the python agent (not the sudo wrapper) so we can signal it to reset.
agent_pid() { ps -C python3 -o pid=,args= | awk '/ebpf_agent\.py/{print $1; exit}'; }
AGENT_PID="$(agent_pid || true)"
if [ -z "$AGENT_PID" ]; then
    echo "[warn] eBPF agent (python3 ebpf_agent.py) not found running."
    echo "       Start it in another terminal first; continuing anyway."
    echo "       (On resume after an agent crash, restart it with --append.)"
fi

echo "================================================================"
echo " Experiment A: Detection Effectiveness"
echo "   trials per scenario : $TRIALS"
echo "   benign baseline (s) : $BENIGN_SECONDS"
echo "   agent PID           : ${AGENT_PID:-<not found>}"
echo "   ground truth        : $GROUND_TRUTH"
echo "   checkpoint          : $STATE  (resume=$RESUMING)"
echo "================================================================"
[ "$RESUMING" = "1" ] || read -p "Press Enter to begin the benign baseline phase..."

FRONTEND_IP=$(kubectl get svc frontend -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
benign_hit() { [ -n "$FRONTEND_IP" ] && curl -s "http://$FRONTEND_IP:80/" >/dev/null 2>&1 || true; }

# ---- Phase 1: benign baseline (no attacks) -> FPR denominator ---------------
# Skipped on resume: the baseline is needed once, and re-running it would not
# add benign-phase data the agent has already recorded.
if is_done benign; then
    echo ""
    echo "[resume] skipping benign baseline (already done)."
else
    echo ""
    echo "=== Benign baseline: ${BENIGN_SECONDS}s of Online Boutique load ==="
    END=$((SECONDS + BENIGN_SECONDS))
    while [ $SECONDS -lt $END ]; do benign_hit; sleep 0.5; done
    echo "Benign baseline complete."
    mark_done benign
fi

# ---- Phase 2: N independent attack trials -----------------------------------
# Keep a light benign load running in the background for realism (attacks are
# detected amid normal traffic, not on a quiet channel).
( while true; do benign_hit; sleep 0.7; done ) & BENIGN_BG=$!
trap 'kill $BENIGN_BG 2>/dev/null || true' EXIT

for t in $(seq 1 "$TRIALS"); do
    export TRIAL="$t"
    if is_done "t${t}_escape" && is_done "t${t}_lateral"; then
        echo "################## TRIAL $t / $TRIALS -- already done, skipping ##"
        continue
    fi
    echo ""
    echo "################## TRIAL $t / $TRIALS ##################"
    # Reset agent detection state so this trial is independent of the last.
    # (Done at the START of a trial; if resuming mid-trial at the lateral phase,
    #  the escape phase already ran, so we only reset when (re)starting escape.)
    if ! is_done "t${t}_escape"; then
        AGENT_PID="$(agent_pid || true)"
        if [ -n "$AGENT_PID" ]; then
            kill -USR1 "$AGENT_PID" && echo "[reset] sent SIGUSR1 to agent $AGENT_PID"
            sleep 0.5
        fi
    fi
    run_step "t${t}_escape"  "$HERE/attack_escape.sh"
    run_step "t${t}_lateral" "$HERE/attack_lateral.sh"
done

kill $BENIGN_BG 2>/dev/null || true
trap - EXIT

echo ""
echo "================================================================"
echo " Done: $TRIALS trials x 6 scenarios (checkpoint: $STATE)."
echo " Stop the agent (Ctrl+C) to flush metrics + graph, then score:"
echo "   python3 analysis/score.py $RESULTS_DIR/alerts.jsonl $GROUND_TRUTH"
echo ""
echo " To run MORE trials later, re-run with a higher TRIALS (prior trials are"
echo " skipped):   TRIALS=$((TRIALS + 10)) $0"
echo " To start over:  FRESH=1 $0"
echo "================================================================"
