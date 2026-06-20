#!/bin/bash
# =============================================================================
# bench_traffic_impact.sh -- Experiment B (macro): legitimate-traffic impact
# -----------------------------------------------------------------------------
# Measures how much each monitoring approach degrades the THROUGHPUT and LATENCY
# of legitimate application traffic -- the Online Boutique frontend -- under load.
# This is the SLO "legitimate-traffic throughput degradation <= 2%" measurement.
#
# Unlike the synthetic per-syscall microbench (bench_workload_overhead.sh), this
# exercises the REAL workload: the boutique microservices serve HTTP/gRPC, and
# every syscall they make (accept/read/write/openat/connect between services) is
# what the system-wide eBPF/auditd monitoring taxes. The slowdown therefore shows
# up as reduced frontend requests/sec and increased tail latency.
#
# Three conditions (you set each up yourself, as with the other macro benches):
#   baseline : no agent running, no audit rules loaded
#   ebpf     : src/ebpf_agent.py running in another terminal (audit rules OFF)
#   auditd   : broad audit rules loaded + src/auditd_agent.py running (eBPF OFF)
#
# Usage:  bench_traffic_impact.sh <condition>
#   sudo auditctl -D                                   # baseline
#   ./experiments/bench_traffic_impact.sh baseline
#   # (eBPF agent running, audit off)
#   ./experiments/bench_traffic_impact.sh ebpf
#   # (audit rules loaded + auditd agent running)
#   ./experiments/bench_traffic_impact.sh auditd
#   python3 analysis/score.py --traffic results/traffic_impact.csv
#
# Env overrides:
#   FRONTEND_URL  full URL to hit (default: resolve the `frontend` ClusterIP:port)
#   DURATION      seconds per measurement   (default 30)
#   CONCURRENCY   concurrent connections    (default 50)
#   REPEATS       measurements per run      (default 5)
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-results}"
COND="${1:-${CONDITION:-unlabeled}}"
DURATION="${DURATION:-30}"
CONCURRENCY="${CONCURRENCY:-50}"
REPEATS="${REPEATS:-5}"
mkdir -p "$RESULTS_DIR"
# OUT is overridable so a separate comparator (e.g. Falco) collects into its OWN
# CSV (traffic_impact_falco.csv) and scores into its own table, leaving the
# eBPF-vs-auditd result untouched (the scorer derives the name from this file).
OUT="${OUT:-$RESULTS_DIR/traffic_impact.csv}"
HDR="condition,repeat,rps,p50_ms,p95_ms"
if [ ! -f "$OUT" ]; then
    echo "$HDR" > "$OUT"
elif [ "$(head -n1 "$OUT")" != "$HDR" ]; then
    echo "  [warn] fixing stale CSV header in $OUT -> $HDR"
    sed -i "1s|.*|$HDR|" "$OUT"
fi

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# ---- resolve the boutique frontend URL -------------------------------------
if [ -z "${FRONTEND_URL:-}" ]; then
    CIP=$(kubectl get svc frontend -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    PORT=$(kubectl get svc frontend -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
    if [ -z "$CIP" ] || [ "$CIP" = "None" ]; then
        echo "ERROR: could not resolve the 'frontend' service ClusterIP."
        echo "       Set FRONTEND_URL=http://<ip>:<port> explicitly, or check:"
        echo "       kubectl get svc frontend"
        exit 1
    fi
    FRONTEND_URL="http://$CIP:${PORT:-80}/"
fi

# ---- ensure a load generator is available ----------------------------------
# Preference order:
#   1. wrk  -- C, apt-installable, reliably saturates the service (preferred).
#   2. hey  -- Go binary that also reports a p95 percentile; used only if it is
#              already on PATH or cached, or can be fetched from its GitHub
#              release (the old S3 mirror now 403s, so we do NOT rely on it).
# We measure RPS (the SLO metric) identically with either tool; only the tail-
# latency percentile differs (hey -> true p95; wrk -> p90 reported in that slot).
WRK="$(command -v wrk || true)"
HEY="$(command -v hey || true)"
if [ -z "$HEY" ] && [ -x "$RESULTS_DIR/.hey" ]; then HEY="$RESULTS_DIR/.hey"; fi
# Only attempt a hey download if NEITHER tool is present (wrk is the easy path).
if [ -z "$WRK" ] && [ -z "$HEY" ]; then
    CACHE="$RESULTS_DIR/.hey"
    echo "  no load generator found; attempting hey download -> $CACHE"
    if curl -fsSL -o "$CACHE" \
        https://github.com/rakyll/hey/releases/download/v0.1.4/hey_linux_amd64 \
        && chmod +x "$CACHE"; then
        HEY="$CACHE"
    else
        rm -f "$CACHE"
        echo "ERROR: no load generator and hey download failed. Install wrk:"
        echo "       sudo apt-get install -y wrk"
        echo "   (or put a 'hey' binary on PATH / at $RESULTS_DIR/.hey)"
        exit 1
    fi
fi
# Prefer wrk when both exist (more reliable saturation).
USE_HEY=""; [ -n "$HEY" ] && [ -z "$WRK" ] && USE_HEY=1

# ---- sanity: report the monitoring state actually in effect ----------------
echo "=== Condition: $COND | Target: $FRONTEND_URL ==="
pgrep -f "python3 .*ebpf_agent.py"   >/dev/null \
    && echo "  eBPF agent   : RUNNING" || echo "  eBPF agent   : not running"
pgrep -f "python3 .*auditd_agent.py" >/dev/null \
    && echo "  auditd agent : RUNNING" || echo "  auditd agent : not running"
pgrep -x falco >/dev/null \
    && echo "  falco        : RUNNING" || echo "  falco        : not running"
if sudo auditctl -l 2>/dev/null | grep -qE "S (execve|openat|open|connect)"; then
    echo "  audit rules  : $(sudo auditctl -l 2>/dev/null | grep -oE 'S [a-z]+' | tr '\n' ' ')"
else
    echo "  audit rules  : none"
fi
echo "  load tool    : $([ -n "$USE_HEY" ] && echo "$HEY (hey)" || echo "$WRK (wrk)")"
echo ""

# ---- warm-up (fill caches / JIT the services) ------------------------------
echo "Warming up the frontend for 5s..."
if [ -n "$USE_HEY" ]; then "$HEY" -z 5s -c "$CONCURRENCY" "$FRONTEND_URL" >/dev/null 2>&1
else "$WRK" -d5s -c"$CONCURRENCY" -t4 "$FRONTEND_URL" >/dev/null 2>&1; fi

# ---- node-wide CPU sampler -------------------------------------------------
# Reports the node's mean CPU busy% DURING each load run, so you can tell
# whether the services are CPU-bound (the regime where monitoring overhead
# actually shows). If baseline CPU is well below 100%, the workload is
# latency/fan-out-bound and you must raise CONCURRENCY for a meaningful result.
# Printed to stdout only -- CSV schema is unchanged (the scorer ignores it).
_cpu_snapshot() { awk '/^cpu /{idle=$5+$6; tot=0; for(i=2;i<=NF;i++) tot+=$i;
                       print tot, idle}' /proc/stat; }
_cpu_busy_pct() {  # args: "tot0 idle0" "tot1 idle1"
    awk -v a="$1" -v b="$2" 'BEGIN{split(a,x);split(b,y);
        dt=y[1]-x[1]; di=y[2]-x[2];
        printf "%.1f", (dt>0)?100*(1-di/dt):0}'; }

# ---- run REPEATS measurements ----------------------------------------------
echo "Running $REPEATS x ${DURATION}s load tests (c=$CONCURRENCY)..."
for r in $(seq 1 "$REPEATS"); do
    C0="$(_cpu_snapshot)"
    if [ -n "$USE_HEY" ]; then
        TMP=$(mktemp)
        "$HEY" -z "${DURATION}s" -c "$CONCURRENCY" "$FRONTEND_URL" > "$TMP" 2>&1
        # hey output: "Requests/sec: 1234.5" and a "  50% in 0.0123 secs" table.
        rps=$(grep -oE 'Requests/sec:[[:space:]]+[0-9.]+' "$TMP" | grep -oE '[0-9.]+$')
        p50=$(awk '/ 50% in /{printf "%.1f", $3*1000}' "$TMP")
        p95=$(awk '/ 95% in /{printf "%.1f", $3*1000}' "$TMP")
        rm -f "$TMP"
    else
        # wrk fallback: --latency gives a percentile table (50/75/90/99, no 95).
        TMP=$(mktemp)
        "$WRK" -d"${DURATION}s" -c"$CONCURRENCY" -t4 --latency "$FRONTEND_URL" > "$TMP" 2>&1
        rps=$(awk '/Requests\/sec:/{print $2}' "$TMP")
        # convert wrk latency (e.g. "12.34ms"/"1.20s") to ms
        to_ms() { echo "$1" | awk '/s$/&&!/ms$/{sub(/s/,"");print $1*1000;next}{sub(/ms/,"");print $1}'; }
        p50=$(to_ms "$(awk '/^[[:space:]]*50%/{print $2}' "$TMP")")
        p95=$(to_ms "$(awk '/^[[:space:]]*90%/{print $2}' "$TMP")")  # 90% (wrk has no 95)
        rm -f "$TMP"
    fi
    cpu=$(_cpu_busy_pct "$C0" "$(_cpu_snapshot)")
    rps="${rps:-0}"; p50="${p50:-0}"; p95="${p95:-0}"
    echo "$COND,$r,$rps,$p50,$p95" >> "$OUT"
    echo "  [$COND] repeat $r: ${rps} req/s  p50=${p50}ms  p95=${p95}ms  nodeCPU=${cpu}%"
done

echo ""
echo "Appended to $OUT. After all three conditions (baseline/ebpf/auditd):"
echo "  python3 analysis/score.py --traffic $OUT"
