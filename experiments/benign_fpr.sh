#!/bin/bash
# =============================================================================
# benign_fpr.sh -- Task 2.3: high-volume benign run to denominate the FPR (N_b)
# -----------------------------------------------------------------------------
# The "0% FPR" claim needs a denominator: N_b = the number of benign events the
# user-space detector ADJUDICATED. The eBPF agent's in-kernel filter makes benign
# steady-state traffic surface almost nothing (~0.08 events/s under light load),
# so a light/host-side benign run yields a tiny N_b and a useless rule-of-three
# bound (3/N_b). This driver fixes that the right way: it generates *filter-
# surviving* benign events FROM INSIDE A CONTAINER -- a tight service-account
# TOKEN-READ loop. Every token read passes the openat filter and is adjudicated,
# but never alerts (the token-exfil rule only fires if a Kube-API connect follows
# from the same cgroup, which never happens here). So a large N_b with 0 alerts is
# a genuine specificity result, not padding.
#
# Prereq -- start the agent in another terminal WITH --summary-out:
#   sudo python3 src/ebpf_agent.py --no-enrich --metrics /dev/null \
#        --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 \
#        --summary-out results/run_summary.json
#   (Falco/auditd OFF -- this is the eBPF agent's own FPR denominator.)
#
# Then run this, let it finish, Ctrl+C the agent (writes the summary), and read:
#   ./experiments/benign_fpr.sh
#   python3 - <<'PY'
#   import json; d=json.load(open('results/run_summary.json')); n=d['total_events']
#   print('N_b=%d alerts=%d  3/N_b=%.3f%%'%(n,d['alerts'],300.0/n if n else 0))
#   PY
#
# The generator reads the token with `cat` (a forked process per read) because a
# shell-builtin `read` redirection does NOT produce the filter-surviving openat
# the agent adjudicates (verified empirically -- it yielded 0 processed events).
# NOTE for Task 2.2 (agent footprint): each `cat` is a fresh PID -> a fresh
# proc:<pid> graph node, so a high RATE churns the provenance graph and grows RSS.
# Throttling via RATE reduces that churn proportionally; the per-trial behaviour
# is the same realistic short-lived-process pattern real workloads exhibit.
#
# Env:
#   DURATION   seconds of benign load                         (default 600)
#   RATE       token reads/sec; 0 = unthrottled max (FPR).    (default 0)
#              Set e.g. RATE=40 for a representative footprint measurement (2.2).
#   POD        generator pod name                             (default benign-fpr)
#   IMAGE      generator image                                (default busybox)
# =============================================================================
set -uo pipefail

DURATION="${DURATION:-600}"
RATE="${RATE:-0}"
POD="${POD:-benign-fpr}"
IMAGE="${IMAGE:-busybox}"

echo "================================================================"
echo " Benign FPR denominator run (Task 2.3)"
echo "   duration : ${DURATION}s"
echo "   generator: pod/$POD ($IMAGE) -- token-read loop (RATE='"$RATE"' reads/s, 0=max), benign"
echo "================================================================"

# Sanity: agent should be running WITH --summary-out, and nothing else.
if ! pgrep -f 'python3 .*ebpf_agent.py' >/dev/null; then
    echo "[warn] eBPF agent not found. Start it WITH --summary-out first (see header)."
fi
if ! pgrep -f 'ebpf_agent.py.*--summary-out' >/dev/null 2>&1; then
    echo "[warn] agent may be running WITHOUT --summary-out -> N_b will not be written."
fi
pgrep -x falco       >/dev/null && echo "[warn] falco is RUNNING (stop it; this measures the eBPF agent)."
pgrep -f auditd_agent.py >/dev/null && echo "[warn] auditd agent RUNNING (stop it)."
sudo auditctl -l 2>/dev/null | grep -qE 'S (execve|openat|open)' && echo "[warn] audit rules loaded (auditctl -D)."

echo ""
echo "=== Deploying benign generator pod (token-read loop) ==="
kubectl delete pod "$POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
# The SA token is auto-mounted in every pod; reading it passes the openat filter
# and is adjudicated benign. ca.crt read adds a second filter-surviving event.
kubectl run "$POD" --image="$IMAGE" --restart=Never --env "RATE=$RATE" -- sh -c '
  tok=/var/run/secrets/kubernetes.io/serviceaccount/token
  if [ "${RATE:-0}" -gt 0 ]; then
    # throttled: ~RATE token reads/sec (lower RATE = less process-node churn).
    while :; do i=0; while [ "$i" -lt "$RATE" ]; do cat "$tok" >/dev/null 2>&1; i=$((i+1)); done; sleep 1; done
  else
    # unthrottled max rate (FPR denominator).
    while :; do cat "$tok" >/dev/null 2>&1; done
  fi' >/dev/null
kubectl wait --for=condition=Ready pod/"$POD" --timeout=120s || \
    echo "[warn] pod not Ready; continuing (it may already be generating)."

# Light, realistic frontend load alongside, for a representative event mix.
FRONTEND_IP=$(kubectl get svc frontend -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
( if [ -n "$FRONTEND_IP" ]; then
    end=$((SECONDS + DURATION))
    while [ $SECONDS -lt $end ]; do curl -s "http://$FRONTEND_IP/" >/dev/null 2>&1 || true; sleep 0.5; done
  fi ) & CURL_BG=$!

echo "=== Generating benign load for ${DURATION}s (no attacks) ==="
end=$((SECONDS + DURATION))
while [ $SECONDS -lt $end ]; do
    printf "\r  elapsed %ds / %ds" "$SECONDS" "$DURATION"
    sleep 5
done
echo ""

kill "$CURL_BG" 2>/dev/null || true
echo "=== Cleaning up generator pod ==="
kubectl delete pod "$POD" --wait=false 2>/dev/null || true

echo ""
echo "Benign load complete. Now Ctrl+C the agent (Terminal A) to flush the summary,"
echo "then read N_b and the 95% rule-of-three bound:"
echo "  python3 -c \"import json;d=json.load(open('results/run_summary.json'));n=d['total_events'];print('N_b=%d alerts=%d  3/N_b=%.3f%%'%(n,d['alerts'],300.0/n if n else 0))\""
echo ""
echo "Expect alerts=0 (one info-severity suspicious-shell from this generator's own"
echo "shell is fine; it is excluded from FPR). Then set \\NbShow (N_b) and \\NbBound"
echo "(3/N_b %) above tab:fpr in thesis_book/ch6_evaluation.tex (hardcoded by hand)."
