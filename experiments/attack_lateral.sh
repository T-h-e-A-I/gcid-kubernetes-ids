#!/bin/bash
# =============================================================================
# attack_lateral.sh -- Lateral-movement attack scenarios (L1-L2)
# -----------------------------------------------------------------------------
# Deploys a compromised insider pod and an internal target DB, then performs
# unauthorized internal scanning / connections across the cluster network.
# Records GROUND TRUTH for analysis/score.py.
#
# Scenarios:
#   L1 internal scan    : port-scan Online Boutique ClusterIPs from the
#                         compromised pod (bypassing the ingress controller)
#   L2 cross-ns connect : direct connect to the internal DB service:5432
#
# *** Ensure the eBPF agent is running in another terminal first. ***
# =============================================================================
set -uo pipefail

POD=attacker-lateral
ATTACKER_NS="${ATTACKER_NS:-attacker}"   # compromised pod runs in its own ns so
                                         # connects to default-ns targets are
                                         # genuinely cross-namespace (A7 fix)
GROUND_TRUTH="${GROUND_TRUTH:-ground_truth.jsonl}"
MANIFEST="$(dirname "$0")/manifests/attacker-lateral.yaml"

gt() {
    printf '{"ts": %s, "trial": %s, "scenario": "%s", "category": "%s", "expect_rule": "%s"}\n' \
        "$(date +%s.%N)" "${TRIAL:-1}" "$1" "$2" "$3" >> "$GROUND_TRUTH"
}

echo "=== Deploying attacker + target pods (fresh, for trial independence) ==="
# Ensure the attacker namespace exists ONCE (idempotent); kept out of the
# per-trial delete/apply cycle so we don't pay slow namespace termination each
# trial. Only the pods in $MANIFEST churn per trial.
kubectl create namespace "$ATTACKER_NS" --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null 2>&1 || true
kubectl delete -f "$MANIFEST" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready pod/$POD -n "$ATTACKER_NS" --timeout=120s
kubectl wait --for=condition=Ready pod/target-db --timeout=180s || true

run() { kubectl exec $POD -n "$ATTACKER_NS" -- sh -c "$1"; }

# netshoot ships nmap/nc/curl pre-installed -- no runtime install needed.
DB_IP=$(kubectl get svc internal-db -o jsonpath='{.spec.clusterIP}')
echo "Internal DB ClusterIP: $DB_IP"

echo ""
echo "=== L1: Internal scan of Online Boutique ClusterIPs ==="
gt L1 LATERAL cross-namespace-connect
# Scan a few well-known boutique service ports across the Service CIDR.
for svc in frontend productcatalogservice cartservice; do
    IP=$(kubectl get svc $svc -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
    [ -n "$IP" ] && run "nc -zv -w 2 $IP 8080 2>&1 | head -1" || true
done
sleep 1

echo ""
echo "=== L2: Cross-namespace connect to internal DB ($DB_IP:5432) ==="
gt L2 LATERAL cross-namespace-connect
run "nc -zv -w 3 $DB_IP 5432" || true
sleep 1

echo ""
echo "=== Cleaning up ==="
kubectl delete -f "$MANIFEST" --wait=false
echo "Lateral-movement scenarios complete. Ground truth -> $GROUND_TRUTH"
