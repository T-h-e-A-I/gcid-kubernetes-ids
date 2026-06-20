#!/bin/bash
# =============================================================================
# attack_lateral_multinode.sh -- Cross-node lateral movement (runs C1 + C2/L3)
# -----------------------------------------------------------------------------
# Thesis MULTI-NODE extension (todo/plan_multinode.md). Drives lateral movement
# that PROVABLY crosses a node boundary, so the two per-node eBPF agents each see
# only their half:
#
#   C1 single-hop : attacker-mn (Host-1) -> internal-db / relay ClusterIP whose
#                   pod is on Host-2. Host-1 agent fires cross-namespace-connect;
#                   Host-2 agent does NOT see the source connect (its kernel
#                   never ran it). Detection is source-side by design.
#
#   C2 multi-hop  : attacker-mn (Host-1) --leg1--> relay-mn (Host-2)
#                                          --leg2--> internal-db (Host-2)
#                   leg1 is seen by the Host-1 agent, leg2 by the Host-2 agent.
#                   Neither single graph reconstructs attacker->relay->db; the
#                   chain is recovered offline by analysis/stitch_multinode.py.
#
# Also dumps results/pod_ips.json (ip -> {pod,node}) so the stitch can resolve a
# destination IP back to the pod/node that owns it.
#
# *** Start the eBPF agent on BOTH hosts first (each with its own --node-name
#     and --metrics results/alerts.<node>.jsonl). ***
# =============================================================================
set -uo pipefail

GROUND_TRUTH="${GROUND_TRUTH:-ground_truth.jsonl}"
RESULTS_DIR="${RESULTS_DIR:-results}"
MANIFEST="$(dirname "$0")/manifests/multinode-lateral.yaml"
ATTACKER=attacker-mn
RELAY=relay-mn
mkdir -p "$RESULTS_DIR"

# Ground truth, extended with node/hop attribution for the cross-node scoring.
gt() {
    printf '{"ts": %s, "trial": %s, "scenario": "%s", "category": "%s", "expect_rule": "%s", "src_node": "%s", "hop": "%s"}\n' \
        "$(date +%s.%N)" "${TRIAL:-1}" "$1" "$2" "$3" "$4" "$5" >> "$GROUND_TRUTH"
}
run() { kubectl exec "$1" -- sh -c "$2"; }

echo "=== Deploying cross-node attacker + relay + target (fresh) ==="
kubectl delete -f "$MANIFEST" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready pod/$ATTACKER --timeout=120s
kubectl wait --for=condition=Ready pod/$RELAY    --timeout=120s
kubectl wait --for=condition=Ready pod/target-db --timeout=180s || true

# Confirm the pin actually crossed nodes (the experiment is meaningless otherwise).
A_NODE=$(kubectl get pod $ATTACKER -o jsonpath='{.spec.nodeName}')
R_NODE=$(kubectl get pod $RELAY    -o jsonpath='{.spec.nodeName}')
echo "attacker on node: $A_NODE   relay on node: $R_NODE"
[ "$A_NODE" != "$R_NODE" ] || echo "[warn] attacker and relay are on the SAME node -- check 'kubectl get nodes --show-labels' (role=attacker/target)."

# Dump pod IP -> {pod,node} so stitch_multinode.py can resolve dst IPs to pods.
kubectl get pods -A -o json \
  | jq '[.items[] | select(.status.podIP != null)
         | {ip: .status.podIP, pod: .metadata.name, node: .spec.nodeName}]' \
  > "$RESULTS_DIR/pod_ips.json"
echo "Wrote $RESULTS_DIR/pod_ips.json ($(jq length "$RESULTS_DIR/pod_ips.json") pods)"

RELAY_IP=$(kubectl get pod $RELAY -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get svc internal-db -o jsonpath='{.spec.clusterIP}')
echo "relay podIP=$RELAY_IP   internal-db ClusterIP=$DB_IP"

echo ""
echo "=== C1: single-hop cross-node connect (attacker H1 -> DB on H2) ==="
gt C1 LATERAL cross-namespace-connect "$A_NODE" single
run $ATTACKER "nc -zv -w 3 $DB_IP 5432" || true
sleep 1

echo ""
echo "=== C2 leg1: attacker (H1) -> relay (H2) ==="
gt L3a LATERAL cross-namespace-connect "$A_NODE" hop1
run $ATTACKER "nc -zv -w 3 $RELAY_IP 8080" || true
sleep 1

echo "=== C2 leg2: relay (H2) -> internal-db (H2->H2, source on Host-2) ==="
# The pivot: the RELAY itself now connects onward. Its source kernel is Host-2,
# so leg2 is observed by the Host-2 agent, not Host-1's. This is the half of the
# chain Host-1 never sees.
gt L3b LATERAL cross-namespace-connect "$R_NODE" hop2
run $RELAY "nc -zv -w 3 $DB_IP 5432" || true
sleep 1

echo ""
echo "=== Cleaning up ==="
kubectl delete -f "$MANIFEST" --wait=false
echo "Cross-node lateral scenarios complete. Ground truth -> $GROUND_TRUTH"
echo "Next: collect Host-2 alerts, then:"
echo "  python3 analysis/stitch_multinode.py \\"
echo "     $RESULTS_DIR/alerts.host1.jsonl $RESULTS_DIR/alerts.host2.jsonl \\"
echo "     --pod-ips $RESULTS_DIR/pod_ips.json"
