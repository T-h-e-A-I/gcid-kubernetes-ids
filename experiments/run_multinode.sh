#!/bin/bash
# =============================================================================
# run_multinode.sh -- orchestrate the cross-node lateral eval from host1.
# Starts the eBPF agent on BOTH nodes (host1 local, host2 via SSH), drives the
# cross-node attack, collects both alert streams, and stitches the chain.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
H2=root@<HOST2_IP>
H2DIR=/root/thesis_draft
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=no"
DIR=results/multinode_$(date +%Y%m%d); mkdir -p "$DIR"
LOG="$DIR/run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

# ---- host2 kubeconfig (point PodResolver at the control-plane API) ----------
log "preparing host2 kubeconfig"
$SSH $H2 'cat /tmp/kc_mn.yaml >/dev/null 2>&1' || \
  (scp -q -o BatchMode=yes /etc/rancher/k3s/k3s.yaml $H2:/tmp/kc_mn.yaml && \
   $SSH $H2 "sed -i 's#127.0.0.1#10.122.0.2#' /tmp/kc_mn.yaml")

# ---- start agents on both nodes ---------------------------------------------
log "starting host1 agent (local)"
pkill -INT -f ebpf_agent.py 2>/dev/null || true; sleep 3
python3 src/ebpf_agent.py --node-name host1 \
  --metrics "$DIR/alerts.host1.jsonl" \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.host1.log" 2>&1 &
H1AG=$!

log "starting host2 agent (via ssh)"
timeout 25 $SSH $H2 "pkill -INT -f ebpf_agent.py 2>/dev/null; sleep 2; \
  cd $H2DIR && setsid env KUBECONFIG=/tmp/kc_mn.yaml PATH=/usr/local/bin:/usr/bin:/bin \
  python3 src/ebpf_agent.py --node-name host2 \
    --metrics $H2DIR/results/alerts.host2.jsonl \
    --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 \
    </dev/null > $H2DIR/results/agent.host2.log 2>&1 & sleep 1; exit 0" || true

log "waiting for both agents to attach kprobes..."
for i in $(seq 1 45); do
  L1=$(bpftool prog show 2>/dev/null | grep -c syscall__openat || echo 0)
  L2=$($SSH $H2 'bpftool prog show 2>/dev/null | grep -c syscall__openat' 2>/dev/null || echo 0)
  [ "$L1" -ge 1 ] && [ "$L2" -ge 1 ] && { log "both agents attached (h1=$L1 h2=$L2)"; break; }
  sleep 2
done

# ---- drive the cross-node + cross-namespace attack --------------------------
MAN=experiments/manifests/multinode-lateral-ns.yaml
GT="$DIR/ground_truth.jsonl"
gt(){ printf '{"ts": %s, "trial": 1, "scenario": "%s", "category": "LATERAL", "expect_rule": "cross-namespace-connect", "src_node": "%s", "hop": "%s"}\n' "$(date +%s.%N)" "$1" "$2" "$3" >> "$GT"; }
log "deploying namespaced cross-node topology"
kubectl delete -f "$MAN" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MAN" >/dev/null
kubectl wait -n mn-attacker --for=condition=Ready pod/attacker-mn --timeout=120s >>"$LOG" 2>&1
kubectl wait -n mn-relay    --for=condition=Ready pod/relay-mn    --timeout=120s >>"$LOG" 2>&1
kubectl wait -n mn-victim   --for=condition=Ready pod/target-db   --timeout=180s >>"$LOG" 2>&1 || true
A_NODE=$(kubectl get pod -n mn-attacker attacker-mn -o jsonpath='{.spec.nodeName}')
R_NODE=$(kubectl get pod -n mn-relay relay-mn -o jsonpath='{.spec.nodeName}')
log "attacker@$A_NODE  relay@$R_NODE  (cross-node: $([ "$A_NODE" != "$R_NODE" ] && echo YES || echo NO))"
kubectl get pods -A -o json | jq '[.items[]|select(.status.podIP!=null)|{ip:.status.podIP,pod:.metadata.name,node:.spec.nodeName,ns:.metadata.namespace}]' > "$DIR/pod_ips.json"
RELAY_IP=$(kubectl get pod -n mn-relay relay-mn -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get svc -n mn-victim internal-db -o jsonpath='{.spec.clusterIP}')
log "relay podIP=$RELAY_IP  internal-db ClusterIP=$DB_IP"
log "C1: attacker(H1) -> db(H2)"
gt C1 "$A_NODE" single
kubectl exec -n mn-attacker attacker-mn -- nc -zv -w3 "$DB_IP" 5432 >>"$LOG" 2>&1 || true; sleep 1
log "C2 leg1: attacker(H1) -> relay(H2)"
gt L3a "$A_NODE" hop1
kubectl exec -n mn-attacker attacker-mn -- nc -zv -w3 "$RELAY_IP" 8080 >>"$LOG" 2>&1 || true; sleep 1
log "C2 leg2: relay(H2) -> db(H2)  [source kernel = host2]"
gt L3b "$R_NODE" hop2
kubectl exec -n mn-relay relay-mn -- nc -zv -w3 "$DB_IP" 5432 >>"$LOG" 2>&1 || true; sleep 2
kubectl delete -f "$MAN" --wait=false >/dev/null 2>&1 || true
sleep 2

# ---- stop agents ------------------------------------------------------------
log "stopping agents"
kill -INT "$H1AG" 2>/dev/null || true
$SSH $H2 'pkill -INT -f ebpf_agent.py' 2>/dev/null || true
sleep 5
kill -KILL "$H1AG" 2>/dev/null || true

# ---- collect host2 alerts + stitch ------------------------------------------
log "collecting host2 alerts"
scp -q -o BatchMode=yes $H2:$H2DIR/results/alerts.host2.jsonl "$DIR/alerts.host2.jsonl" 2>&1 || true
log "host1 alerts: $(wc -l < "$DIR/alerts.host1.jsonl" 2>/dev/null), host2 alerts: $(wc -l < "$DIR/alerts.host2.jsonl" 2>/dev/null)"

log "=== STITCH ==="
python3 analysis/stitch_multinode.py \
  "$DIR/alerts.host1.jsonl" "$DIR/alerts.host2.jsonl" \
  --pod-ips "$DIR/pod_ips.json" --json-out "$DIR/metrics_stitch_multinode.json" 2>&1 | tee -a "$LOG"
log "DONE -> $DIR"
