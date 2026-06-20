#!/bin/bash
# =============================================================================
# run_multinode_overnight.sh -- FULL statistical cross-node lateral eval.
# Detached (run under systemd-run). Agents on both nodes run for the whole run;
# the cross-node pivot (C1 single-hop + C2 two-leg chain) is repeated N times
# against the namespaced two-node topology, then scored:
#   - host1 source-side detection (C1 + leg1)
#   - host2 leg2 detection
#   - CROSS-NODE chains recovered by the offline stitch
# Spacing >> stitch window so each trial's legs join within-trial only.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
H2=root@<HOST2_IP>
H2DIR=/root/thesis_draft
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10"
N="${N:-500}"; SPACING="${SPACING:-30}"; WINDOW="${WINDOW:-15}"
MAN=experiments/manifests/multinode-lateral-ns.yaml
DIR="results/multinode_overnight_$(date +%Y%m%d)"; mkdir -p "$DIR"
LOG="$DIR/run.log"; : > "$LOG"
GT="$DIR/ground_truth.jsonl"; : > "$GT"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
gt(){ printf '{"ts": %s, "trial": %s, "scenario": "%s", "category": "LATERAL", "expect_rule": "cross-namespace-connect", "src_node": "%s", "hop": "%s"}\n' "$(date +%s.%N)" "$1" "$2" "$3" "$4" >> "$GT"; }

log "OVERNIGHT multinode: N=$N spacing=${SPACING}s window=${WINDOW}s -> $DIR"

# ---- host2 kubeconfig --------------------------------------------------------
$SSH $H2 'test -f /tmp/kc_mn.yaml' || \
  (scp -q -o BatchMode=yes /etc/rancher/k3s/k3s.yaml $H2:/tmp/kc_mn.yaml && \
   $SSH $H2 "sed -i 's#127.0.0.1#10.122.0.2#' /tmp/kc_mn.yaml")

# ---- start both agents (append mode so they accumulate across all trials) ---
log "starting host1 agent"
pkill -INT -f ebpf_agent.py 2>/dev/null || true; sleep 3
python3 src/ebpf_agent.py --node-name host1 --append \
  --metrics "$DIR/alerts.host1.jsonl" --prune-window 120 \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.host1.log" 2>&1 &
H1AG=$!
log "starting host2 agent (via ssh, detached)"
timeout 25 $SSH $H2 "pkill -INT -f ebpf_agent.py 2>/dev/null; sleep 2; \
  mkdir -p $H2DIR/$DIR; \
  cd $H2DIR && setsid env KUBECONFIG=/tmp/kc_mn.yaml PATH=/usr/local/bin:/usr/bin:/bin \
  python3 src/ebpf_agent.py --node-name host2 --append --prune-window 120 \
    --metrics $H2DIR/$DIR/alerts.host2.jsonl \
    --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 \
    </dev/null > $H2DIR/$DIR/agent.host2.log 2>&1 & sleep 1; exit 0" || true
mkdir -p "$DIR"   # ensure host2's relative path dir exists here too for scp target

log "waiting for both agents to attach..."
for i in $(seq 1 45); do
  L1=$(bpftool prog show 2>/dev/null | grep -c syscall__openat || echo 0)
  L2=$($SSH $H2 'bpftool prog show 2>/dev/null | grep -c syscall__openat' 2>/dev/null || echo 0)
  [ "${L1:-0}" -ge 1 ] && [ "${L2:-0}" -ge 1 ] && { log "both attached (h1=$L1 h2=$L2)"; break; }
  sleep 2
done

# ---- deploy the topology ONCE ----------------------------------------------
log "deploying namespaced topology"
kubectl delete -f "$MAN" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MAN" >/dev/null
kubectl wait -n mn-attacker --for=condition=Ready pod/attacker-mn --timeout=120s >>"$LOG" 2>&1
kubectl wait -n mn-relay    --for=condition=Ready pod/relay-mn    --timeout=120s >>"$LOG" 2>&1
kubectl wait -n mn-victim   --for=condition=Ready pod/target-db   --timeout=180s >>"$LOG" 2>&1 || true
A_NODE=$(kubectl get pod -n mn-attacker attacker-mn -o jsonpath='{.spec.nodeName}')
R_NODE=$(kubectl get pod -n mn-relay relay-mn -o jsonpath='{.spec.nodeName}')
log "attacker@$A_NODE relay@$R_NODE  cross-node=$([ "$A_NODE" != "$R_NODE" ] && echo YES || echo NO)"
kubectl get pods -A -o json | jq '[.items[]|select(.status.podIP!=null)|{ip:.status.podIP,pod:.metadata.name,node:.spec.nodeName,ns:.metadata.namespace}]' > "$DIR/pod_ips.json"
RELAY_IP=$(kubectl get pod -n mn-relay relay-mn -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get svc -n mn-victim internal-db -o jsonpath='{.spec.clusterIP}')
log "relay=$RELAY_IP db=$DB_IP"

# ---- trial loop -------------------------------------------------------------
for t in $(seq 1 "$N"); do
  gt "$t" C1  "$A_NODE" single
  kubectl exec -n mn-attacker attacker-mn -- nc -zv -w3 "$DB_IP" 5432 >/dev/null 2>&1 || true
  gt "$t" L3a "$A_NODE" hop1
  kubectl exec -n mn-attacker attacker-mn -- nc -zv -w3 "$RELAY_IP" 8080 >/dev/null 2>&1 || true
  gt "$t" L3b "$R_NODE" hop2
  kubectl exec -n mn-relay relay-mn -- nc -zv -w3 "$DB_IP" 5432 >/dev/null 2>&1 || true
  echo "$t" > "$DIR/progress.txt"
  [ $((t % 25)) -eq 0 ] && log "trial $t/$N done"
  sleep "$SPACING"
done

# ---- stop agents, collect, stitch + score -----------------------------------
log "trials done; stopping agents + collecting"
kubectl delete -f "$MAN" --wait=false >/dev/null 2>&1 || true
kill -INT "$H1AG" 2>/dev/null || true
$SSH $H2 'pkill -INT -f ebpf_agent.py' 2>/dev/null || true
sleep 8; kill -KILL "$H1AG" 2>/dev/null || true
scp -q -o BatchMode=yes $H2:$H2DIR/$DIR/alerts.host2.jsonl "$DIR/alerts.host2.jsonl" 2>>"$LOG" || true

log "=== STITCH ==="
python3 analysis/stitch_multinode.py "$DIR/alerts.host1.jsonl" "$DIR/alerts.host2.jsonl" \
  --pod-ips "$DIR/pod_ips.json" --window "$WINDOW" \
  --json-out "$DIR/metrics_stitch_multinode.json" 2>&1 | tee -a "$LOG"

log "=== PER-LEG DETECTION (N=$N) ==="
python3 - "$DIR" "$N" <<'PY' 2>&1 | tee -a "$LOG"
import json,sys,math
d,N=sys.argv[1],int(sys.argv[2])
def load(f):
    out=[]
    try:
        for l in open(f):
            try: out.append(json.loads(l))
            except: pass
    except FileNotFoundError: pass
    return out
h1=[a for a in load(f"{d}/alerts.host1.jsonl") if a.get("rule")=="cross-namespace-connect"]
h2=[a for a in load(f"{d}/alerts.host2.jsonl") if a.get("rule")=="cross-namespace-connect"]
st=json.load(open(f"{d}/metrics_stitch_multinode.json"))
def ci(k,n):
    if n==0: return (0,0)
    p=k/n; lo=max(0,p-1.96*math.sqrt(p*(1-p)/n)); hi=min(1,p+1.96*math.sqrt(p*(1-p)/n))
    return (round(lo,4),round(hi,4))
# host1 sees C1 + leg1 (~2N), host2 sees leg2 (~N), chains ~N
res={"trials":N,
     "host1_src_alerts":len(h1),"host1_per_trial":round(len(h1)/N,3),
     "host2_leg2_alerts":len(h2),"host2_leg2_rate":round(min(1,len(h2)/N),4),"host2_leg2_ci":ci(min(len(h2),N),N),
     "cross_node_chains":st.get("cross_node_chains",0),
     "cross_node_chain_rate":round(min(1,st.get("cross_node_chains",0)/N),4),
     "cross_node_chain_ci":ci(min(st.get("cross_node_chains",0),N),N)}
json.dump(res,open(f"{d}/metrics_multinode_stat.json","w"),indent=2)
print(json.dumps(res,indent=2))
PY
log "DONE -> $DIR"
echo DONE > "$DIR/COMPLETE"
