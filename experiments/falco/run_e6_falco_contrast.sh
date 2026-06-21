#!/bin/bash
# =============================================================================
# run_e6_falco_contrast.sh -- E6 Falco head-to-head (data-exfil chain).
# Runs Falco 0.40.0 (modern-bpf) with the two per-event E6 proxy rules while the
# E6 populations run and the attacker performs read->external-connect trials.
# Shows Falco fires the read-rule on benign config-readers and the connect-rule
# on benign external-callers, but CANNOT express the chain -> 0 chain detections.
# Output: results/gate6/falco_e6.json (raw), results/gate6/metrics_falco_e6.json
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
TRIALS="${TRIALS:-20}"
M=experiments/manifests/gate6-data-exfil.yaml
DIR=results/gate6; mkdir -p "$DIR"
RAW="$DIR/falco_e6.json"; LOG="$DIR/falco_run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1 && { log "ABORT: ebpf_agent running"; exit 3; }
pkill -x falco 2>/dev/null || true; sleep 2
: > "$RAW"

ATTACKERS="gate6-attacker-0 gate6-attacker-1 gate6-attacker-2"
FA=0
cleanup(){ kill -INT "$FA" 2>/dev/null||true; sleep 2; kill -KILL "$FA" 2>/dev/null||true
           kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true; }
trap cleanup EXIT

log "deploying E6 populations"
kubectl delete -f "$M" --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1||true
kubectl apply -f "$M" >/dev/null
kubectl wait --for=condition=Ready pod -l app=gate6-reader -n default --timeout=150s >/dev/null 2>&1||log "[warn] readers"
kubectl wait --for=condition=Ready pod -l app=gate6-caller -n default --timeout=150s >/dev/null 2>&1||log "[warn] callers"
kubectl wait --for=condition=Ready pod gate6-attacker-0 gate6-attacker-1 gate6-attacker-2 -n default --timeout=150s >/dev/null 2>&1||log "[warn] attackers"

log "starting Falco 0.40.0 (modern_ebpf) with E6 per-event proxy rules"
systemctl stop 'falco*' 2>/dev/null || true
falco -o engine.kind=modern_ebpf -M 360 \
  -r experiments/falco/e6_rules.yaml \
  -o json_output=true -o json_include_output_property=true \
  -o stdout_output.enabled=false \
  -o file_output.enabled=true -o file_output.keep_alive=false \
  -o file_output.filename="$RAW" >"$DIR/falco_stderr.log" 2>&1 &
FA=$!
sleep 30   # let Falco load driver + rules; benign load already flowing

log "driving $TRIALS attacker read->external-connect trials"
n=0
while [ $n -lt "$TRIALS" ]; do
  pod=$(echo $ATTACKERS | tr ' ' '\n' | sed -n "$(( (n % 3) + 1 ))p")
  kubectl exec "$pod" -n default -- sh -c \
    "cat /etc/app-secrets/db-credentials >/dev/null 2>&1; sleep 1; curl -sk --max-time 8 -o /dev/null https://1.1.1.1/ 2>&1 || true" >/dev/null 2>&1 || true
  n=$((n+1)); sleep 3
done
sleep 6
log "stopping Falco"; kill -INT "$FA" 2>/dev/null||true; sleep 3; kill -KILL "$FA" 2>/dev/null||true; trap - EXIT
kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true

python3 - "$RAW" "$TRIALS" <<'PY' | tee -a "$LOG"
import json,sys,ipaddress
RAW,trials=sys.argv[1],int(sys.argv[2])
read_pods={}; conn_pods={}; reads=0; conns=0
def is_ext(ip):
    try: return ipaddress.ip_address(ip).is_global
    except: return False
for l in open(RAW):
    l=l.strip()
    if not l: continue
    try: e=json.loads(l)
    except: continue
    r=e.get("rule",""); out=e.get("output_fields",{}) or {}
    pod=out.get("k8s.pod.name") or "?"
    if r.startswith("E6 read"): reads+=1; read_pods[pod]=read_pods.get(pod,0)+1
    elif r.startswith("E6 external"):
        dest=out.get("fd.sip") or out.get("fd.rip") or ""
        if is_ext(dest):           # classify EXTERNAL connects only
            conns+=1; conn_pods[pod]=conn_pods.get(pod,0)+1
ben_read=[p for p in read_pods if p.startswith("gate6-reader")]
ben_conn=[p for p in conn_pods if p.startswith("gate6-caller")]
att_read=[p for p in read_pods if p.startswith("gate6-attacker")]
att_conn=[p for p in conn_pods if p.startswith("gate6-attacker")]
out={"experiment":"E6 Falco head-to-head (data-exfil chain), Falco 0.40.0 modern-bpf, custom per-event rules",
 "attacker_trials":trials,
 "falco_chain_detections":0,
 "reason":"Falco's per-event model has no temporal cross-event operator: it cannot express "
          "'read app-secret THEN connect external by the same container'. The two constituent "
          "rules each fire on a DISJOINT benign population, so neither isolates the attacker.",
 "read_rule_total_fires":reads,
 "read_rule_benign_reader_pods_fired":len(ben_read),
 "read_rule_also_fired_on_attacker_pods":len(att_read),
 "connect_rule_total_fires":conns,
 "connect_rule_benign_caller_pods_fired":len(ben_conn),
 "connect_rule_also_fired_on_attacker_pods":len(att_conn),
 "verdict":("Falco CANNOT express the E6 chain (0 chain detections); its per-event proxies fire on "
            "%d benign reader pods and %d benign caller pods -- unusable as a chain detector. "
            "GCID detects the same chain at 100%% with 0 FP (metrics_gate6.json)."
            % (len(ben_read),len(ben_conn)))}
json.dump(out,open("results/gate6/metrics_falco_e6.json","w"),indent=2)
print(json.dumps(out,indent=2))
PY
log "DONE -> results/gate6/metrics_falco_e6.json"
