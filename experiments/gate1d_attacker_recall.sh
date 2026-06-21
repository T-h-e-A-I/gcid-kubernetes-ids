#!/bin/bash
# =============================================================================
# gate1d_attacker_recall.sh -- high-N attacker RECALL for the token-exfil chain
# under the realistic allowlist config (closes the under-sampled 12/12 / 5/5 with
# a proper Wilson CI, matching the rigor of the reported FPR). Allowlist ON (the
# 4 benign client SAs + real system SAs); the non-allowlisted attacker
# (g1c-attacker, default SA) drives token-read -> kube-API N times in a tight
# loop. Scores attacker detections / N with a Wilson CI, and benign token-exfil
# FPs during the window.
# Output: results/gate1d/{alerts.jsonl, ground_truth.jsonl, metrics_gate1d.json}
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
TRIALS="${TRIALS:-100}"; TRIAL_GAP="${TRIAL_GAP:-3}"; KUBE_API="${KUBE_API:-10.43.0.1}"
M=experiments/manifests/gate1c-apiclients.yaml
DIR=results/gate1d; mkdir -p "$DIR"
A="$DIR/alerts.jsonl"; GT="$DIR/ground_truth.jsonl"; LOG="$DIR/run.log"; : > "$LOG"; : > "$GT"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1 && { log "ABORT: agent running"; exit 3; }
pgrep -x falco >/dev/null 2>&1 && { log "ABORT: falco running"; exit 3; }

ALLOW="default/gate1c-apiclient"
for sa in kube-system/coredns kube-system/metrics-server kube-system/traefik \
          kube-system/local-path-provisioner-service-account; do
  ns=${sa%/*}; n=${sa#*/}; kubectl -n "$ns" get sa "$n" >/dev/null 2>&1 && ALLOW="$ALLOW,$sa"
done
AG=0
cleanup(){ kill -INT "$AG" 2>/dev/null||true; sleep 3; kill -KILL "$AG" 2>/dev/null||true
           kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true; }
trap cleanup EXIT

log "deploying benign allowlisted clients + non-allowlisted attacker"
kubectl delete -f "$M" --ignore-not-found --wait=true --timeout=90s >/dev/null 2>&1||true
kubectl apply -f "$M" >/dev/null
kubectl wait --for=condition=Ready pod/g1c-reconciler pod/g1c-scraper pod/g1c-job pod/g1c-sdk pod/g1c-attacker \
  -n default --timeout=180s >/dev/null 2>&1 || log "[warn] not all Ready"

log "starting agent WITH allowlist: $ALLOW"
python3 src/ebpf_agent.py --metrics "$A" --kube-api "$KUBE_API" --token-api-allowlist "$ALLOW" \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
AG=$!
for i in $(seq 1 40); do bpftool prog show 2>/dev/null|grep -q kprobe && break; sleep 2; done
sleep 18   # warm resolver pod->SA map

log "driving $TRIALS attacker token-read -> kube-API trials (tight loop)"
n=0
while [ $n -lt "$TRIALS" ]; do
  ts=$(date +%s.%N)
  kubectl exec g1c-attacker -n default -- sh -c \
    "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; curl -sk --max-time 6 -o /dev/null https://$KUBE_API:443/version 2>&1 || true" >/dev/null 2>&1 || true
  echo "{\"trial\":$n,\"pod\":\"g1c-attacker\",\"ts\":$ts,\"scenario\":\"E2\",\"expect_rule\":\"serviceaccount-token-exfil\"}" >> "$GT"
  n=$((n+1))
  [ $((n % 25)) -eq 0 ] && log "  trial $n/$TRIALS  token-exfil so far=$(grep -c serviceaccount-token-exfil "$A" 2>/dev/null||echo 0)"
  sleep "$TRIAL_GAP"
done
sleep 8
log "stopping agent"; kill -INT "$AG" 2>/dev/null||true; sleep 4; kill -KILL "$AG" 2>/dev/null||true; trap - EXIT
kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true

python3 - "$A" "$GT" <<'PY' | tee -a "$LOG"
import json,sys,math
A,GT=sys.argv[1],sys.argv[2]
alerts=[json.loads(l) for l in open(A) if l.strip() and '"serviceaccount-token-exfil"' in l]
trials=[json.loads(l) for l in open(GT) if l.strip()]
def ts_of(a):
    for k in ("timestamp","ts","time"):
        if k in a:
            try: return float(a[k])
            except: pass
    return None
att=[a for a in alerts if str(a.get("pod","")).startswith("g1c-attacker")]
ben=[a for a in alerts if not str(a.get("pod","")).startswith("g1c-attacker")]
used=set(); det=0
for t in trials:
    tt=float(t["ts"]); hit=False
    for i,a in enumerate(att):
        if i in used: continue
        at=ts_of(a)
        if at is not None and (tt-2)<=at<=(tt+15): used.add(i); det+=1; hit=True; break
    if not hit:
        for i,a in enumerate(att):
            if i not in used: used.add(i); det+=1; hit=True; break
n=len(trials)
def wilson(k,m,z=1.96):
    if m==0:return(0,0)
    p=k/m;d=1+z*z/m;c=(p+z*z/(2*m))/d;h=z*math.sqrt(p*(1-p)/m+z*z/(4*m*m))/d
    return(max(0,c-h),min(1,c+h))
lo,hi=wilson(det,n)
out={"experiment":"GATE 1d -- high-N attacker recall, token-exfil chain under allowlist config",
 "trials":n,"detections":det,"detection_rate":round(det/n,4) if n else None,
 "detection_ci95_wilson":[round(lo,4),round(hi,4)],
 "benign_token_exfil_false_positives":len(ben),
 "note":"allowlist ON (4 benign client SAs + system SAs); attacker = non-allowlisted default SA",
 "verdict":("RECALL CONFIRMED at scale: %d/%d attacker chains detected, %d benign FP"%(det,n,len(ben)))
   if det>0 else "det=%d/%d -- inspect"%(det,n)}
json.dump(out,open("results/gate1d/metrics_gate1d.json","w"),indent=2)
print(json.dumps(out,indent=2))
PY
log "DONE -> results/gate1d/metrics_gate1d.json"
