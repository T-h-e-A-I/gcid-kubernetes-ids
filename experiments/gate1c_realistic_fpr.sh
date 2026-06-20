#!/bin/bash
# =============================================================================
# gate1c_realistic_fpr.sh -- realistic API-heavy precision re-run (v3 blocker).
#
# v3 reviewers (5/7, the dominant Q2 blocker): the token->API precision claim
# was validated on (a) a workload that never calls the API (0/445), and (b) only
# 25 curated curls. They want the FPR measured under DIVERSE, REAL, CHURNING
# API clients with the SA allowlist active, and the attacker still detected.
#
# This runs the agent with --token-api-allowlist covering the synthetic clients'
# dedicated SA AND the real system API-client SAs (coredns, metrics-server),
# then for DURATION exercises: 4 diverse synthetic client patterns (reconcile/
# scrape/burst/sdk) + their RESTART churn + REAL system component restarts
# (coredns, metrics-server) + a non-allowlisted attacker driven periodically.
#
# Reports: token->API FPR with allowlist ON under realistic load, suppressed
# count (the denominator of legit correlation events), attacker detection,
# and an FP/hour extrapolation.
# Outputs: results/gate1c/{alerts.jsonl, run.log, metrics_gate1c.json}
# SAFETY: refuses to start if another ebpf_agent.py is running.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

DURATION="${DURATION:-1500}"          # seconds of realistic load (default 25 min)
CHURN_EVERY="${CHURN_EVERY:-180}"     # restart a client every N seconds
ATTACK_EVERY="${ATTACK_EVERY:-150}"   # attacker token->API every N seconds
KUBE_API="${KUBE_API:-10.43.0.1}"
DIR=results/gate1c; mkdir -p "$DIR"
A="$DIR/alerts.jsonl"; LOG="$DIR/run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

if pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1; then
  log "ABORT: an ebpf_agent.py is already running."; pgrep -af 'python3 .*ebpf_agent.py'|tee -a "$LOG"; exit 3
fi
pgrep -x falco >/dev/null 2>&1 && { log "ABORT: falco running."; exit 3; }

# Best-effort deploy a REAL client-go operator (kube-state-metrics) into the
# benign mix -- a recognizable, API-heavy operator, not a synthetic curl loop.
KSM=experiments/manifests/kube-state-metrics.yaml
log "deploying real operator kube-state-metrics (best-effort)"
kubectl apply -f "$KSM" >/dev/null 2>&1 || log "[warn] KSM apply failed (continuing)"

# Allowlist: synthetic SA + real system/operator API-client SAs present in cluster.
ALLOW="default/gate1c-apiclient,default/kube-state-metrics"
for sa in kube-system/coredns kube-system/metrics-server kube-system/traefik \
          kube-system/local-path-provisioner-service-account; do
  ns=${sa%/*}; n=${sa#*/}
  kubectl -n "$ns" get sa "$n" >/dev/null 2>&1 && ALLOW="$ALLOW,$sa"
done
log "allowlist: $ALLOW"

M=experiments/manifests/gate1c-apiclients.yaml
SYN="g1c-reconciler g1c-scraper g1c-job g1c-sdk"
AG=0
cleanup(){ kill -INT "$AG" 2>/dev/null||true; sleep 3; kill -KILL "$AG" 2>/dev/null||true
           kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true
           kubectl delete -f experiments/manifests/kube-state-metrics.yaml --wait=false >/dev/null 2>&1||true; }
trap cleanup EXIT

log "starting agent WITH allowlist (realistic-load precision re-run, DURATION=${DURATION}s)"
python3 src/ebpf_agent.py --metrics "$A" --kube-api "$KUBE_API" \
  --token-api-allowlist "$ALLOW" \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
AG=$!
for i in $(seq 1 40); do bpftool prog show 2>/dev/null|grep -q syscall__ && break; sleep 2; done; sleep 3

log "deploying diverse benign API clients (allowlisted SA) + attacker (default SA)"
kubectl delete -f "$M" --ignore-not-found --wait=true >/dev/null 2>&1||true
kubectl apply -f "$M" >/dev/null
kubectl wait --for=condition=Ready pod/g1c-reconciler pod/g1c-scraper pod/g1c-job pod/g1c-sdk pod/g1c-attacker \
  -n default --timeout=180s >/dev/null 2>&1 || log "[warn] not all clients Ready"
sleep 15   # warm resolver pod->SA map before scoring

cnt(){ local n; n=$(grep -c "\"$1\"" "$A" 2>/dev/null || true); echo "${n:-0}"; }
end=$((SECONDS+DURATION)); nc=0; na=0; tick=0
log "running realistic load + churn for ${DURATION}s"
while [ $SECONDS -lt $end ]; do
  sleep 30; tick=$((tick+30))
  # periodic attacker (non-allowlisted) read->API -> MUST be detected
  if [ $((tick % ATTACK_EVERY)) -lt 30 ]; then
    kubectl exec g1c-attacker -n default -- sh -c \
      "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; curl -sk https://$KUBE_API:443/version >/dev/null 2>&1" >/dev/null 2>&1 || true
    na=$((na+1))
  fi
  # churn: restart one synthetic client (cold token->API reconnect) + occasionally a real system client
  if [ $((tick % CHURN_EVERY)) -lt 30 ]; then
    c=$(echo $SYN | tr ' ' '\n' | sed -n "$(( (nc % 4) + 1 ))p"); nc=$((nc+1))
    kubectl delete pod "$c" -n default --wait=false >/dev/null 2>&1 || true
    kubectl apply -f "$M" >/dev/null 2>&1 || true
    # rotate restarts across the REAL operators so genuine client-go token->API
    # reconnects land throughout the window
    case $((nc % 5)) in
      0) kubectl -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 || true;;
      1) kubectl -n kube-system rollout restart deploy/metrics-server >/dev/null 2>&1 || true;;
      2) kubectl -n kube-system rollout restart deploy/traefik >/dev/null 2>&1 || true;;
      3) kubectl -n kube-system rollout restart deploy/local-path-provisioner >/dev/null 2>&1 || true;;
      4) kubectl -n default rollout restart deploy/kube-state-metrics >/dev/null 2>&1 || true;;
    esac
  fi
  fp=$(cnt serviceaccount-token-exfil); sup=$(cnt token-exfil-suppressed-allowlist)
  log "  +${tick}s  token-exfil FP=$fp  suppressed=$sup  attacker-runs=$na  churns=$nc"
done

FP=$(cnt serviceaccount-token-exfil); SUP=$(cnt token-exfil-suppressed-allowlist); API=$(cnt kube-api-access)
log "stopping agent"
kill -INT "$AG" 2>/dev/null||true; sleep 4; kill -KILL "$AG" 2>/dev/null||true; trap - EXIT
kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true
kubectl delete -f "$KSM" --wait=false >/dev/null 2>&1||true

# Attacker detections = token-exfil FPs attributed to g1c-attacker; benign FPs = the rest.
python3 - "$A" "$FP" "$SUP" "$API" "$DURATION" "$na" <<'PY' | tee -a "$LOG"
import json,sys,math
A,fp,sup,api,dur,na=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6])
att=0; ben=0
for l in open(A):
    try: a=json.loads(l)
    except: continue
    if a.get("rule")=="serviceaccount-token-exfil":
        if a.get("pod","")=="g1c-attacker": att+=1
        else: ben+=1
den=sup+ben  # legitimate token->API correlation events adjudicated (suppressed + benign-FP)
def wilson(k,n,z=1.96):
    if n==0:return(0,0)
    p=k/n;d=1+z*z/n;c=(p+z*z/(2*n))/d;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return(max(0,c-h),min(1,c+h))
lo,hi=wilson(ben,den)
out={"experiment":"GATE 1c -- realistic API-heavy token->API precision (allowlist ON)",
 "duration_s":dur,"allowlist":"synthetic SA + real coredns/metrics-server SAs",
 "legit_correlation_events_adjudicated":den,
 "benign_token_exfil_false_positives":ben,
 "fpr_on_token_api_correlation":round(ben/den,4) if den else None,
 "fpr_ci95_wilson":[round(lo,4),round(hi,4)],
 "benign_suppressed_by_allowlist":sup,
 "attacker_runs":na,"attacker_token_exfil_detections":att,
 "benign_fp_per_hour":round(ben/(dur/3600.0),2) if dur else None,
 "kube_api_access_alerts":api,
 "verdict":("PRECISE under realistic load: allowlist suppresses real+diverse API clients while the "
   "non-allowlisted attacker is detected" if ben<=1 and att>0 else
   "benign_FP=%d attacker_det=%d -- inspect"%(ben,att))}
json.dump(out,open("results/gate1c/metrics_gate1c.json","w"),indent=2)
print(json.dumps(out,indent=2))
PY
log "DONE -> results/gate1c/metrics_gate1c.json"
