#!/bin/bash
# =============================================================================
# gate1_benign_apiclients.sh -- GATE 1 (round-2 reviewer-driven).
#
# QUESTION (raised by 6/8 v2 reviewers): the headline FPR (0/445, 1h) was
# measured on Online Boutique, which is gRPC service-to-service and NEVER
# contacts the kube-API server -- so the benign population could not, by
# construction, exhibit the one behaviour the `serviceaccount-token-exfil` rule
# keys on (read SA token -> connect kube-API within 60s). This run injects that
# exact confounder with LEGITIMATE, API-talking benign pods and measures whether
# the token-exfil rule false-fires, i.e. the FPR *specifically on the token->API
# correlation*. No attacks run here; every token-exfil alert is a FALSE POSITIVE.
#
# Outputs: results/gate1/{alerts.jsonl, benign_truth.jsonl, run.log, metrics_gate1.json}
#
# SAFETY: refuses to start if another ebpf_agent.py is already running (e.g. the
# multinode overnight unit) -- two agents would double-attach kprobes and corrupt
# both measurements. Wait for that to finish first.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

N_DRIVEN="${N_DRIVEN:-25}"      # controlled benign read->connect sessions (denominator)
SPACING="${SPACING:-3}"         # seconds between driven sessions
KUBE_API="${KUBE_API:-10.43.0.1}"
DIR=results/gate1; mkdir -p "$DIR"
A="$DIR/alerts.jsonl"; GT="$DIR/benign_truth.jsonl"; LOG="$DIR/run.log"
: > "$LOG"; : > "$GT"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
ts(){ python3 -c 'import time;print("%.3f"%time.time())'; }
gt(){ echo "{\"ts\":$(ts),\"kind\":\"$1\",\"note\":\"$2\"}" >> "$GT"; }

# ---- SAFETY GUARD: no concurrent agent (multinode unit etc.) ----------------
if pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1; then
  log "ABORT: an ebpf_agent.py is already running (multinode?). Refusing to"
  log "       start a second agent -- it would double-attach kprobes."
  pgrep -af 'python3 .*ebpf_agent.py' | tee -a "$LOG"
  exit 3
fi
pgrep -x falco >/dev/null 2>&1 && { log "ABORT: falco is running (stop it first)."; exit 3; }

M=experiments/manifests/benign-apiclients.yaml
cleanup(){
  log "cleanup"
  kill -INT "${AG:-0}" 2>/dev/null || true; sleep 4; kill -KILL "${AG:-0}" 2>/dev/null || true
  kubectl delete -f "$M" --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "GATE 1: benign API-client confounder run (N_DRIVEN=$N_DRIVEN, kube-api=$KUBE_API)"
log "starting clean agent"
python3 src/ebpf_agent.py --metrics "$A" --kube-api "$KUBE_API" \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
AG=$!
# wait for kprobes (tcp connect probe in particular)
for i in $(seq 1 40); do bpftool prog show 2>/dev/null | grep -q syscall__ && break; sleep 2; done
sleep 3
snap(){ grep -c '"serviceaccount-token-exfil"' "$A" 2>/dev/null || echo 0; }
snap_api(){ grep -c '"kube-api-access"' "$A" 2>/dev/null || echo 0; }

# ---- Deploy the benign API-talking pods -------------------------------------
log "deploying benign API-client pods (controller cold-start, periodic reporter, adminbox)"
kubectl delete -f "$M" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$M" >/dev/null
gt deploy "benign API clients deployed"
kubectl wait --for=condition=Ready pod/benign-controller pod/benign-reporter pod/benign-adminbox \
  -n default --timeout=150s >/dev/null 2>&1 || log "[warn] not all benign pods Ready"
sleep 10   # let controller cold-start (read token -> API) + warm cgroup map
gt controller_start "benign-controller bootstrap read-token->API (G1a)"

# ---- G1c: legitimate client RESTART during monitoring -----------------------
log "G1c: restart benign-controller (re-reads token + NEW API connect on fresh cgroup)"
kubectl delete pod benign-controller -n default --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$M" >/dev/null 2>&1 || true   # recreates benign-controller (+others already exist)
kubectl wait --for=condition=Ready pod/benign-controller -n default --timeout=120s >/dev/null 2>&1 || true
sleep 10
gt controller_restart "benign-controller restarted (G1c)"

# ---- G1d + driven denominator: N controlled benign read->connect sessions ----
# kubectl exec into the adminbox and perform, N_DRIVEN times, the EXACT benign
# sequence (read own token, contact the API). These are the clean denominator.
log "driving $N_DRIVEN controlled benign read->connect sessions via adminbox (admin-debug pattern)"
for i in $(seq 1 "$N_DRIVEN"); do
  gt benign_session "driven benign read-token->kube-api #$i"
  kubectl exec benign-adminbox -n default -- sh -c \
    'T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -H "Authorization: Bearer $T" https://'"$KUBE_API"':443/version >/dev/null 2>&1' \
    >/dev/null 2>&1 || true
  sleep "$SPACING"
done

# Let the periodic reporter accrue a few organic cycles too.
log "observing periodic reporter (organic read->connect every 20s) for 60s"
sleep 60

# ---- Tally -------------------------------------------------------------------
FP=$(snap); API=$(snap_api)
# denominator = driven sessions + controller cold-start + controller restart
# (reporter's organic connects are additional benign opportunities, reported separately)
N_DEN=$(( N_DRIVEN + 2 ))
log "stopping agent + cleanup"
kill -INT "$AG" 2>/dev/null || true; sleep 4; kill -KILL "$AG" 2>/dev/null || true
trap - EXIT
kubectl delete -f "$M" --wait=false >/dev/null 2>&1 || true

log "=== GATE 1 RESULT ==="
log "benign token->API correlation sessions driven (denominator) : $N_DEN"
log "serviceaccount-token-exfil FALSE POSITIVES                  : $FP"
log "kube-api-access alerts (expected on every benign API connect): $API"
python3 - "$FP" "$N_DEN" "$API" "$N_DRIVEN" <<'PY' | tee -a "$LOG"
import json,sys,math
fp,n,api,ndr=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
def wilson(k,n,z=1.96):
    if n==0: return (0.0,0.0)
    p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return (max(0,c-h),min(1,c+h))
lo,hi=wilson(fp,n)
out={"benign_correlation_sessions":n,"driven_sessions":ndr,
     "token_exfil_false_positives":fp,
     "fpr_on_token_api_correlation":round(fp/n,4) if n else None,
     "fpr_ci95_wilson":[round(lo,4),round(hi,4)],
     "kube_api_access_alerts":api,
     "interpretation":(
        "token-exfil rule false-fires on legitimate API-client startup/restart"
        if fp>0 else
        "token-exfil rule did NOT false-fire on legitimate API clients")}
json.dump(out,open("results/gate1/metrics_gate1.json","w"),indent=2)
print(json.dumps(out,indent=2))
PY
log "DONE -> results/gate1/metrics_gate1.json"
