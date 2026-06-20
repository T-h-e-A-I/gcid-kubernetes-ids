#!/bin/bash
# =============================================================================
# gate1b_allowlist.sh -- GATE 1b: does service-account allowlisting recover
# PRECISION on the token->API correlation while preserving attack detection?
#
# GATE 1 proved the bare rule false-fires on 100% (25/25) of legitimate API
# clients. This run turns on --token-api-allowlist default/gate1-apiclient and
# re-measures, with the benign clients under that (allowlisted) SA and a
# compromised app pod under the default (non-allowlisted) SA.
#
# Success = benign token-exfil FPs drop to ~0 AND the attacker is still detected.
# Outputs: results/gate1b/{alerts.jsonl, run.log, metrics_gate1b.json}
# SAFETY: refuses to start if another ebpf_agent.py is running.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

N_DRIVEN="${N_DRIVEN:-25}"
SPACING="${SPACING:-3}"
KUBE_API="${KUBE_API:-10.43.0.1}"
ALLOW="${ALLOW:-default/gate1-apiclient}"
DIR=results/gate1b; mkdir -p "$DIR"
A="$DIR/alerts.jsonl"; LOG="$DIR/run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

if pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1; then
  log "ABORT: an ebpf_agent.py is already running. Refusing to double-attach."
  pgrep -af 'python3 .*ebpf_agent.py' | tee -a "$LOG"; exit 3
fi
pgrep -x falco >/dev/null 2>&1 && { log "ABORT: falco running."; exit 3; }

M=experiments/manifests/gate1b-allowlist.yaml
AG=0
cleanup(){ kill -INT "$AG" 2>/dev/null || true; sleep 4; kill -KILL "$AG" 2>/dev/null || true
           kubectl delete -f "$M" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "GATE 1b: allowlist=$ALLOW  (benign clients allowlisted; attacker on default SA)"
log "starting agent WITH --token-api-allowlist"
python3 src/ebpf_agent.py --metrics "$A" --kube-api "$KUBE_API" \
  --token-api-allowlist "$ALLOW" \
  --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
AG=$!
for i in $(seq 1 40); do bpftool prog show 2>/dev/null | grep -q syscall__ && break; sleep 2; done
sleep 3

log "deploying benign(allowlisted-SA) + attacker(default-SA) pods"
kubectl delete -f "$M" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$M" >/dev/null
kubectl wait --for=condition=Ready pod/benign-reporter pod/benign-adminbox pod/gate1-attacker \
  -n default --timeout=150s >/dev/null 2>&1 || log "[warn] not all pods Ready"
sleep 12   # warm cgroup map + let resolver pick up pod->SA (kubectl refresh ~5s)

cnt(){ grep -c "\"$1\"" "$A" 2>/dev/null || echo 0; }

# ---- BENIGN: N driven legitimate read->connect sessions (allowlisted SA) ------
log "driving $N_DRIVEN benign read->connect sessions via adminbox (allowlisted SA)"
for i in $(seq 1 "$N_DRIVEN"); do
  kubectl exec benign-adminbox -n default -- sh -c \
    'T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -H "Authorization: Bearer $T" https://'"$KUBE_API"':443/version >/dev/null 2>&1' \
    >/dev/null 2>&1 || true
  sleep "$SPACING"
done
log "observing periodic reporter (allowlisted) 40s"; sleep 40
BENIGN_FP=$(cnt serviceaccount-token-exfil)
SUPPRESSED=$(cnt token-exfil-suppressed-allowlist)
log "benign-phase token-exfil FPs (allowlist ON): $BENIGN_FP   suppressed-allowlist: $SUPPRESSED"

# ---- ATTACKER: compromised app pod (default SA, NOT allowlisted) -------------
log "ATTACK: gate1-attacker (default SA) reads token -> hits Kube-API (E2)"
B=$BENIGN_FP
for i in $(seq 1 5); do
  kubectl exec gate1-attacker -n default -- sh -c \
    'head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; curl -sk https://'"$KUBE_API"':443/version >/dev/null 2>&1' \
    >/dev/null 2>&1 || true
  sleep 3
done
sleep 3
TOTAL_TE=$(cnt serviceaccount-token-exfil)
ATTACK_DET=$(( TOTAL_TE - B ))
log "attacker token-exfil detections (5 attempts): $ATTACK_DET"

log "stopping agent + cleanup"
kill -INT "$AG" 2>/dev/null || true; sleep 4; kill -KILL "$AG" 2>/dev/null || true
trap - EXIT
kubectl delete -f "$M" --wait=false >/dev/null 2>&1 || true

python3 - "$BENIGN_FP" "$N_DRIVEN" "$SUPPRESSED" "$ATTACK_DET" <<'PY' | tee -a "$LOG"
import json,sys
bfp,ndr,supp,adet=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
out={"experiment":"GATE 1b -- service-account allowlist precision fix",
 "allowlist":"default/gate1-apiclient",
 "benign_driven_sessions":ndr,
 "benign_token_exfil_false_positives_allowlist_ON":bfp,
 "benign_suppressed_by_allowlist":supp,
 "attacker_attempts":5,"attacker_token_exfil_detections":adet,
 "gate1_baseline_benign_FP_allowlist_OFF":40,
 "verdict":(
   "FIX WORKS: allowlist removes benign FPs while attacker (non-allowlisted SA) still detected"
   if bfp==0 and adet>0 else
   "PARTIAL/FAIL: benign_FP=%d attacker_det=%d -- inspect"%(bfp,adet))}
json.dump(out,open("results/gate1b/metrics_gate1b.json","w"),indent=2)
print(json.dumps(out,indent=2))
PY
log "DONE -> results/gate1b/metrics_gate1b.json"
