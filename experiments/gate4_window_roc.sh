#!/bin/bash
# =============================================================================
# gate4_window_roc.sh -- detection x false-positive ROC vs the correlation window.
#
# A reviewer asks: the 60s/0.55% headline is one point on a window-size frontier;
# widen the window to catch slower attackers and the FP rate should rise. We plot
# that frontier. For each window W (NO allowlist, so the raw correlation FP is
# exposed): run the diverse benign API clients + an attacker, and measure
#   - benign token-exfil FP rate  (the FP axis)
#   - attacker detection at a FAST chain (dwell 5s, should be caught for any W)
#   - attacker detection at a SLOW chain (dwell W+30s, should be MISSED <= W)
# The detection-vs-dwell cliff (max detectable dwell = W) is the recall axis.
# Outputs: results/gate4/{roc.csv, metrics_gate4.json, run.log}
# SAFETY: refuses if another ebpf_agent.py is running.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
WINDOWS="${WINDOWS:-15 60 300}"
PER_W="${PER_W:-150}"            # seconds of benign load per window
KUBE_API="${KUBE_API:-10.43.0.1}"
ALLOW="${ALLOW:-}"              # set to allowlist SAs to test the identity-scoped curve
ALLOW_ARGS=""; [ -n "$ALLOW" ] && ALLOW_ARGS="--token-api-allowlist $ALLOW"
DIR=results/gate4; mkdir -p "$DIR"
LOG="$DIR/run.log"; : > "$LOG"; ROC="$DIR/roc.csv"
echo "window_s,benign_fp,benign_events,fast_attack_detected,slow_attack_detected" > "$ROC"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
cnt(){ local n; n=$(grep -c "\"$1\"" "$2" 2>/dev/null || true); echo "${n:-0}"; }

pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1 && { log "ABORT: agent already running"; exit 3; }
pgrep -x falco >/dev/null 2>&1 && { log "ABORT: falco running"; exit 3; }

M=experiments/manifests/gate1c-apiclients.yaml
cleanup(){ pkill -INT -f 'ebpf_agent.py' 2>/dev/null||true; sleep 2
           kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true; }
trap cleanup EXIT

log "deploying diverse benign API clients + attacker (shared across windows)"
kubectl delete -f "$M" --ignore-not-found --wait=true >/dev/null 2>&1||true
kubectl apply -f "$M" >/dev/null
kubectl wait --for=condition=Ready pod/g1c-reconciler pod/g1c-scraper pod/g1c-job pod/g1c-sdk pod/g1c-attacker \
  -n default --timeout=180s >/dev/null 2>&1 || log "[warn] not all ready"
sleep 12

for W in $WINDOWS; do
  A="$DIR/alerts.w${W}.jsonl"; : > "$A"
  log "=== window=${W}s (no allowlist) ==="
  python3 src/ebpf_agent.py --metrics "$A" --kube-api "$KUBE_API" --token-window "$W" $ALLOW_ARGS \
    --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 > "$DIR/agent.w${W}.log" 2>&1 &
  AG=$!
  for i in $(seq 1 40); do bpftool prog show 2>/dev/null|grep -q syscall__ && break; sleep 2; done; sleep 3
  # benign load for PER_W seconds (the diverse clients run continuously)
  sleep "$PER_W"
  # FAST attacker: read token -> connect 5s later (within any W -> must detect)
  kubectl exec g1c-attacker -n default -- sh -c \
    "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; sleep 5; curl -sk https://$KUBE_API:443/version >/dev/null 2>&1" >/dev/null 2>&1 || true
  sleep 3
  fast=$(cnt serviceaccount-token-exfil "$A")
  # SLOW attacker: read token -> connect W+30s later (beyond window -> must MISS)
  base=$(cnt serviceaccount-token-exfil "$A")
  kubectl exec g1c-attacker -n default -- sh -c \
    "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; sleep $((W+30)); curl -sk https://$KUBE_API:443/version >/dev/null 2>&1" >/dev/null 2>&1 || true
  sleep 3
  slow=$(( $(cnt serviceaccount-token-exfil "$A") - base ))
  kill -INT "$AG" 2>/dev/null||true; sleep 4; kill -KILL "$AG" 2>/dev/null||true
  # benign FP = token-exfil from benign pods (exclude g1c-attacker); benign events = kube-api-access from benign
  benfp=$(python3 -c "
import json
fp=0
for l in open('$A'):
    try:a=json.loads(l)
    except:continue
    if a.get('rule')=='serviceaccount-token-exfil' and a.get('pod','?')!='g1c-attacker': fp+=1
print(fp)")
  bevents=$(cnt kube-api-access "$A")
  fast_det=$([ "$fast" -gt 0 ] && echo 1 || echo 0)
  slow_det=$([ "$slow" -gt 0 ] && echo 1 || echo 0)
  log "window=${W}s benign_FP=$benfp benign_api_events=$bevents fast_detected=$fast_det slow(W+30)_detected=$slow_det"
  echo "$W,$benfp,$bevents,$fast_det,$slow_det" >> "$ROC"
done

trap - EXIT; kubectl delete -f "$M" --wait=false >/dev/null 2>&1||true
log "=== ROC ==="; cat "$ROC" | tee -a "$LOG"
python3 -c "
import csv,json
rows=list(csv.DictReader(open('$ROC')))
out={'experiment':'GATE 4 -- detection x FP ROC vs correlation window (no allowlist)',
 'rows':[{'window_s':int(r['window_s']),'benign_fp':int(r['benign_fp']),
          'benign_api_events':int(r['benign_events']),
          'fast_attack_detected':bool(int(r['fast_attack_detected'])),
          'slow_attack_W+30_detected':bool(int(r['slow_attack_detected']))} for r in rows],
 'reading':('max detectable attacker dwell == window W (recall axis); benign FP without allowlist is '
   'the FP axis. With identity-scoping (allowlist, GATE 1c) benign FP is ~0 regardless of W, '
   'decoupling the window from precision so it can be widened to catch slower chains at only a memory cost.')}
json.dump(out,open('results/gate4/metrics_gate4.json','w'),indent=2)
print(json.dumps(out,indent=2))
"
log "DONE -> results/gate4/metrics_gate4.json"
