#!/bin/bash
# =============================================================================
# run_b2_adversarial.sh -- B2 adversarial robustness R2-R4 (measured).
#   R2  syscall-padding vs the BoSC namespace-switch window
#   R3  slow read->connect chain vs the 60 s token-exfil correlation window
#   R4  renamed/relocated host binary vs the host-boundary path rule
# Runs each against the live agent and records which rules fire.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
DIR=results/b2; mkdir -p "$DIR"
A="$DIR/alerts.jsonl"; LOG="$DIR/run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }
POD=attacker-escape

log "starting agent"
pkill -INT -f ebpf_agent.py 2>/dev/null || true; sleep 3
python3 src/ebpf_agent.py --metrics "$A" \
  --pod-cidr 10.42.0.0/24 --svc-cidr 10.43.0.0/16 > "$DIR/agent.log" 2>&1 &
AG=$!
for i in $(seq 1 40); do bpftool prog show 2>/dev/null | grep -q syscall__setns && break; sleep 2; done
kubectl delete pod $POD --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f experiments/manifests/attacker-escape.yaml >/dev/null
kubectl wait --for=condition=Ready pod/$POD --timeout=120s >/dev/null
sleep 8   # warm cgroup map
run(){ kubectl exec $POD -- sh -c "$1"; }
snap(){ wc -l < "$A" 2>/dev/null || echo 0; }

# ---- R2: BoSC padding. Modern nsenter uses pidfd_open+setns with NO ns-file
# open -- the extreme of "padding" (the classic openat precursor is absent).
# GCID anchors on setns, so it must still detect. -----------------------------
log "R2: nsenter (setns-anchored; precursor-free = max padding)"
B=$(snap); run "nsenter --target 1 --mount -- ls /etc/hostname >/dev/null 2>&1" || true; sleep 2
log "R2 new alerts: $(( $(snap) - B ))"

# ---- R3a CONTROL: fast token-read -> immediate kube-api connect (chain) -----
log "R3a (control): fast chain (read token -> connect now)"
B=$(snap)
run "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; curl -sk https://10.43.0.1:443/version >/dev/null 2>&1" || true; sleep 2
log "R3a new alerts: $(( $(snap) - B ))"

# ---- R3b: SLOW chain -- read token, wait > 60 s, then connect ---------------
log "R3b: slow chain (read token, sleep 65s > 60s window, then connect)"
B=$(snap)
run "head -c40 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; sleep 65; curl -sk https://10.43.0.1:443/version >/dev/null 2>&1" || true; sleep 2
log "R3b new alerts: $(( $(snap) - B ))"

# ---- R4: renamed/relocated host binary, executed ----------------------------
log "R4: copy host binary to a renamed host path and exec it"
B=$(snap)
run 'cp /host/bin/true /host/tmp/zzdecoy_$$ 2>/dev/null; chmod +x /host/tmp/zzdecoy_$$; /host/tmp/zzdecoy_$$; rm -f /host/tmp/zzdecoy_$$' || true; sleep 2
log "R4 new alerts: $(( $(snap) - B ))"

log "stopping agent + cleanup"
kill -INT "$AG" 2>/dev/null || true; sleep 4; kill -KILL "$AG" 2>/dev/null || true
kubectl delete pod $POD --wait=false >/dev/null 2>&1 || true

log "=== rules fired (full run) ==="
python3 -c "
import json,collections
c=collections.Counter()
for l in open('$A'):
    try: c[json.loads(l).get('rule')]+=1
    except: pass
for r,n in c.most_common(): print('  %4d  %s'%(n,r))
print('--- R3 verdict: token-exfil=%d (expect 1, fast only) | kube-api-access=%d (expect 2, both)'
      % (c.get('serviceaccount-token-exfil',0), c.get('kube-api-access',0)))
print('--- R2 verdict: nsenter-bosc=%d (expect >=1)' % c.get('nsenter-bosc',0))
print('--- R4 verdict: host-binary-exec=%d file-boundary=%d (expect >=1 each)'
      % (c.get('host-binary-exec',0), c.get('file-boundary',0)))
" | tee -a "$LOG"
log "DONE"
