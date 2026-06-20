#!/bin/bash
# =============================================================================
# run_b3_scalability.sh -- B3: provenance-graph scalability + pruning.
# A load POD (events from the host are filtered in-kernel, so load must come
# from a container) generates a sustained, high-cardinality syscall stream;
# the agent samples (events, graph nodes, edges, RSS) over time for two
# conditions:
#   noprune : --prune-window 0   (unbounded growth -- the default)
#   prune   : --prune-window 60  (time-windowed eviction)
# Detection state (BoSC, token_read_cg) is separate + bounded, so pruning the
# provenance graph has no detection impact -- this measures memory only.
# =============================================================================
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
DUR="${DUR:-150}"
DIR=results/b3
mkdir -p "$DIR"
LOG="$DIR/run.log"; : > "$LOG"
log(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

# ---- deploy the load pod: sustained file-open loop spawning short-lived
# processes (each open -> a provenance edge; high event volume) -------------
log "deploying load pod"
kubectl delete pod b3-load --ignore-not-found --wait=true >/dev/null 2>&1 || true
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: b3-load
  labels: {role: b3load}
spec:
  nodeSelector: {role: attacker}
  restartPolicy: Never
  containers:
  - name: load
    image: busybox
    securityContext: {privileged: true}
    # Open many DISTINCT host paths (each "/host/..." open is a security-relevant
    # event the in-kernel filter submits -> a provenance edge + file/proc node),
    # so the graph actually grows. Benign non-host opens are filtered in-kernel.
    command: ["sh","-c","while true; do for f in /host/etc/* /host/usr/bin/* /host/bin/* /host/usr/lib/* /host/usr/sbin/*; do head -c1 \"$f\" >/dev/null 2>&1; done; done"]
    volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
YAML
kubectl wait --for=condition=Ready pod/b3-load --timeout=120s >>"$LOG" 2>&1
log "load pod Ready (generating sustained container syscall load)"

run_cond() {
  local COND="$1" PW="$2"
  log "=== condition $COND (prune-window=$PW) ==="
  pkill -INT -f "ebpf_agent.py" 2>/dev/null || true; sleep 3
  python3 src/ebpf_agent.py --metrics /dev/null \
      --pod-cidr 10.42.0.0/24 --svc-cidr 10.43.0.0/16 \
      --stats-out "$DIR/stats_$COND.csv" --stats-interval 5 --prune-window "$PW" \
      > "$DIR/agent_$COND.log" 2>&1 &
  local AG=$!
  for i in $(seq 1 40); do bpftool prog show 2>/dev/null | grep -q syscall__openat && break; sleep 2; done
  log "$COND: agent attached (pid $AG); sampling ${DUR}s"
  sleep "$DUR"
  log "$COND: stopping agent"
  kill -INT "$AG" 2>/dev/null || true; sleep 4; kill -KILL "$AG" 2>/dev/null || true
  log "$COND: final $(tail -1 "$DIR/stats_$COND.csv")"
}

run_cond noprune 0
run_cond prune 60

log "cleaning up load pod"
kubectl delete pod b3-load --ignore-not-found --wait=false >/dev/null 2>&1 || true

log "=== SUMMARY ==="
for c in noprune prune; do
  python3 -c "
import csv
rows=list(csv.DictReader(open('$DIR/stats_$c.csv')))
rows=[r for r in rows if int(r['events'])>0]
if rows:
    f=rows[-1]; peak=max(int(r['rss_kb']) for r in rows)
    print('$c: samples=%d final t=%ss events=%s nodes=%s edges=%s rss=%.1fMB peakRSS=%.1fMB'%(
        len(rows),f['t_s'],f['events'],f['nodes'],f['edges'],int(f['rss_kb'])/1024,peak/1024))
" | tee -a "$LOG"
done
log "DONE"
