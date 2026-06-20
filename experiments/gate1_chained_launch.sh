#!/bin/bash
# Waits for the multinode overnight unit to COMPLETE cleanly, then fires GATE 1
# on the now-idle cluster. Detached watcher so the two agents never overlap.
set -uo pipefail
cd /root/thesis_draft
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
W=results/gate1/watcher.log; mkdir -p results/gate1; : > "$W"
say(){ echo "[$(date +%T)] $*" | tee -a "$W"; }

MN=results/multinode_overnight_20260619
MAX=$((5*3600))   # 5h hard cap so we never wait forever
start=$SECONDS
say "watcher up; waiting for gcid-multinode to finish (cap 5h)"
while :; do
  active=$(systemctl is-active gcid-multinode 2>/dev/null || echo unknown)
  agent=$(pgrep -f 'python3 .*ebpf_agent.py' >/dev/null 2>&1 && echo yes || echo no)
  prog=$(cat "$MN/progress.txt" 2>/dev/null || echo "?")
  if [ "$active" != "active" ] && [ "$agent" = "no" ]; then
    say "multinode no longer active (state=$active, agent=$agent, progress=$prog)"
    break
  fi
  if [ $((SECONDS-start)) -gt $MAX ]; then
    say "ABORT: 5h cap reached, multinode still active -- not firing GATE 1."
    exit 1
  fi
  sleep 60
done

# brief settle so the multinode cleanup (pods, host2 agent) drains
say "settling 30s before GATE 1"; sleep 30
if [ -f "$MN/COMPLETE" ]; then say "multinode COMPLETE marker present"; else say "[warn] no COMPLETE marker (multinode may have ended early) -- continuing GATE 1 anyway"; fi

say "launching GATE 1"
bash experiments/gate1_benign_apiclients.sh >> "$W" 2>&1
rc=$?
say "GATE 1 finished rc=$rc -> results/gate1/metrics_gate1.json"
exit $rc
