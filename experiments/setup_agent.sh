#!/bin/bash
# =============================================================================
# setup_agent.sh -- Provision HOST-2 (the NEW VM): full eBPF toolchain + join
#                   the existing k3s cluster as a worker (agent) node.
# -----------------------------------------------------------------------------
# Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
#         eBPF Syscall Monitoring -- MULTI-NODE extension (todo/plan_multinode.md).
#
# Host-2 is a FRESH machine, so -- unlike the server -- it has NONE of the eBPF
# experiment dependencies yet. This script installs the COMPLETE toolchain the
# detection agent needs to load/compile BPF on Host-2's own kernel (separate
# kernel == separate eBPF data plane, the whole point of the two-host testbed),
# then joins it to Host-1's cluster.
#
# Target: Ubuntu 24.04 LTS, kernel 6.8+ with BTF, 4 vCPU / 8 GB (match Host-1 so
#         the per-node overhead parity run C3 is valid). See plan_multinode.md §2.
#
# REQUIRED inputs (from Host-1's setup_server.sh output):
#   K3S_URL    e.g. https://<host1-private-ip>:6443
#   K3S_TOKEN  the node token printed by setup_server.sh
# Optional:
#   NODE_NAME      (default: host2)   k3s + agent identity for this host
#   PRIVATE_IP     (default: auto)    this host's VPC/private IP (for --node-ip)
#   WITH_AUDITD    (default: 1)       also install/arm auditd (baseline parity)
#
# Usage:
#   K3S_URL=https://10.116.0.5:6443 K3S_TOKEN=K10abc... \
#       ./experiments/setup_agent.sh
# =============================================================================
set -euo pipefail

log()  { echo -e "\n\033[1;34m[agent-setup]\033[0m $*"; }
fail() { echo -e "\n\033[1;31m[agent-setup ERROR]\033[0m $*" >&2; exit 1; }

NODE_NAME="${NODE_NAME:-host2}"
WITH_AUDITD="${WITH_AUDITD:-1}"
# Best-effort private-IP autodetect (DigitalOcean VPC is usually 10.x on eth1).
PRIVATE_IP="${PRIVATE_IP:-$(ip -4 -o addr show 2>/dev/null \
    | awk '/ 10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\./{print $4}' \
    | cut -d/ -f1 | head -1)}"

[ -n "${K3S_URL:-}" ]   || fail "K3S_URL is required (https://<host1-private-ip>:6443). See setup_server.sh output."
[ -n "${K3S_TOKEN:-}" ] || fail "K3S_TOKEN is required (the node token from setup_server.sh)."

# ---- 0. Pre-flight: kernel / BTF (eBPF prerequisites) -----------------------
log "Pre-flight checks (kernel, BTF)..."
echo "  kernel : $(uname -r)"
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  BTF    : present (/sys/kernel/btf/vmlinux) -- good for BCC CO-RE"
else
    echo "  [warn] /sys/kernel/btf/vmlinux MISSING -- BCC may still work via"
    echo "         kernel headers, but a BTF-enabled kernel (5.15+/6.x) is"
    echo "         strongly recommended. Continuing."
fi

# ---- 1. Base packages -------------------------------------------------------
log "Updating base packages..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl wget git jq conntrack build-essential \
    software-properties-common chrony wrk
# chrony: NTP time sync. REQUIRED -- the cross-node correlation stitch
# (analysis/stitch_multinode.py, run C2) joins the two nodes' alerts on a
# timestamp window, so Host-1 and Host-2 clocks MUST agree. (plan_multinode §8)
sudo systemctl enable --now chrony 2>/dev/null || sudo systemctl enable --now chronyd 2>/dev/null || true

# ---- 2. eBPF / BCC toolchain (THE CRITICAL PART for a fresh VM) -------------
# Identical to setup_env.sh so Host-2's data plane is byte-for-byte the same as
# Host-1's -- required for a valid per-node overhead comparison (C3).
log "Installing eBPF toolchain (BCC, clang/llvm, kernel headers)..."
sudo apt-get install -y \
    bpfcc-tools python3-bpfcc bpftrace \
    clang llvm libelf-dev libpcap-dev gcc-multilib \
    linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
    sysstat            # pidstat, for the overhead benchmark

# ---- 3. Python detection-engine dependencies (apt, not pip) ----------------
# The agent runs under `sudo python3` and imports BCC from the SYSTEM python
# (python3-bpfcc); apt packages are what root's interpreter sees and this avoids
# the PEP 668 externally-managed-environment error on Ubuntu 24.04.
log "Installing Python dependencies (networkx, seccomp, plotting, scipy)..."
sudo apt-get install -y \
    python3-networkx python3-seccomp python3-matplotlib python3-scipy

# ---- 4. auditd baseline (optional, for per-node baseline parity) -----------
if [ "$WITH_AUDITD" = "1" ]; then
    log "Installing + arming auditd (baseline; same rules as Host-1)..."
    sudo apt-get install -y auditd audispd-plugins
    sudo auditctl -D || true
    sudo auditctl -b 16384 || true
    sudo auditctl -a always,exit -F arch=b64 -S execve  -k exec_monitor
    sudo auditctl -a always,exit -F arch=b64 -S openat  -k file_monitor
    sudo auditctl -a always,exit -F arch=b64 -S open    -k file_monitor
    sudo auditctl -a always,exit -F arch=b64 -S connect -k net_monitor
    sudo auditctl -a always,exit -F arch=b64 -S setns   -k ns_monitor
else
    log "Skipping auditd (WITH_AUDITD=0)."
fi

# ---- 5. Smoke-test the eBPF stack BEFORE joining ----------------------------
# Catch a broken BCC install now, not midway through an experiment.
log "Smoke-testing BCC (loading a trivial probe)..."
if sudo python3 - <<'PY'
from bcc import BPF
BPF(text=b'int kprobe__sys_clone(void *ctx){return 0;}')
print("  BCC OK -- a probe compiled and attached.")
PY
then :; else fail "BCC smoke test failed -- fix the toolchain before joining (check linux-headers-$(uname -r))."; fi

# ---- 6. Join the k3s cluster as an agent (worker) ---------------------------
log "Joining k3s cluster as agent '$NODE_NAME' -> $K3S_URL ..."
NODE_IP_FLAG=""
[ -n "$PRIVATE_IP" ] && NODE_IP_FLAG="--node-ip $PRIVATE_IP"
echo "  node-name : $NODE_NAME"
echo "  node-ip   : ${PRIVATE_IP:-<auto>}"
curl -sfL https://get.k3s.io | \
    K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" \
    sh -s - agent --node-name "$NODE_NAME" $NODE_IP_FLAG

log "Waiting for k3s-agent service to come up..."
until sudo systemctl is-active --quiet k3s-agent; do sleep 3; done

log "Agent provisioning complete on '$NODE_NAME'."
echo "================================================================"
echo "Verify FROM HOST-1:   kubectl get nodes -o wide   (expect 2 Ready)"
echo "Then label this node:  kubectl label node $NODE_NAME role=target --overwrite"
echo ""
echo "Start THIS node's eBPF agent (separate kernel = separate data plane):"
echo "  sudo python3 src/ebpf_agent.py --node-name $NODE_NAME \\"
echo "       --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 \\"
echo "       --metrics results/alerts.$NODE_NAME.jsonl"
echo ""
echo "After the run, ship this file to Host-1 for merged scoring:"
echo "  scp results/alerts.$NODE_NAME.jsonl <host1-user>@<host1-private-ip>:~/thesis_draft/results/"
echo "================================================================"
