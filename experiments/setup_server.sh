#!/bin/bash
# =============================================================================
# setup_server.sh -- Provision HOST-1 as the k3s SERVER (control plane + worker)
#                    for the two-host multi-node testbed.
# -----------------------------------------------------------------------------
# Thesis: eBPF Syscall Monitoring -- MULTI-NODE extension (todo/plan_multinode.md).
#
# Host-1 is the EXISTING single-node VM. This script makes it the cluster server
# that Host-2 (setup_agent.sh) joins, and prints the join URL + token. It is
# idempotent: if k3s is already installed it reuses it and just emits the token;
# pass FORCE_REINSTALL=1 to rebind a single-node install to the private IP.
#
# The eBPF toolchain on Host-1 is assumed already installed by the original
# setup_env.sh; the apt lines below are re-run idempotently as a safety net so
# this script is self-contained.
#
# Optional inputs:
#   NODE_NAME        (default: host1)
#   PRIVATE_IP       (default: auto)   VPC/private IP agents will dial (6443)
#   FORCE_REINSTALL  (default: 0)      reinstall k3s server bound to PRIVATE_IP
#   DEPLOY_BOUTIQUE  (default: 1)      (re)deploy Online Boutique
#
# Usage:   PRIVATE_IP=10.116.0.5 ./experiments/setup_server.sh
# =============================================================================
set -euo pipefail

log()  { echo -e "\n\033[1;34m[server-setup]\033[0m $*"; }
fail() { echo -e "\n\033[1;31m[server-setup ERROR]\033[0m $*" >&2; exit 1; }

NODE_NAME="${NODE_NAME:-host1}"
FORCE_REINSTALL="${FORCE_REINSTALL:-0}"
DEPLOY_BOUTIQUE="${DEPLOY_BOUTIQUE:-1}"
PRIVATE_IP="${PRIVATE_IP:-$(ip -4 -o addr show 2>/dev/null \
    | awk '/ 10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\./{print $4}' \
    | cut -d/ -f1 | head -1)}"
[ -n "$PRIVATE_IP" ] || fail "Could not autodetect a private IP; set PRIVATE_IP=<vpc-ip>."

# ---- 1. Toolchain safety net (idempotent) -----------------------------------
log "Ensuring base + eBPF toolchain + python deps + chrony (idempotent)..."
sudo apt-get update
sudo apt-get install -y curl wget git jq conntrack build-essential chrony \
    bpfcc-tools python3-bpfcc bpftrace clang llvm libelf-dev libpcap-dev \
    gcc-multilib linux-headers-$(uname -r) linux-tools-common \
    linux-tools-generic sysstat \
    python3-networkx python3-seccomp python3-matplotlib python3-scipy
# chrony: keep Host-1/Host-2 clocks aligned for the cross-node stitch (run C2).
sudo systemctl enable --now chrony 2>/dev/null || sudo systemctl enable --now chronyd 2>/dev/null || true

# ---- 2. k3s SERVER ----------------------------------------------------------
# Bind the API + node to the PRIVATE IP so Host-2 joins over the VPC, and add a
# TLS SAN so the agent's TLS handshake to https://<private-ip>:6443 validates.
SERVER_FLAGS="--node-name $NODE_NAME --node-ip $PRIVATE_IP \
--advertise-address $PRIVATE_IP --tls-san $PRIVATE_IP"

if command -v k3s >/dev/null 2>&1 && [ "$FORCE_REINSTALL" != "1" ]; then
    log "k3s already installed -> reusing it (set FORCE_REINSTALL=1 to rebind to $PRIVATE_IP)."
else
    log "Installing k3s server (bound to $PRIVATE_IP)..."
    curl -sfL https://get.k3s.io | sh -s - server $SERVER_FLAGS
fi

mkdir -p "$HOME/.kube"
sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"
export KUBECONFIG="$HOME/.kube/config"

log "Waiting for the server node to become Ready..."
until kubectl get nodes 2>/dev/null | grep -q " Ready"; do sleep 3; done
kubectl label node "$NODE_NAME" role=attacker --overwrite || true
kubectl get nodes -o wide

# ---- 3. Online Boutique (benign workload) -----------------------------------
if [ "$DEPLOY_BOUTIQUE" = "1" ]; then
    log "Deploying Online Boutique (benign traffic)..."
    BOUTIQUE_DIR="$HOME/microservices-demo"
    [ -d "$BOUTIQUE_DIR" ] || git clone --depth 1 \
        https://github.com/GoogleCloudPlatform/microservices-demo.git "$BOUTIQUE_DIR"
    kubectl apply -f "$BOUTIQUE_DIR/release/kubernetes-manifests.yaml"
    log "Boutique applied (pods may take minutes; they will spread to Host-2 once it joins)."
fi

# ---- 4. Emit the JOIN command for Host-2 ------------------------------------
TOKEN="$(sudo cat /var/lib/rancher/k3s/server/node-token)"
log "Server ready. Provide the following to Host-2 (setup_agent.sh):"
echo "================================================================"
echo "  Run on HOST-2:"
echo ""
echo "    K3S_URL=https://$PRIVATE_IP:6443 \\"
echo "    K3S_TOKEN=$TOKEN \\"
echo "        ./experiments/setup_agent.sh"
echo ""
echo "  Firewall (open ONLY between the two private IPs):"
echo "    TCP 6443  (k3s API)   UDP 8472 (flannel VXLAN)   TCP 10250 (kubelet)"
echo "================================================================"
echo ""
echo "Start Host-1's eBPF agent:"
echo "  sudo python3 src/ebpf_agent.py --node-name $NODE_NAME \\"
echo "       --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16 \\"
echo "       --metrics results/alerts.$NODE_NAME.jsonl --graph-out results/graph.$NODE_NAME.json"
