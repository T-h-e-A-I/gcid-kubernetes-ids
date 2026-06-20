#!/bin/bash
# =============================================================================
# setup_env.sh -- Provision the Kubernetes (k3s) experimental environment
# -----------------------------------------------------------------------------
# Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
#         eBPF Syscall Monitoring.
#
# Target: a single Ubuntu 22.04 VM (>=4 vCPU, 8GB RAM, kernel 5.15+ with BTF).
# Installs: eBPF toolchain, k3s single-node cluster, auditd baseline, and the
# Online Boutique microservices demo (realistic benign traffic for FPR tests).
#
# NOTE: the user runs this manually (per their instruction). It is idempotent
# where practical. Take a VM snapshot after it completes ("Cluster+Toolchain
# Ready") as recommended in the Lab Setup Guide.
# =============================================================================
set -euo pipefail

log() { echo -e "\n\033[1;34m[setup]\033[0m $*"; }

# ---- 1. Base packages -------------------------------------------------------
log "Updating base packages..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl wget git jq conntrack build-essential \
    software-properties-common \
    wrk            # HTTP load generator (fallback for bench_traffic_impact.sh;
                   # the script auto-downloads `hey` if not present)

# ---- 2. eBPF / BCC toolchain ------------------------------------------------
log "Installing eBPF toolchain (BCC, clang/llvm, headers)..."
sudo apt-get install -y \
    bpfcc-tools python3-bpfcc bpftrace \
    clang llvm libelf-dev libpcap-dev gcc-multilib \
    linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
    sysstat            # provides pidstat for the overhead benchmark

# ---- 3. Python detection-engine dependencies --------------------------------
# Install via APT (not pip): the agent runs under `sudo python3` and imports
# BCC from the system Python (python3-bpfcc). System packages are what root's
# interpreter sees, and apt avoids the PEP 668 "externally-managed-environment"
# error on modern Ubuntu.
#   python3-networkx  : in-memory dependency graph (detection engine)
#   python3-seccomp   : 'seccomp' module for the agent --harden bpf() lockdown
#   python3-matplotlib: figures in analysis/score.py
#   python3-scipy     : exact Welch t-test (score.py falls back without it)
log "Installing Python dependencies via apt (networkx, seccomp, plotting)..."
sudo apt-get install -y \
    python3-networkx python3-seccomp python3-matplotlib python3-scipy

# ---- 4. auditd baseline -----------------------------------------------------
log "Installing and configuring auditd (baseline comparison)..."
sudo apt-get install -y auditd audispd-plugins
# Rules cover the syscalls the attacks use so the baseline can ATTEMPT the same
# scenarios as the eBPF agent. NOTE the cost: to see file access and lateral
# movement, auditd must log EVERY open/openat/connect system-wide -- a huge log
# volume (vs eBPF's in-kernel filtering). That flood is the realistic auditd
# overhead the thesis measures, and the kernel will DROP records under load
# (raising the backlog limit only softens this), which is itself the auditd
# limitation: it cannot scope monitoring cheaply.
sudo auditctl -D || true
sudo auditctl -b 16384 || true                  # larger backlog -> fewer drops
sudo auditctl -a always,exit -F arch=b64 -S execve  -k exec_monitor
sudo auditctl -a always,exit -F arch=b64 -S openat  -k file_monitor
sudo auditctl -a always,exit -F arch=b64 -S open    -k file_monitor
sudo auditctl -a always,exit -F arch=b64 -S connect -k net_monitor
sudo auditctl -a always,exit -F arch=b64 -S mount   -k mount_monitor
sudo auditctl -a always,exit -F arch=b64 -S setns   -k ns_monitor
sudo auditctl -w /etc/shadow -p rwxa -k sensitive_access
sudo auditctl -w /etc/passwd -p rwxa -k sensitive_access
sudo auditctl -w /var/lib/kubelet -p rwxa -k k8s_sensitive || true
sudo auditctl -w /etc/kubernetes/pki -p rwxa -k k8s_sensitive || true
sudo auditctl -w /run/containerd/containerd.sock -p rwxa -k k8s_sensitive || true

# ---- 5. k3s single-node cluster --------------------------------------------
log "Installing k3s (single-node Kubernetes)..."
curl -sfL https://get.k3s.io | sh -
mkdir -p "$HOME/.kube"
sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"
export KUBECONFIG="$HOME/.kube/config"

log "Waiting for the node to become Ready..."
until kubectl get nodes 2>/dev/null | grep -q " Ready"; do sleep 3; done
kubectl get nodes

# Record the CIDRs so the agent can be configured. NOTE: on k3s the per-node
# `.spec.podCIDR` field is frequently EMPTY (k3s manages Flannel internally and
# does not always populate it). The agent needs the *cluster-wide* Pod CIDR
# (a /16), not the per-node /24, so we resolve it robustly with fallbacks:
#   1) node .spec.podCIDR  -> 2) .spec.podCIDRs  -> 3) infer from a pod IP
#   -> 4) k3s default 10.42.0.0/16
resolve_pod_cidr() {
    local c
    c=$(kubectl get node -o jsonpath='{.items[0].spec.podCIDR}' 2>/dev/null)
    if [ -z "$c" ]; then
        c=$(kubectl get node -o jsonpath='{.items[0].spec.podCIDRs[0]}' 2>/dev/null)
    fi
    if [ -z "$c" ]; then
        # Infer the /16 from any running pod's IP (e.g. 10.42.0.5 -> 10.42.0.0/16)
        local ip
        ip=$(kubectl get pods -A -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
        [ -n "$ip" ] && c="$(echo "$ip" | cut -d. -f1-2).0.0/16"
    fi
    # Normalise a per-node /24 to the cluster /16 the agent expects.
    case "$c" in
        */24) c="$(echo "$c" | cut -d. -f1-2).0.0/16" ;;
    esac
    [ -z "$c" ] && c="10.42.0.0/16"   # k3s default cluster-cidr
    echo "$c"
}
POD_CIDR="$(resolve_pod_cidr)"

log "Cluster network ranges (configure the agent with these):"
echo "  Pod CIDR     : $POD_CIDR"
echo "  Service CIDR : 10.43.0.0/16 (k3s default)"
echo "  Kube-API     : $(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}' 2>/dev/null)"
echo "  (verify Pod CIDR from real pod IPs: kubectl get pods -A -o wide)"

# ---- 6. Online Boutique target workload -------------------------------------
# Clone OUTSIDE the thesis repo to avoid creating a nested git repository
# (which would otherwise show up as an embedded repo / accidental submodule in
# `git status`). $HOME matches the Lab Setup Guide.
log "Deploying Online Boutique microservices (benign traffic generator)..."
BOUTIQUE_DIR="$HOME/microservices-demo"
if [ ! -d "$BOUTIQUE_DIR" ]; then
    git clone --depth 1 \
        https://github.com/GoogleCloudPlatform/microservices-demo.git \
        "$BOUTIQUE_DIR"
fi
kubectl apply -f "$BOUTIQUE_DIR/release/kubernetes-manifests.yaml"
log "Waiting for boutique pods (this can take several minutes)..."
kubectl wait --for=condition=Ready pods --all --timeout=600s || \
    echo "[warn] some pods not ready yet; re-check with: kubectl get pods"

log "Setup complete."
echo "================================================================"
echo "Next steps:"
echo "  1. Take a VM snapshot: 'Cluster & Toolchain Ready'."
echo "  2. Start the agent:    sudo python3 src/ebpf_agent.py \\"
echo "                            --pod-cidr <PodCIDR> --svc-cidr 10.43.0.0/16"
echo "  3. Run experiments:    ./experiments/run_evaluation.sh"
echo "================================================================"
