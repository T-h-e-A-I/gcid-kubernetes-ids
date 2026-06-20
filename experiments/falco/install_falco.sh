#!/bin/bash
# =============================================================================
# install_falco.sh -- Task 2.1: install Falco on the k3s node for the head-to-head
# -----------------------------------------------------------------------------
# Installs Falco as a HOST PACKAGE (not the DaemonSet) with the modern_ebpf
# (CO-RE) driver, JSON output, and file output to /var/log/falco/events.json.
#
# Why host package rather than the Helm DaemonSet:
#   - the eBPF/auditd agents are benchmarked as host processes (pidstat on the
#     PID), so a host `falco` process is the apples-to-apples overhead target
#     (experiments/falco/bench_falco_overhead.sh selects it via `pgrep -x falco`);
#   - file_output lands directly on the host fs where run_falco_eval.sh tails it.
#
# Idempotent-ish: re-running re-applies config + rules and restarts the service.
# Pin a version with FALCO_VERSION=<x.y.z> for reproducibility (record it in Ch.6).
#
#   sudo ./experiments/falco/install_falco.sh
#   falco --version            # <-- record this in the thesis
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Falco >= 0.41 moved container support to a separately-loaded `container`
# plugin; the stock config references it under load_plugins without a matching
# plugins: entry, so startup fails with "Cannot load plugin 'container': plugin
# config not found for given name". A PRE-0.41 build has container support built
# into the engine -> works out of the box and is the right choice for a
# reproducible thesis (cite the version `falco --version` prints).
#   FALCO_VERSION=auto    (default) auto-pick the newest pre-0.41 version in the repo
#   FALCO_VERSION=0.40.x  pin an exact version (see `apt-cache madison falco`)
#   FALCO_VERSION=latest  newest available (>=0.41 -> also installs the plugin)
FALCO_VERSION="${FALCO_VERSION:-auto}"
LOG_DIR="/var/log/falco"
LOG_FILE="$LOG_DIR/events.json"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo)." >&2; exit 1
fi

echo "=== 1/5 Adding the Falcosecurity apt repository ==="
apt-get update -y
apt-get install -y curl gnupg ca-certificates
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
cat > /etc/apt/sources.list.d/falcosecurity.list <<'EOF'
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF
apt-get update -y

echo "=== 2/5 Installing Falco (modern_ebpf driver, no kmod/DKMS prompt) ==="
# Pre-seed debconf so the package does NOT try to build the kernel module:
echo "falco falco/driver_choice select Modern eBPF" | debconf-set-selections || true
export DEBIAN_FRONTEND=noninteractive

# Resolve 'auto' -> newest pre-0.41 (0.40/0.39/0.38) version actually in the repo.
if [ "$FALCO_VERSION" = "auto" ]; then
    PICK=$(apt-cache madison falco 2>/dev/null | awk '{print $3}' \
           | grep -E '^0\.(40|39|38)\.' | sort -V | tail -1)
    if [ -n "$PICK" ]; then
        echo "  auto-selected newest pre-0.41 version: $PICK"
        FALCO_VERSION="$PICK"
    else
        echo "  [warn] no pre-0.41 version in the repo; falling back to latest (+plugin)."
        echo "         available versions:"; apt-cache madison falco | sed 's/^/           /'
        FALCO_VERSION="latest"
    fi
fi

if [ "$FALCO_VERSION" != "latest" ]; then
    echo "  pinning falco=$FALCO_VERSION (pre-plugin; container support built-in)"
    if ! apt-get install -y --allow-downgrades "falco=$FALCO_VERSION"; then
        echo "  [error] version $FALCO_VERSION not installable. Available versions:"
        apt-cache madison falco | sed 's/^/           /'
        echo "  Re-run with FALCO_VERSION=<one of the above>, or FALCO_VERSION=latest."
        exit 1
    fi
else
    apt-get install -y falco
    # Latest (>=0.41) needs the container plugin; install it so startup succeeds.
    echo "  latest selected -> installing the container plugin (>=0.41 needs it)"
    if command -v falcoctl >/dev/null 2>&1; then
        falcoctl artifact install container \
            || echo "  [warn] container plugin install failed; if startup errors with"
        echo "         'plugin config not found', drop 'container' from load_plugins."
    else
        echo "  [warn] falcoctl not found; install the container plugin manually."
    fi
fi

echo "=== 3/5 Installing the custom rules (idiomatic outbound + illustrative E2) ==="
mkdir -p /etc/falco/rules.d
install -m 0644 "$HERE/custom_rules.yaml" /etc/falco/rules.d/thesis_custom_rules.yaml

echo "=== 4/5 Configuring JSON + file output -> $LOG_FILE ==="
mkdir -p "$LOG_DIR"
: > "$LOG_FILE"
# Robust, YAML-aware config edit (the earlier regex approach was fragile: it
# could leave NO output channel enabled -> "No output configured" at startup).
# Uses PyYAML so duplicate keys collapse and the result is always valid YAML.
command -v python3 >/dev/null && python3 -c "import yaml" 2>/dev/null \
    || apt-get install -y python3-yaml
python3 - "$LOG_FILE" <<'PY'
import sys, shutil, yaml
log = sys.argv[1]
path = "/etc/falco/falco.yaml"
shutil.copy(path, path + ".bak")                 # keep the original
with open(path) as f:
    cfg = yaml.safe_load(f) or {}

# Enable BOTH stdout (handy for debugging) and file output, in JSON.
cfg.setdefault("stdout_output", {})["enabled"] = True
fo = cfg.setdefault("file_output", {})
fo["enabled"] = True
fo["keep_alive"] = False
fo["filename"] = log
cfg["json_output"] = True
cfg["json_include_output_property"] = True

# modern_ebpf engine (Falco >= 0.37 uses the `engine:` block).
eng = cfg.get("engine")
if not isinstance(eng, dict):
    eng = {}
eng["kind"] = "modern_ebpf"
cfg["engine"] = eng

with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
print("  patched", path, "(backup ->", path + ".bak)")
PY

echo "=== 5/5 Selecting and starting the modern_ebpf service unit ==="
# The Falco deb ships ONE unit per driver (falco-modern-bpf / falco-bpf /
# falco-kmod); the generic 'falco' unit often defaults to the kmod driver and
# crash-loops when no kernel module is built. Each per-driver unit's ExecStart
# passes its own `-o engine.kind=...`, which OVERRIDES falco.yaml -- so we must
# pick the right unit, not just set engine.kind in the file.
SVC=""
for u in falco-modern-bpf falco; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${u}\.service"; then
        SVC="$u"; break
    fi
done
if [ -z "$SVC" ]; then
    echo "  [warn] no falco systemd unit found; start manually: sudo falco &"
else
    # Stop/disable the other driver units so only one falco runs.
    for u in falco falco-bpf falco-kmod; do
        [ "$u" = "$SVC" ] || systemctl disable --now "$u" 2>/dev/null || true
    done
    systemctl daemon-reload
    systemctl enable --now "$SVC" 2>/dev/null || systemctl restart "$SVC"
    sleep 4
    if systemctl is-active --quiet "$SVC"; then
        echo "  $SVC.service: active"
    else
        echo "  [warn] $SVC not active. Run 'sudo falco' in the foreground to see the error."
    fi
fi
echo "  (the falco PROCESS is named 'falco' regardless of unit -> bench/run scripts unaffected)"

echo ""
echo "Falco version: $(falco --version 2>/dev/null | head -1)  <-- RECORD THIS"
echo "Driver       : modern_ebpf (CO-RE)"
echo "JSON log     : $LOG_FILE"
echo "Custom rules : /etc/falco/rules.d/thesis_custom_rules.yaml"
echo ""
echo "Verify rules loaded:   journalctl -u 'falco*' --no-pager | grep -iE 'rules loaded|modern_ebpf|initialized'"
echo "Then run the eval:      ./experiments/falco/run_falco_eval.sh"
