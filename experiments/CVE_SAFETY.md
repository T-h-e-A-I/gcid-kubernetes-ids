# B1 Real-CVE Escape Harness — Safety & Runbook

`attack_cve.sh` performs **genuine** privileged-container escapes (not the benign stand-ins in
`attack_escape.sh`). Read this before running it.

## Why techniques, not numbered CVEs

This host is **kernel 6.8 + cgroup v2 (unified only) + modern k3s runc**. The classic numbered
container-escape CVEs are **patched / not applicable** here and will not detonate:

| CVE | Why it won't fire on this host |
|---|---|
| CVE-2022-0492 (cgroup release_agent) | `release_agent` is cgroup **v1** only; this host is v2-only |
| CVE-2019-5736 (runc /proc/self/exe) | needs vulnerable runc; k3s ships patched runc |
| CVE-2024-21626 (Leaky Vessels runc) | patched in current runc |
| CVE-2022-0185 / Dirty Pipe (CVE-2022-0847) | kernel ≤5.16; 6.8 is patched. Dirty Pipe is also out-of-scope (kernel-bypass) |

We instead detonate the **real, modern, version-independent** privileged-container escape
*techniques*, which produce the genuine syscall sequences the detector must catch. This is
*stronger* evidence than a version-locked old CVE: it proves detection of a real exploit path that
works on a current, patched system.

| ID | Technique | Distinct primitive | Expected rule |
|---|---|---|---|
| C1 | Privileged host-disk mount + chroot (READ-ONLY) | mount-based escape | `privileged-mount` + `file-boundary` |
| C2 | `core_pattern` host code-exec | proc-write → host exec | `file-boundary` |

## Blast-radius / credential safety (the worry, answered)

- The exploits run **locally**; nothing is transmitted or published. There is no internet "release."
- A successful escape grants host code-exec **to the payload we write** — and our payloads only
  read a host file / `touch` a marker. They **never** read or exfiltrate host secrets; the payloads
  do not touch any credential files on the host, and the techniques have no interest in them.
- Detection fires on the **syscall behavior**, so we deliberately keep the destructive end harmless.

## Built-in safeguards (in the script)

1. **Detonation guard** — refuses to run unless `CONFIRM_DETONATE=yes`. No accidental fire.
2. **C1 mounts the host disk READ-ONLY** (`-o ro`) → cannot corrupt the host filesystem.
3. **C2 backs up and restores `/proc/sys/kernel/core_pattern`** via an `EXIT` trap, so the host
   crash handler is restored even if the script is interrupted. (Leaving it pointed at a deleted
   payload would break future host core dumps — this is the one real operational risk, and it is
   handled.)
4. **Cleanup** removes the payload + markers and unmounts.

## Pre-run checklist

1. **Take a VM snapshot** (one-click rollback if anything misbehaves).
2. Ensure no other run is using the cluster/agent.
3. Confirm the eBPF agent is running and writing `alerts.jsonl`.
4. Run: `CONFIRM_DETONATE=yes GROUND_TRUTH=results/ground_truth_cve.jsonl ./experiments/attack_cve.sh`
5. After: confirm `core_pattern` restored (`cat /proc/sys/kernel/core_pattern`), markers gone,
   no leftover mounts (`mount | grep hostdisk`).
6. Score: confirm C1 → `privileged-mount`, C2 → `file-boundary` in the alerts.

## Note on scope

Publishing PoCs for already-public, patched issues is standard security-research practice. This
artifact ships the detection agent plus non-destructive reproductions and *describes* these escape
tests; it does not ship weaponized exploit code.
