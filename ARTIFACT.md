# GCID — Artifact / Reproducibility Manifest

This artifact lets an independent reader reproduce every number in the paper and verify that the
baselines (Falco, Tetragon) genuinely cannot express the token→API correlation on-host.

## Contents

| Component | Path | Reproduces |
|---|---|---|
| eBPF agent (detection) | `src/ebpf_agent.py`, `src/ebpf_probes.c` | the whole system |
| auditd baseline | `src/auditd_agent.py` | overhead 3-way |
| Scoring/analysis | `analysis/score.py`, `analysis/stitch_multinode.py` | ADR/FPR/CIs, cross-node |
| **Falco config** (exact, version-pinned) | `experiments/falco/custom_rules.yaml` | the Falco head-to-head (§6.1) |
| **Tetragon policies** (exact) | `experiments/tetragon/policy-*.yaml`, `run_tetragon_test.sh` | the Tetragon head-to-head (§2.5) |
| Attack harnesses | `experiments/attack_*.sh`, `attack_cve.sh` (guarded) | all 8 scenarios + 2 real escapes |
| Benign / precision drivers | `experiments/gate1*.sh`, `gate3_*.sh`, `gate4_*.sh`, `manifests/*.yaml` | GATE 1/1b/1c/3/4 |
| Multinode | `experiments/run_multinode*.sh`, `manifests/multinode-*.yaml` | §6.9 N=500 |
| Overhead bench | `experiments/run_overhead_3way.sh`, `run_b3_scalability.sh` | §6.5, §6.8 |
| Raw results + metrics | `results/<gate>/metrics_*.json`, `results/EXPERIMENTS_SUMMARY.md` | every table/figure |

## Environment
- Single-node k3s v1.35.5+k3s1, Ubuntu 24.04, **kernel 6.8**, 4 vCPU / 8 GB. This kernel applies to
  *every* experiment, not just the real-escape one.
- Falco 0.40.0 (modern-eBPF). Tetragon via Cilium Helm chart. BCC for the agent.

## Baseline fairness
- Falco was given a *competent operator ruleset for every scenario* (`experiments/falco/custom_rules.yaml`), not defaults;
  Falco wins 7/8. The one failure (E2) is architectural, not a tuning gap.
- Tetragon was given hand-written stateful TracingPolicies for both halves of the chain; it emits both
  as independent per-event observations with no chain event.
- What is NOT claimed: a Falco/Tetragon → external-SIEM pipeline *can* correlate off-host; the claim
  is strictly about on-host, at-detection-time correlation.

## Safety
- `attack_cve.sh` is guarded (`CONFIRM_DETONATE=yes`) and non-destructive; see `CVE_SAFETY.md`.
