# GCID — Artifact / Reproducibility Manifest

This artifact lets an independent reader reproduce every number in the paper and verify that the
baselines (Falco, Tetragon) genuinely cannot express the token→API correlation on-host. Reviewers
across rounds named artifact release as the single highest-leverage credibility fix; this is the
manifest for it. **To release: create a public repo, copy the files below, fill the redactions, push.**
(Do this from a clean checkout, not the live VM, since this VM has credentials connected.)

## What to include

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

## Environment (pin in the README)
- Single-node k3s v1.35.5+k3s1, Ubuntu 24.04, **kernel 6.8**, 4 vCPU / 8 GB. (State this kernel for
  *every* experiment, not just the real-escape one — a reviewer asked.)
- Falco 0.40.0 (modern-eBPF). Tetragon via Cilium Helm chart. BCC for the agent.

## Baseline-fairness evidence to foreground in the README
- Falco was given a *competent operator ruleset for every scenario* (the file above), not defaults;
  Falco wins 7/8. The one failure (E2) is architectural, not a tuning gap.
- Tetragon was given hand-written stateful TracingPolicies for both halves of the chain; it emits both
  as independent per-event observations with no chain event. Include the captured `events.json`.
- Note explicitly what is NOT claimed: a Falco/Tetragon → external-SIEM pipeline *can* correlate
  off-host; the claim is strictly about on-host, at-detection-time correlation.

## Redactions before release
- Remove any `host credential files`, kubeconfigs, DO tokens, or VM-specific IPs/hostnames from logs/scripts.
- `attack_cve.sh` stays guarded (`CONFIRM_DETONATE=yes`); ship `CVE_SAFETY.md` alongside it.

## Paper statement (already added to the manuscript)
"Artifact availability: the GCID agent, the exact Falco and Tetragon configurations, all attack and
benign harnesses, and the raw result logs are available at <REPO-URL> to reproduce every reported
measurement."
