# GCID — Graph-Correlated Intrusion Detection for Kubernetes

Research artifact for the paper *"GCID: Graph-Correlated Intrusion Detection for Kubernetes —
Delivering `auditd`-Class Event Correlation at eBPF Cost"* (Awesh Islam, Tausif Rashid, BUET).

GCID is a single Kubernetes-native runtime agent that builds a provenance/dependency graph from eBPF
syscall telemetry (not `auditd`), with in-kernel cgroup attribution, and detects both container-escape
(vertical) and lateral-movement (horizontal) attacks. Detection runs on bounded per-cgroup state; the
graph serves explainability. This artifact reproduces every measurement in the paper and the
head-to-head comparisons against Falco and Tetragon.

## Layout
```
src/             eBPF agent (ebpf_agent.py, ebpf_probes.c), auditd baseline
analysis/        scoring (ADR/FPR/CIs, score.py) + cross-node stitch
experiments/     attack + benign harnesses; falco/ (exact rules); tetragon/ (policies); manifests/
results/         metrics_*.json for every experiment + EXPERIMENTS_SUMMARY.md (all numbers + CIs)
ARTIFACT.md      detailed reproduction manifest
```

## Environment
Single-node k3s v1.35.5+k3s1, Ubuntu 24.04, **kernel 6.8**, 4 vCPU / 8 GB; Online Boutique workload;
Falco 0.40.0 (modern-eBPF); Tetragon (Cilium Helm chart); BCC for the agent. (Kernel 6.8 applies to
*all* experiments, not just the real-escape validation.)

## Reproducing the key results
- **Detection + Falco head-to-head (§6.1):** `experiments/run_full_clean.sh`; Falco rules in
  `experiments/falco/custom_rules.yaml`.
- **Tetragon head-to-head (§2.5):** `experiments/tetragon/run_tetragon_test.sh` with the two
  `policy-*.yaml`; shows Tetragon emits both halves as independent per-event observations, no chain event.
- **Token→API precision + cold-start fix (§6.3.1):** `experiments/gate1c_realistic_fpr.sh`.
- **Adaptive-adversary dwell curve (§6.6):** `experiments/gate3_dwell_sweep.sh`.
- **Window–precision frontier (§6.8):** `experiments/gate4_window_roc.sh` (with/without `ALLOW=`).
- **E6 data-exfil (second correlation scenario):** `experiments/gate6_data_exfil.sh` (manifest `manifests/gate6-data-exfil.yaml`); Falco contrast in `experiments/falco/run_e6_falco_contrast.sh` with `falco/e6_rules.yaml`.
- **Overhead / scalability (§6.5, §6.8):** `experiments/run_overhead_3way.sh`, `run_b3_scalability.sh`.
- **Cross-node (§6.9):** `experiments/run_multinode_overnight.sh` (`<HOST2_IP>` = the worker node).

## Baseline fairness (stated up front)
Falco was given a competent operator ruleset for **every** scenario (not defaults) and wins 7/8;
Tetragon was given hand-written stateful `TracingPolicy` objects for both halves of the chain. The
claim is specifically about **on-host, at-detection-time** correlation; a Falco/Tetragon → external
SIEM pipeline can correlate off-host, and we do not claim otherwise.

## Safety
`experiments/attack_cve.sh` is guarded (`CONFIRM_DETONATE=yes`) and non-destructive; see
`experiments/CVE_SAFETY.md`. Run only on a disposable VM with a snapshot.

## License
Released under the MIT License. See [LICENSE](LICENSE).
