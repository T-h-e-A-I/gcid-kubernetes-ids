# GCID — Consolidated Experiment Results

Single-node k3s (Ubuntu 24.04, kernel 6.8, 4 vCPU / 8 GB) unless noted; Online Boutique benign
workload. All raw metrics under `results/<name>/metrics_*.json`. CIs are Wilson 95% unless noted.

## Detection & the Falco head-to-head (canonical run `results/run_full_20260618/`)

| Metric | Value |
|---|---|
| Per-scenario reliability | 8/8 scenarios ≥99.9% (1,000 replays each; all 1000/1000 except E5 999/1000) |
| Lead result — E2 token-exfil chain | **Falco 0/100** (CI [0, 3.7%]) vs **GCID 100/100** (CI [96.3%, 100%]) |
| Falco other scenarios | 7/8 at 100% (every single-action escape + visible connect) |
| Detection latency | 544 ms mean / 1,700 ms p95; single-action ~330 ms; E2 chain 1,698 ms |

## Second correlation family — E6 data-exfil (`results/run_gate6_20260621/`, `gate6_data_exfil.sh`)

Added to answer the "advantage rests on one attack family" review point. A structurally distinct
correlation-only chain: read sensitive mounted secret (`/etc/app-secrets/`) → connect to an **external**
endpoint. Disjoint benign populations (3 config-readers that only read; 3 external-callers that only
egress) make each constituent event non-discriminating.

| Metric | Value |
|---|---|
| GCID detection | **90/90 = 100%** (Wilson CI [95.9%, 100%]), **0 benign FP** |
| Falco (best per-event rules, 0.40.0 modern_ebpf) | **0 chain detections**; read-rule fires on 3 benign reader pods (92 events), connect-rule fires on 3 benign caller pods (86 events) — neither isolates the attacker |
| Takeaway | same bounded-state read→connect primitive expresses **two** distinct families (credential abuse + data exfiltration) → mechanism generalizes, not a one-off |

## Token→API precision (the C3 precision story)

| Experiment | Result | File |
|---|---|---|
| **GATE 1** — bare rule vs benign API clients (no scoping) | **40 FP, 0 attacks**; 25/25 driven sessions (100%) | `gate1/` |
| **GATE 1b** — + service-account allowlist (small demo) | 40→1 FP; 33/33 resolved suppressed; attacker 5/5 | `gate1b/` |
| **GATE 1c** — realistic, churning, API-heavy (real operators) | **3/542 = 0.55% FPR** (CI [0.19%, 1.61%], ≈6 FP/hr per node); 539 suppressed; attacker **12/12** | `gate1c/` |
| GATE 1c cold-start fix (resolver `/proc/cgroup`) | benign FP **27→3** (FPR 4.98%→0.55%); attacker 12/12 | `gate1c/metrics_gate1c_*.json` |

## Adaptive adversary & the correlation window

| Experiment | Result | File |
|---|---|---|
| **GATE 3** — dwell sweep (detection vs read→connect delay) | chain detection **100% at ≤58 s, 0% at ≥62 s** (60 s window); `kube-api-access` fires at every delay | `gate3/` |
| **GATE 4** — window–precision frontier (sweep 15/60/300 s) | benign FP **75→93→176 without scoping**, **0 at every window with scoping**; detection ceiling = window (fast 5 s caught, slow W+30 missed) | `gate4/` |
| | → identity-scoping **decouples window from precision**; 60 s is a design choice, not a cherry-picked point | |

## Overhead & scalability (`results/metrics_workload.json`, `metrics_b3_scalability.json`)

| Metric | Baseline | GCID (eBPF) | auditd |
|---|---|---|---|
| Online Boutique throughput | 51.0 RPS | 49.3 RPS (**−3.4%**) | — |
| `openat` microbench (ops/s) | 318.9k | 295.8k (**+7.3%**) | 15.4k (**+95.2%**) |
| `execve` microbench (ops/s) | 806 | 841 (≈0%) | 652 (**+19.0%**) |
| Agent CPU | — | 0.05% | 0.08% (p=0.47, n.s.) |
| Agent RSS | — | 238 MB | 13 MB (~18×) |
| Graph: no-prune vs 60 s-prune | — | 80,580 nodes / 324 MB rising | 37,466 / 282 MB plateau |

## False positives (escape/lateral rules)

| Metric | Value |
|---|---|
| Benign baseline FPR (escape/lateral rules) | 0/445 over 1 h → 0%, 95% CI [0, 0.67%] (feasibility, not production) |
| Note | Online Boutique never calls the kube-API, so the token→API rule is measured separately (GATE 1c) |

## Real-escape validation (`results/cve_20260619/`)

| Technique | Detection | Kernel |
|---|---|---|
| `core_pattern` host code-execution | detected (`file-boundary`) | 6.8 (patched) |
| Privileged host-mount escape | detected (`privileged-mount`, warm pod) | 6.8 (patched) |

## Adversarial robustness (initial; `results/metrics_b2_adversarial.json`)

| Evasion | Result |
|---|---|
| R1 new mount API (`move_mount`) | found + closed (E5 0→999/1000) |
| R2 BoSC padding (precursor-free pidfd+setns) | no evasion (setns-anchored) |
| R3 slow chain (≥62 s gap) | **succeeds** — total bypass of the chain alert past the 60 s window (GATE 3) |
| R4 renamed host binary | no evasion (boundary-anchored) |

## Cross-node / multi-node (`results/multinode_overnight_20260619/`, N=500)

| Metric | Value |
|---|---|
| Per-leg detection | leg1 + leg2 each **500/500 = 100%** |
| End-to-end offline stitch | **396/500 = 79.2%** (CI [75.6%, 82.8%]) |
| 20.8% shortfall cause | host1 IP→pod resolution latency (499 resolved / 501 not, of 1000 leg-1 alerts) — null join key, *not* lost telemetry |
| Mechanism | offline SIEM-style alert-stitch on pod identity; **not** a distributed graph |
