#!/usr/bin/env python3
# =============================================================================
# score.py -- Offline scoring & figure generation for the thesis experiments
# -----------------------------------------------------------------------------
# Consumes the artifacts produced by the experiment scripts and computes the
# metrics + figures that go into Chapter 6:
#
#   Experiment A (detection effectiveness):
#     score.py <alerts.jsonl> <ground_truth.jsonl> [--benign-window SEC]
#       -> ADR (Attack Detection Rate), FPR, mean detection latency, per-rule
#          breakdown; emits results/metrics_detection.json + a bar figure.
#
#   Experiment B macro (agent overhead):
#     score.py --overhead <overhead_ebpf.txt> <overhead_auditd.txt>
#       -> mean +/- std CPU% and RSS for each agent, Welch's t-test p-value;
#          emits results/metrics_overhead.json + a comparison figure.
#
#   Experiment B micro (program types):
#     score.py --program-types <program_types.csv>
#       -> mean ops/sec per variant + % overhead vs base; emits a bar figure.
#
# matplotlib is optional: if absent, numeric results are still printed/saved and
# figure generation is skipped with a warning.
# =============================================================================
import argparse
import json
import statistics
import sys

try:
    import matplotlib
    matplotlib.use("Agg")  # headless (VM / CI friendly)
    import matplotlib.pyplot as plt
    HAVE_PLT = True
except ImportError:
    HAVE_PLT = False

LATENCY_MATCH_WINDOW = 10.0  # s: an alert counts for a scenario if within this


# -----------------------------------------------------------------------------
# Experiment A: detection effectiveness
# -----------------------------------------------------------------------------
def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _fpr_ci95(fp, n):
    """95% CI for the false-positive rate. Rule-of-three [0, 3/n] when fp==0
    (Hanley & Lippman-Hand); Wilson score interval otherwise. Returns
    (point, lo, hi) as fractions, or None when n==0."""
    if not n:
        return None
    if fp == 0:
        return (0.0, 0.0, 3.0 / n)
    p = fp / n
    z = 1.96
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (p, max(0.0, centre - half), min(1.0, centre + half))


def score_detection(alerts_path, gt_path, benign_window, events_path=None):
    alerts = load_jsonl(alerts_path)
    truth = load_jsonl(gt_path)

    if not truth:
        print("No ground-truth records found.", file=sys.stderr)
        return

    # Earliest attack timestamp -> everything before it (within benign_window)
    # is benign-phase activity used to estimate the false-positive rate.
    first_attack = min(t["ts"] for t in truth)
    benign_start = first_attack - benign_window if benign_window else 0

    # Match each ground-truth occurrence (there are now ~TRIALS of each
    # scenario) to the nearest unused alert with the expected rule within the
    # window. matched_alert_ids prevents one alert satisfying two occurrences.
    matched_alert_ids = set()
    occurrences = []  # one row per attack execution across all trials
    for t in truth:
        best = None
        for i, a in enumerate(alerts):
            if i in matched_alert_ids or a.get("rule") != t["expect_rule"]:
                continue
            dt = a["ts"] - t["ts"]
            if 0 <= dt <= LATENCY_MATCH_WINDOW:
                if best is None or dt < best[1]:
                    best = (i, dt)
        if best is not None:
            matched_alert_ids.add(best[0])
            occurrences.append({"scenario": t["scenario"],
                                "trial": t.get("trial", 1),
                                "detected": True,
                                "latency_ms": round(best[1] * 1000.0, 1)})
        else:
            occurrences.append({"scenario": t["scenario"],
                                "trial": t.get("trial", 1),
                                "detected": False, "latency_ms": None})

    # ---- aggregate per scenario across trials (mean +/- std) ----------------
    by_scenario = {}
    for o in occurrences:
        by_scenario.setdefault(o["scenario"], []).append(o)
    per_scenario = []
    for name in sorted(by_scenario):
        runs = by_scenario[name]
        n = len(runs)
        det = sum(1 for r in runs if r["detected"])
        lats = [r["latency_ms"] for r in runs if r["detected"]]
        per_scenario.append({
            "scenario": name,
            "trials": n,
            "detected": det,
            "detection_rate": round(det / n, 3) if n else 0.0,
            "latency_ms_mean": round(statistics.mean(lats), 1) if lats else None,
            "latency_ms_std": round(statistics.pstdev(lats), 1) if len(lats) > 1 else 0.0,
        })

    tp = sum(1 for o in occurrences if o["detected"])
    total = len(occurrences)
    fn = total - tp
    all_lats = [o["latency_ms"] for o in occurrences if o["detected"]]
    # Macro ADR = mean of per-scenario detection rates (+/- std across scenarios)
    rates = [s["detection_rate"] for s in per_scenario]
    # False positives = benign-phase alerts, EXCLUDING informational signals
    # (e.g. demoted suspicious-shell, v2 P1-4) which are context, not detections.
    fp = sum(1 for a in alerts
             if benign_start <= a["ts"] < first_attack
             and a.get("severity") != "info")

    # FPR denominator: benign-phase events the agent actually processed in the
    # same [benign_start, first_attack) window as the FP numerator. Without this
    # count an "FPR = 0" is meaningless (no denominator, no CI). #A2.
    benign_events = None
    fpr = None
    fpr_ci = None
    if events_path:
        events = load_jsonl(events_path)
        benign_events = sum(1 for e in events
                            if benign_start <= e["ts"] < first_attack)
        ci = _fpr_ci95(fp, benign_events)
        if ci:
            fpr, lo, hi = ci
            fpr_ci = [round(lo, 6), round(hi, 6)]

    result = {
        "experiment": "detection_effectiveness",
        "trials_per_scenario": max((s["trials"] for s in per_scenario),
                                   default=0),
        "attacks_total": total,
        "detected_tp": tp,
        "missed_fn": fn,
        "attack_detection_rate_micro": round(tp / total, 4) if total else 0.0,
        "attack_detection_rate_macro_mean": round(statistics.mean(rates), 4) if rates else 0.0,
        "attack_detection_rate_macro_std": round(statistics.pstdev(rates), 4) if len(rates) > 1 else 0.0,
        "mean_latency_ms": round(statistics.mean(all_lats), 1) if all_lats else None,
        "std_latency_ms": round(statistics.pstdev(all_lats), 1) if len(all_lats) > 1 else 0.0,
        "p95_latency_ms": (round(sorted(all_lats)[int(0.95 * len(all_lats)) - 1], 1)
                           if len(all_lats) >= 2 else None),
        "false_positives_benign_phase": fp,
        "benign_events_total": benign_events,
        "benign_window_s": benign_window,
        "fpr": round(fpr, 6) if fpr is not None else None,
        "fpr_ci95": fpr_ci,
        "per_scenario": per_scenario,
    }
    # Derive a distinct output name from the alerts filename so scoring the
    # auditd baseline (alerts_auditd.jsonl) does NOT overwrite the eBPF results:
    #   alerts.jsonl        -> metrics_detection.json
    #   alerts_auditd.jsonl -> metrics_detection_auditd.json
    import os
    stem = os.path.basename(alerts_path).rsplit(".", 1)[0]
    tag = stem[len("alerts"):] if stem.startswith("alerts") else "_" + stem
    result["source"] = stem
    _save("results/metrics_detection%s.json" % tag, result)
    _print_block("DETECTION EFFECTIVENESS (Experiment A) [%s]" % stem, result)

    if HAVE_PLT:
        _fig_detection(per_scenario, "results/fig_detection%s.png" % tag)


def _fig_detection(per_scenario, path):
    names = [s["scenario"] for s in per_scenario]
    rates = [s["detection_rate"] for s in per_scenario]
    colors = ["#2a9d8f" if r >= 0.99 else ("#e9c46a" if r > 0 else "#e76f51")
              for r in rates]
    plt.figure(figsize=(8, 4))
    plt.bar(names, rates, color=colors)
    plt.ylim(0, 1.05)
    plt.ylabel("Detection rate (over trials)")
    plt.title("Per-scenario detection rate")
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    print("  figure -> %s" % path)


# -----------------------------------------------------------------------------
# Experiment B macro: agent overhead
# -----------------------------------------------------------------------------
def _parse_pidstat_col(path, header_token):
    """Extract one metric from a per-second sample file.

    Two accepted formats:
      1. Plain floats, one per line -- the fine-grained /proc/<pid>/stat %CPU
         sampler (one %CPU value per second). Used for CPU since pidstat's %CPU
         rounds sub-1% usage to 0.00.
      2. pidstat single-resource rows (still used for memory). For both
         `pidstat -u` and `-r` the metric sits 3rd-from-last:
           -u:  ... %CPU  CPU  Command   -> %CPU
           -r:  ... RSS   %MEM Command   -> RSS
    `header_token` (\"%CPU\"/\"RSS\") only skips pidstat header lines.
    """
    vals = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format 1: a bare float (the fine-grained CPU sampler).
            try:
                vals.append(float(line))
                continue
            except ValueError:
                pass
            # Format 2: pidstat row.
            if (header_token in line or "Average" in line or "Linux" in line
                    or "Command" in line):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                vals.append(float(parts[-3]))   # 3rd-from-last = metric
            except ValueError:
                continue
    return vals


def _mem_path(cpu_path):
    """Best-effort sibling memory file (overhead_X_cpu.txt -> _mem.txt)."""
    return cpu_path.replace("_cpu.", "_mem.")


def _csv_tag(path, base):
    """Derive an output tag from a CSV filename so a separate comparator file
    (e.g. workload_overhead_falco.csv) is scored into its own metrics/figure
    instead of overwriting the canonical one:
      workload_overhead.csv        -> ''        (default, back-compat)
      workload_overhead_falco.csv  -> '_falco'  -> metrics_workload_falco.json
    `base` is the canonical stem ('workload_overhead' / 'traffic_impact')."""
    import os
    stem = os.path.basename(path).rsplit(".", 1)[0]
    return stem[len(base):] if stem.startswith(base) else "_" + stem


def _overhead_label(path):
    """Derive the comparator label from a CPU-sample filename so a non-auditd
    comparator (e.g. Falco) is scored into its OWN output files rather than
    overwriting the eBPF-vs-auditd result:
      overhead_auditd_cpu.txt -> 'auditd'  (default, back-compat)
      overhead_falco_cpu.txt  -> 'falco'   -> metrics_overhead_falco.json
    Falls back to 'auditd' if the name does not match."""
    import os
    import re
    m = re.match(r"overhead_(.+)_cpu", os.path.basename(path))
    return m.group(1) if m else "auditd"


def score_overhead(ebpf_path, comparator_path):
    ec = _parse_pidstat_col(ebpf_path, "%CPU")
    ac = _parse_pidstat_col(comparator_path, "%CPU")
    import os

    def _mem(cpu_path):
        mp = _mem_path(cpu_path)
        if mp != cpu_path and os.path.exists(mp):
            return _parse_pidstat_col(mp, "RSS")
        return [0]
    er = _mem(ebpf_path)
    ar = _mem(comparator_path)
    if not ec or not ac:
        print("Could not parse pidstat CPU samples.", file=sys.stderr)
        return

    # The comparator (auditd by default, or e.g. 'falco') determines BOTH the
    # JSON key and the output filename, so Falco never clobbers the auditd table.
    label = _overhead_label(comparator_path)
    tag = "" if label == "auditd" else "_" + label

    pval = _welch_p(ec, ac)
    result = {
        "experiment": "agent_overhead",
        "comparator": label,
        "ebpf": {"cpu_mean": round(statistics.mean(ec), 2),
                 "cpu_std": round(statistics.pstdev(ec), 2),
                 "rss_kb_mean": round(statistics.mean(er), 1)},
        label: {"cpu_mean": round(statistics.mean(ac), 2),
                "cpu_std": round(statistics.pstdev(ac), 2),
                "rss_kb_mean": round(statistics.mean(ar), 1)},
        "cpu_reduction_pct": round(
            100 * (statistics.mean(ac) - statistics.mean(ec))
            / statistics.mean(ac), 1) if statistics.mean(ac) else None,
        "welch_t_pvalue": pval,
        "n_samples": {"ebpf": len(ec), label: len(ac)},
    }
    _save("results/metrics_overhead%s.json" % tag, result)
    _print_block("AGENT OVERHEAD vs %s (Experiment B macro)" % label, result)

    if HAVE_PLT:
        plt.figure(figsize=(5, 4))
        plt.bar(["eBPF", label],
                [result["ebpf"]["cpu_mean"], result[label]["cpu_mean"]],
                yerr=[result["ebpf"]["cpu_std"], result[label]["cpu_std"]],
                color=["#2a9d8f", "#e76f51"], capsize=6)
        plt.ylabel("CPU utilisation (%)")
        plt.title("Agent CPU overhead (lower is better)")
        plt.tight_layout()
        plt.savefig("results/fig_overhead%s.png" % tag, dpi=150)
        print("  figure -> results/fig_overhead%s.png" % tag)


def _welch_p(a, b):
    """Welch's t-test p-value without SciPy (normal approximation for the
    t-statistic; adequate for the large n pidstat produces). If SciPy is
    available we use the exact distribution."""
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    na, nb = len(a), len(b)
    se = (va / na + vb / nb) ** 0.5
    if se == 0:
        return 0.0
    t = (ma - mb) / se
    try:
        from scipy import stats
        df = (va / na + vb / nb) ** 2 / (
            (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
        return round(2 * stats.t.sf(abs(t), df), 6)
    except ImportError:
        # Normal approximation: p = 2 * (1 - Phi(|t|))
        import math
        p = 2 * (1 - 0.5 * (1 + math.erf(abs(t) / math.sqrt(2))))
        return round(p, 6)


# -----------------------------------------------------------------------------
# Experiment B micro: program-type overhead
# -----------------------------------------------------------------------------
def score_program_types(csv_path):
    import csv
    data = {}
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            data.setdefault(row["variant"], []).append(float(row["ops_per_sec"]))
    means = {k: statistics.mean(v) for k, v in data.items()}
    base = means.get("base", max(means.values()))
    result = {"experiment": "program_types", "mean_ops_per_sec": {},
              "overhead_pct_vs_base": {}}
    order = ["base", "kprobe", "tracepoint", "raw_tracepoint"]
    for k in [x for x in order if x in means]:
        result["mean_ops_per_sec"][k] = round(means[k], 0)
        result["overhead_pct_vs_base"][k] = round(100 * (base - means[k]) / base, 1)
    _save("results/metrics_program_types.json", result)
    _print_block("eBPF PROGRAM-TYPE OVERHEAD (Experiment B micro)", result)

    if HAVE_PLT:
        ks = [k for k in order if k in means]
        plt.figure(figsize=(6, 4))
        plt.bar(ks, [means[k] for k in ks], color="#264653")
        plt.ylabel("openat throughput (ops/sec)")
        plt.title("Program-type overhead (higher = less overhead)")
        plt.tight_layout()
        plt.savefig("results/fig_program_types.png", dpi=150)
        print("  figure -> results/fig_program_types.png")


# -----------------------------------------------------------------------------
# Experiment B macro (PRIMARY): workload throughput degradation
# -----------------------------------------------------------------------------
def score_workload(csv_path):
    """Compute the % slowdown each monitor imposes on each workload, relative to
    the unmonitored baseline (Bertinatto-style). Grouped per syscall workload
    (execve, openat, ...), since each surfaces a different monitored syscall's
    cost. Backward-compatible with the old single-workload `execs_per_sec` CSV."""
    import csv
    from collections import defaultdict
    # data[workload][condition] = [ops...]
    data = defaultdict(lambda: defaultdict(list))
    # Parse POSITIONALLY by column count, not by header name. This is robust to a
    # stale/mismatched header (e.g. an old 3-column `condition,repeat,execs_per_sec`
    # header left on a file that now holds 4-column rows), which otherwise makes
    # DictReader read the repeat-index column as the ops value.
    #   4 cols -> condition, workload, repeat, ops   (current schema)
    #   3 cols -> condition, repeat, ops             (old single-workload schema)
    with open(csv_path) as f:
        for cells in csv.reader(f):
            if not cells:
                continue
            # Skip any header row (a row whose last cell is not numeric).
            try:
                ops = float(cells[-1])
            except ValueError:
                continue
            if len(cells) >= 4:
                cond, wl = cells[0], cells[1]
            elif len(cells) == 3:
                cond, wl = cells[0], "execve"
            else:
                continue
            data[wl][cond].append(ops)

    result = {"experiment": "workload_overhead", "by_workload": {}}
    order = ["baseline", "ebpf", "auditd"]
    for wl in sorted(data):
        conds = data[wl]
        if "baseline" not in conds:
            print("workload '%s': no baseline, skipping" % wl, file=sys.stderr)
            continue
        base = statistics.mean(conds["baseline"])
        entry = {"mean_ops_per_sec": {}, "std_ops_per_sec": {},
                 "overhead_pct_vs_baseline": {}}
        keys = [k for k in order if k in conds] + \
               [k for k in conds if k not in order]
        for k in keys:
            v = conds[k]
            entry["mean_ops_per_sec"][k] = round(statistics.mean(v), 0)
            entry["std_ops_per_sec"][k] = round(
                statistics.pstdev(v), 0) if len(v) > 1 else 0.0
            entry["overhead_pct_vs_baseline"][k] = round(
                100 * (base - statistics.mean(v)) / base, 2)
        result["by_workload"][wl] = entry
    tag = _csv_tag(csv_path, "workload_overhead")
    result["source"] = csv_path
    _save("results/metrics_workload%s.json" % tag, result)
    _print_block("WORKLOAD OVERHEAD (Experiment B macro, primary)%s"
                 % ((" [%s]" % tag.lstrip("_")) if tag else ""), result)

    if HAVE_PLT and result["by_workload"]:
        wls = list(result["by_workload"].keys())
        conds = order + [c for wl in wls
                         for c in result["by_workload"][wl]["overhead_pct_vs_baseline"]
                         if c not in order]
        conds = [c for c in dict.fromkeys(conds)
                 if any(c in result["by_workload"][wl]["overhead_pct_vs_baseline"]
                        for wl in wls)]
        x = list(range(len(wls)))
        w = 0.8 / max(len(conds), 1)
        colors = {"baseline": "#264653", "ebpf": "#2a9d8f", "auditd": "#e76f51"}
        plt.figure(figsize=(7, 4))
        for i, c in enumerate(conds):
            vals = [result["by_workload"][wl]["overhead_pct_vs_baseline"].get(c, 0)
                    for wl in wls]
            plt.bar([xi + i * w for xi in x], vals, width=w, label=c,
                    color=colors.get(c, None))
        plt.xticks([xi + w * (len(conds) - 1) / 2 for xi in x], wls)
        plt.ylabel("Workload slowdown vs baseline (%)")
        plt.title("Monitoring overhead per syscall workload")
        plt.legend()
        plt.tight_layout()
        plt.savefig("results/fig_workload%s.png" % tag, dpi=150)
        print("  figure -> results/fig_workload%s.png" % tag)


def score_traffic(csv_path):
    """Legitimate-traffic impact (Experiment B macro): RPS degradation and tail
    latency increase the monitoring imposes on the Online Boutique frontend,
    relative to the unmonitored baseline. CSV schema:
        condition,repeat,rps,p50_ms,p95_ms
    Reports throughput degradation % (the <=2% SLO) per condition."""
    import csv
    from collections import defaultdict
    # data[condition] = {"rps": [...], "p50": [...], "p95": [...]}
    data = defaultdict(lambda: {"rps": [], "p50": [], "p95": []})
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            try:
                rps = float(row["rps"])
            except (KeyError, ValueError):
                continue
            d = data[row["condition"]]
            d["rps"].append(rps)
            for col, key in (("p50_ms", "p50"), ("p95_ms", "p95")):
                try:
                    d[key].append(float(row[col]))
                except (KeyError, ValueError):
                    pass

    if "baseline" not in data:
        print("traffic: no baseline rows, cannot compute degradation",
              file=sys.stderr)
        return
    base_rps = statistics.mean(data["baseline"]["rps"])
    order = ["baseline", "ebpf", "auditd"]
    keys = [k for k in order if k in data] + \
           [k for k in data if k not in order]

    result = {"experiment": "traffic_impact",
              "baseline_rps": round(base_rps, 1),
              "by_condition": {}}
    for k in keys:
        d = data[k]
        mean_rps = statistics.mean(d["rps"])
        entry = {
            "rps_mean": round(mean_rps, 1),
            "rps_std": round(statistics.pstdev(d["rps"]), 1)
                       if len(d["rps"]) > 1 else 0.0,
            "throughput_degradation_pct": round(
                100 * (base_rps - mean_rps) / base_rps, 2),
            "p50_ms_mean": round(statistics.mean(d["p50"]), 1) if d["p50"] else None,
            "p95_ms_mean": round(statistics.mean(d["p95"]), 1) if d["p95"] else None,
        }
        result["by_condition"][k] = entry
    tag = _csv_tag(csv_path, "traffic_impact")
    result["source"] = csv_path
    _save("results/metrics_traffic%s.json" % tag, result)
    _print_block("LEGITIMATE-TRAFFIC IMPACT (Experiment B macro)%s"
                 % ((" [%s]" % tag.lstrip("_")) if tag else ""), result)

    if HAVE_PLT and result["by_condition"]:
        conds = [k for k in keys]
        colors = {"baseline": "#264653", "ebpf": "#2a9d8f", "auditd": "#e76f51"}
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4))
        ax1.bar(conds, [result["by_condition"][c]["rps_mean"] for c in conds],
                color=[colors.get(c) for c in conds])
        ax1.set_ylabel("Frontend throughput (req/s)")
        ax1.set_title("Throughput under monitoring")
        ax2.bar(conds,
                [result["by_condition"][c]["throughput_degradation_pct"] for c in conds],
                color=[colors.get(c) for c in conds])
        ax2.axhline(2.0, ls="--", color="gray", lw=1, label="2% SLO")
        ax2.set_ylabel("Throughput degradation vs baseline (%)")
        ax2.set_title("Legitimate-traffic impact")
        ax2.legend()
        plt.tight_layout()
        plt.savefig("results/fig_traffic%s.png" % tag, dpi=150)
        print("  figure -> results/fig_traffic%s.png" % tag)


# -----------------------------------------------------------------------------
def _save(path, obj):
    import os
    os.makedirs("results", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _print_block(title, obj):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print(json.dumps(obj, indent=2))


def main():
    p = argparse.ArgumentParser(description="Thesis experiment scorer")
    p.add_argument("pos", nargs="*", help="alerts.jsonl ground_truth.jsonl")
    p.add_argument("--benign-window", type=float, default=120.0,
                   help="seconds of benign phase before first attack (FPR)")
    p.add_argument("--events", metavar="EVENTS_JSONL",
                   help="events.jsonl for the FPR denominator (benign-phase events)")
    p.add_argument("--overhead", nargs=2, metavar=("EBPF", "AUDITD"),
                   help="score agent overhead from two pidstat files")
    p.add_argument("--program-types", metavar="CSV",
                   help="score eBPF program-type benchmark CSV")
    p.add_argument("--workload", metavar="CSV",
                   help="score workload-overhead CSV (baseline/ebpf/auditd)")
    p.add_argument("--traffic", metavar="CSV",
                   help="score legitimate-traffic-impact CSV (frontend RPS)")
    args = p.parse_args()

    if args.overhead:
        score_overhead(*args.overhead)
    elif args.program_types:
        score_program_types(args.program_types)
    elif args.workload:
        score_workload(args.workload)
    elif args.traffic:
        score_traffic(args.traffic)
    elif len(args.pos) == 2:
        score_detection(args.pos[0], args.pos[1], args.benign_window, args.events)
    else:
        p.error("provide alerts.jsonl + ground_truth.jsonl, or --overhead, "
                "or --program-types, or --workload, or --traffic")


if __name__ == "__main__":
    main()
