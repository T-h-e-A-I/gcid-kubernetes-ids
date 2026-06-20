#!/usr/bin/env python3
# =============================================================================
# window_sensitivity.py -- Detection-rate sensitivity to the scorer match window
# -----------------------------------------------------------------------------
# Re-scores the SAME alerts.jsonl / ground_truth.jsonl over a sweep of
# action-to-alert match-window sizes. This separates genuine detection MISSES
# from late-but-real alerts (scorer artifacts), answering the peer-review
# concern that the fixed 10 s window in score.py can drop true positives.
#
# Key finding (n=100 run): every one of the 700 attacks is detected once the
# window reaches 30 s; the 16 "misses" at the 10 s operating point are all L1
# multi-target-scan connects that alert late (p95 ~18 s), i.e. a LATENCY problem,
# not a COVERAGE gap.
#
# Usage:
#   python3 analysis/window_sensitivity.py [alerts.jsonl] [ground_truth.jsonl]
# Defaults to results/alerts.jsonl + results/ground_truth.jsonl.
# Emits results/metrics_window_sensitivity.json and (if matplotlib present)
# results/fig_window_sensitivity.png.
# =============================================================================
import json, sys, statistics

WINDOWS = [1, 2, 3, 5, 8, 10, 15, 20, 30, 45, 60, 90, 120]


def load(p):
    return [json.loads(l) for l in open(p) if l.strip()]


def score(alerts, truth, window, scenario=None):
    matched, det, tot, lats = set(), 0, 0, []
    for t in sorted(truth, key=lambda x: x["ts"]):
        if scenario and t["scenario"] != scenario:
            continue
        tot += 1
        best = None
        for i, a in enumerate(alerts):
            if i in matched or a.get("rule") != t["expect_rule"]:
                continue
            dt = a["ts"] - t["ts"]
            if 0 <= dt <= window and (best is None or dt < best[1]):
                best = (i, dt)
        if best is not None:
            matched.add(best[0]); det += 1; lats.append(best[1] * 1000)
    return det, tot, lats


def main():
    import os
    ap = sys.argv[1] if len(sys.argv) > 1 else "results/alerts.jsonl"
    gp = sys.argv[2] if len(sys.argv) > 2 else "results/ground_truth.jsonl"
    alerts = sorted(load(ap), key=lambda a: a["ts"])
    truth = load(gp)
    # Separate output per source so a comparator (Falco) does not overwrite the
    # eBPF artifact: alerts.jsonl -> "", alerts_falco.jsonl -> "_falco".
    stem = os.path.basename(ap).rsplit(".", 1)[0]
    tag = stem[len("alerts"):] if stem.startswith("alerts") else "_" + stem
    scenarios = sorted({t["scenario"] for t in truth})
    out = {"experiment": "window_sensitivity", "source": stem,
           "match_window_default_s": 10.0,
           "overall": [], "L1": [], "by_scenario": {s: [] for s in scenarios}}
    for w in WINDOWS:
        d, t, _ = score(alerts, truth, w)
        out["overall"].append({"window_s": w, "tp": d, "total": t,
                               "adr": round(d / t, 4)})
        d1, t1, l1 = score(alerts, truth, w, "L1")
        out["L1"].append({"window_s": w, "detected": d1, "trials": t1,
                          "rate": round(d1 / t1, 3) if t1 else 0.0,
                          "latency_p95_ms": round(sorted(l1)[int(0.95 * len(l1)) - 1], 0)
                          if len(l1) >= 2 else None})
        for s in scenarios:
            ds, ts, _ = score(alerts, truth, w, s)
            out["by_scenario"][s].append({"window_s": w,
                                          "rate": round(ds / ts, 3) if ts else 0.0})
    # The best ADR reached at any window: a coverage CEILING. For this work it is
    # 1.0 (all misses are latency); for Falco it plateaus below 1.0 because the
    # E2 chain is a capability gap that no window recovers.
    out["adr_ceiling"] = max(r["adr"] for r in out["overall"])
    json.dump(out, open("results/metrics_window_sensitivity%s.json" % tag, "w"),
              indent=2)
    print(json.dumps(out, indent=2))

    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        ww = [r["window_s"] for r in out["overall"]]
        plt.figure(figsize=(7, 4))
        plt.plot(ww, [r["adr"] for r in out["overall"]], marker="o",
                 label="Overall ADR (%d attacks)" % out["overall"][0]["total"],
                 color="#2a9d8f")
        plt.plot(ww, [r["rate"] for r in out["L1"]], marker="s",
                 label="L1 detection rate", color="#e76f51")
        # E2 line: flat 1.0 for this work, flat 0.0 for Falco (capability gap).
        if "E2" in out["by_scenario"]:
            plt.plot(ww, [r["rate"] for r in out["by_scenario"]["E2"]], marker="^",
                     label="E2 token-exfil chain", color="#264653")
        plt.axvline(10, ls="--", color="gray", lw=1, label="10 s operating point")
        plt.ylim(-0.02, 1.02); plt.xlabel("Action-to-alert match window (s)")
        plt.ylabel("Detection rate"); plt.title("Detection vs. scorer match window")
        plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
        plt.savefig("results/fig_window_sensitivity%s.png" % tag, dpi=150)
        print("figure -> results/fig_window_sensitivity%s.png" % tag)
    except Exception as e:
        print("figure skipped:", e)


if __name__ == "__main__":
    main()
