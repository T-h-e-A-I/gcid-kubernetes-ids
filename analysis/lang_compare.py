#!/usr/bin/env python3
# =============================================================================
# lang_compare.py -- language-comparison study (todo/plan_lang_rewrite.md).
# -----------------------------------------------------------------------------
# Two modes:
#   --parity A.jsonl B.jsonl
#       Detection-parity control: confirm the Python and Go engines emit the
#       SAME alerts (rule, severity, pid, comm, detail, ts) on the same stream.
#       Exit non-zero if they differ. This is what makes the overhead numbers
#       valid -- "same work, measured cost", not "cheaper because it does less".
#
#   --aggregate DIR --rates "40 368" --out metrics_lang.json
#       Parse the footprint_<eng>_<rate>.txt files produced by run_lang_eval.sh,
#       extract window-mean CPU% and RSS (mean/max) per (engine, rate), write a
#       JSON summary, and print a LaTeX-ready table (tab:lang_footprint).
# =============================================================================
import argparse
import json
import re
import sys


def _load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append((round(float(d.get("ts", 0.0)), 3), d.get("category"),
                         d.get("rule"), d.get("severity"), d.get("pid"),
                         d.get("comm"), d.get("detail")))
    return rows


def parity(a, b):
    ra, rb = _load(a), _load(b)
    print("=" * 60)
    print("DETECTION PARITY CHECK")
    print("  Python alerts : %d   (%s)" % (len(ra), a))
    print("  Go     alerts : %d   (%s)" % (len(rb), b))
    # Compare as multisets sorted (order-independent: both are processing the
    # same stream so order should match too, but the claim is set-equality).
    sa, sb = sorted(ra), sorted(rb)
    match = sa == sb
    print("  EXACT MATCH (ts,category,rule,severity,pid,comm,detail): %s"
          % ("YES" if match else "NO"))
    if not match:
        only_py = [x for x in sa if x not in sb][:10]
        only_go = [x for x in sb if x not in sa][:10]
        if only_py:
            print("  -- in Python only (up to 10):")
            for x in only_py:
                print("     ", x)
        if only_go:
            print("  -- in Go only (up to 10):")
            for x in only_go:
                print("     ", x)
    # Per-rule tallies for a quick eyeball.
    def tally(rows):
        t = {}
        for r in rows:
            t[r[2]] = t.get(r[2], 0) + 1
        return t
    print("  by-rule Python:", tally(ra))
    print("  by-rule Go    :", tally(rb))
    print("=" * 60)
    return 0 if match else 1


_WIN = re.compile(r"window mean=([0-9.]+)")
_PERSEC = re.compile(r"per-sec mean=([0-9.]+)\s+std=([0-9.]+)")
_RSS = re.compile(r"RSS\s*:\s*mean=([0-9.]+)\s*MB\s*\(max\s*([0-9.]+)\s*MB\)")


def _parse_footprint(path):
    try:
        txt = open(path).read()
    except FileNotFoundError:
        return None
    out = {}
    m = _WIN.search(txt)
    if m:
        out["cpu_window_mean"] = float(m.group(1))
    m = _PERSEC.search(txt)
    if m:
        out["cpu_persec_mean"] = float(m.group(1))
        out["cpu_persec_std"] = float(m.group(2))
    m = _RSS.search(txt)
    if m:
        out["rss_mean_mb"] = float(m.group(1))
        out["rss_max_mb"] = float(m.group(2))
    return out or None


def aggregate(d, rates, out_path):
    data = {"engines": ["python", "go"], "rates": rates, "by_run": {}}
    for rate in rates:
        for eng in ("python", "go"):
            key = "%s_%s" % (eng, rate)
            fp = _parse_footprint("%s/footprint_%s.txt" % (d, key))
            if fp:
                data["by_run"][key] = fp
    if out_path:
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        print("[lang_compare] wrote %s" % out_path)

    # ---- human + LaTeX table ----
    print("=" * 64)
    print("USER-SPACE FOOTPRINT: Python vs Go (same stream, matched rate)")
    print("-" * 64)
    print("%-8s %-8s %12s %12s %12s" %
          ("rate", "engine", "CPU% (win)", "RSS mean MB", "RSS max MB"))
    for rate in rates:
        for eng in ("python", "go"):
            r = data["by_run"].get("%s_%s" % (eng, rate))
            if not r:
                continue
            print("%-8s %-8s %12s %12s %12s" % (
                rate, eng,
                ("%.3f" % r.get("cpu_window_mean", r.get("cpu_persec_mean", 0))),
                ("%.1f" % r.get("rss_mean_mb", 0)),
                ("%.1f" % r.get("rss_max_mb", 0))))
    print("-" * 64)
    print("LaTeX (tab:lang_footprint) rows:")
    for rate in rates:
        py = data["by_run"].get("python_%s" % rate, {})
        go = data["by_run"].get("go_%s" % rate, {})
        if not py and not go:
            continue
        print("%s & %.2f & %.2f & %.0f & %.0f \\\\" % (
            rate,
            py.get("cpu_window_mean", py.get("cpu_persec_mean", 0)),
            go.get("cpu_window_mean", go.get("cpu_persec_mean", 0)),
            py.get("rss_mean_mb", 0), go.get("rss_mean_mb", 0)))
    print("  (cols: rate ev/s & Python CPU%% & Go CPU%% & Python RSS MB & Go RSS MB)")
    print("=" * 64)


def main():
    ap = argparse.ArgumentParser(description="language-comparison aggregator")
    ap.add_argument("--parity", nargs=2, metavar=("PY_JSONL", "GO_JSONL"))
    ap.add_argument("--aggregate", metavar="DIR")
    ap.add_argument("--rates", default="40 368",
                    help="space-separated event rates used in Phase 2")
    ap.add_argument("--out", default=None, help="metrics_lang.json output path")
    args = ap.parse_args()

    if args.parity:
        sys.exit(parity(args.parity[0], args.parity[1]))
    if args.aggregate:
        aggregate(args.aggregate, args.rates.split(), args.out)
        return
    ap.error("choose --parity or --aggregate")


if __name__ == "__main__":
    main()
