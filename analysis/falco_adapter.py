#!/usr/bin/env python3
# =============================================================================
# falco_adapter.py -- normalize Falco JSON output into the project alert schema
# -----------------------------------------------------------------------------
# Task 2.1 (Falco head-to-head). Falco is scored with the SAME analysis/score.py
# against the SAME ground_truth.jsonl as the eBPF agent. score.py matches an
# alert to a ground-truth occurrence purely by `rule == expect_rule` within a
# time window (score.py:score_detection) -- nothing tool-specific. So the only
# glue needed is this adapter: it converts Falco's JSON-lines events into the
# `alerts.jsonl` schema the eBPF agent emits, rewriting each Falco rule name to
# the thesis `expect_rule` for the scenario it corresponds to.
#
# IMPORTANT -- write the output as results_falco/alerts_falco.jsonl so score.py
# derives a SEPARATE output (metrics_detection_falco.json + fig_detection_falco.png)
# and never overwrites the eBPF or auditd results.
#
#   python3 analysis/falco_adapter.py results_falco/falco_events.json \
#           --out results_falco/alerts_falco.jsonl
#   python3 analysis/score.py results_falco/alerts_falco.jsonl \
#           results_falco/ground_truth.jsonl
#
# THE HONESTY CONTROL (see todo/plan_falco.md section 2):
#   E2 (serviceaccount-token-exfil) is DELIBERATELY NOT in the mapping. Falco
#   cannot natively express the cgroup-correlated "read SA token -> later reach
#   the Kube-API" CHAIN. A per-event token-read rule fires on EVERY legitimate
#   pod (pure noise), so mapping it onto serviceaccount-token-exfil would
#   manufacture a false detection of the exact capability the thesis claims
#   Falco lacks. E2 must remain a MISS for Falco -- that is the headline result.
#   `FORBIDDEN_EXPECT` enforces this even if someone later edits RULE_MAP.
# =============================================================================
import argparse
import json
import re
import sys

# ---- the rule map (auditable; lift into the thesis appendix) -----------------
# Each entry: (substring matched case-insensitively against Falco's rule name,
#              thesis expect_rule, alert category). First match wins.
# Substrings target Falco's *stock* rule names plus the idiomatic outbound rule
# added in experiments/falco/custom_rules.yaml.
RULE_MAP = [
    # --- our idiomatic thesis rules (experiments/falco/custom_rules.yaml) ---
    ("read sensitive host file",     "file-boundary",           "ESCAPE"),   # E1
    ("namespace switch via setns",   "nsenter-bosc",            "ESCAPE"),   # E3
    ("host binary",                  "host-binary-exec",        "ESCAPE"),   # E4 (tamper/exec)
    ("contact kube api",             "kube-api-access",         "LATERAL"),  # E2b
    ("unexpected outbound",          "cross-namespace-connect", "LATERAL"),  # L1/L2
    ("privileged mount",             "privileged-mount",        "ESCAPE"),   # E5
    # --- Falco STOCK rule names (kept so stock-only runs still map) ---------
    ("read sensitive file",          "file-boundary",           "ESCAPE"),   # E1 (stock)
    ("contact k8s api server",       "kube-api-access",         "LATERAL"),  # E2b (stock)
    ("change thread namespace",      "nsenter-bosc",            "ESCAPE"),   # E3 (stock)
    ("set namespace",                "nsenter-bosc",            "ESCAPE"),   # E3 (stock alt)
    ("write below root",             "host-binary-exec",        "ESCAPE"),   # E4 (stock)
    ("write below binary dir",       "host-binary-exec",        "ESCAPE"),   # E4 (stock alt)
    ("write below monitored dir",    "host-binary-exec",        "ESCAPE"),   # E4 (stock alt)
    ("outbound connection",          "cross-namespace-connect", "LATERAL"),  # L1/L2 (stock-ish)
    ("unexpected connection",        "cross-namespace-connect", "LATERAL"),  # L1/L2 (alt)
]

# expect_rules a Falco event may NEVER be mapped to (enforced below). This is the
# E2 honesty guard: see the module docstring.
FORBIDDEN_EXPECT = {"serviceaccount-token-exfil"}

# Fail fast if anyone adds a forbidden mapping.
for _sub, _expect, _cat in RULE_MAP:
    if _expect in FORBIDDEN_EXPECT:
        raise SystemExit("RULE_MAP maps a Falco rule onto a FORBIDDEN expect "
                         "rule (%r): that would fake the E2 chain detection. "
                         "Remove it." % _expect)


def _parse_falco_time(ev):
    """Falco event time -> epoch float, on the same wall clock as ground truth.
    Prefers the numeric nanosecond field if present (output_fields.evt.time or
    top-level 'time' as int); otherwise parses the RFC3339 'time' string
    (e.g. 2026-06-07T12:34:56.789012345Z) including 9-digit nanoseconds."""
    of = ev.get("output_fields") or {}
    # 1. numeric nanoseconds (most reliable, no tz parsing)
    for v in (of.get("evt.time"), ev.get("time") if isinstance(ev.get("time"), (int, float)) else None):
        if isinstance(v, (int, float)) and v > 1e17:   # ns since epoch
            return v / 1e9
    # 2. RFC3339 string
    t = ev.get("time")
    if isinstance(t, str):
        m = re.match(r"(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})"
                     r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", t.strip())
        if m:
            import calendar
            date, hh, mm, ss, frac, tz = m.groups()
            y, mo, d = (int(x) for x in date.split("-"))
            secs = (hh, mm, ss)
            base = calendar.timegm((y, mo, d, int(secs[0]), int(secs[1]),
                                    int(secs[2]), 0, 0, 0))  # treat as UTC
            # timezone offset (Z or +/-HH:MM); default UTC
            if tz and tz != "Z":
                sign = 1 if tz[0] == "+" else -1
                tzc = tz[1:].replace(":", "")
                off = sign * (int(tzc[:2]) * 3600 + int(tzc[2:4]) * 60)
                base -= off
            fr = float("0." + frac) if frac else 0.0
            return base + fr
    return None


def _short_cid(cid):
    if not cid:
        return "?"
    return str(cid)[:12]


def adapt(in_path, out_path, include_unmapped=True):
    n_in = n_mapped = n_unmapped = 0
    by_expect = {}
    out = open(out_path, "w")
    with open(in_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue   # skip non-JSON banner lines Falco may emit
            if "rule" not in ev:
                continue
            n_in += 1
            ts = _parse_falco_time(ev)
            if ts is None:
                print("[warn] could not parse time for rule %r; skipping"
                      % ev.get("rule"), file=sys.stderr)
                continue
            of = ev.get("output_fields") or {}
            rule_lc = str(ev["rule"]).lower()

            expect = category = None
            for sub, exp, cat in RULE_MAP:
                if sub in rule_lc:
                    expect, category = exp, cat
                    break

            if expect in FORBIDDEN_EXPECT:        # defence in depth
                expect = None

            if expect is None:
                # Unmapped Falco event: keep it VISIBLE for inspection but never
                # countable. severity 'info' is excluded from FPR (score.py) and
                # the "falco:" prefix guarantees it can't equal any expect_rule.
                n_unmapped += 1
                if not include_unmapped:
                    continue
                rec = {
                    "ts": ts, "category": "INFO",
                    "rule": "falco:" + str(ev["rule"]),
                    "severity": "info", "pid": int(of.get("proc.pid", 0) or 0),
                    "comm": of.get("proc.name", "?"),
                    "pod": of.get("k8s.pod.name", "?"),
                    "namespace": of.get("k8s.ns.name", "?"),
                    "container": _short_cid(of.get("container.id")),
                    "detail": ev.get("output", ""),
                }
            else:
                n_mapped += 1
                by_expect[expect] = by_expect.get(expect, 0) + 1
                rec = {
                    "ts": ts, "category": category, "rule": expect,
                    "severity": "alert", "pid": int(of.get("proc.pid", 0) or 0),
                    "comm": of.get("proc.name", "?"),
                    "pod": of.get("k8s.pod.name", "?"),
                    "namespace": of.get("k8s.ns.name", "?"),
                    "container": _short_cid(of.get("container.id")),
                    "detail": of.get("fd.name") or ev.get("output", ""),
                    "falco_rule": ev["rule"],   # provenance: original Falco rule
                }
            out.write(json.dumps(rec) + "\n")
    out.close()

    print("=" * 60)
    print("Falco -> alerts adapter")
    print("=" * 60)
    print("  input events      : %d" % n_in)
    print("  mapped (alerts)   : %d" % n_mapped)
    print("  unmapped (info)   : %d%s" % (n_unmapped,
          " [written]" if include_unmapped else " [dropped]"))
    print("  by expect_rule    : %s" % (json.dumps(by_expect) if by_expect else "{}"))
    print("  NOTE: serviceaccount-token-exfil is intentionally absent "
          "(E2 is a Falco miss by design).")
    print("  output            -> %s" % out_path)


def main():
    p = argparse.ArgumentParser(
        description="Normalize Falco JSON events into the alerts.jsonl schema.")
    p.add_argument("falco_json", help="Falco JSON-lines events file")
    p.add_argument("--out", required=True,
                   help="output alerts file (use results_falco/alerts_falco.jsonl)")
    p.add_argument("--no-unmapped", action="store_true",
                   help="drop unmapped Falco events instead of writing them as info")
    args = p.parse_args()
    adapt(args.falco_json, args.out, include_unmapped=not args.no_unmapped)


if __name__ == "__main__":
    main()
