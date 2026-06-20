#!/usr/bin/env python3
# =============================================================================
# stitch_multinode.py -- Cross-node provenance stitching (todo/plan_multinode.md,
#                        run C2). The intellectual core of the multi-node result.
# -----------------------------------------------------------------------------
# In the two-host testbed each eBPF agent has a SEPARATE kernel and therefore a
# SEPARATE, node-local provenance graph keyed on node-local cgroup ids. A lateral
# chain that pivots across nodes (attacker@host1 -> relay@host2 -> db@host2) is
# seen by NEITHER agent as a whole: host1's agent sees only leg1, host2's only
# leg2. This script demonstrates BOTH:
#
#   1. THE GAP  -- per node, the alert set is partial; no single node holds the
#                  full attacker->relay->db chain.
#   2. THE FIX  -- merge the two streams and JOIN connect alerts across nodes on
#                  a CLUSTER-GLOBAL key (the network destination: dst_ip resolved
#                  to the pod that owns it via pod_ips.json), which replaces the
#                  node-local cgroup_id the live engine cannot share. Chaining
#                  edges where one hop's destination pod is the next hop's source
#                  pod reconstructs the cross-node campaign.
#
# This is an OFFLINE post-hoc prototype of the future-work "shared event store +
# distributed graph" (Ch.7 subsec:fw_multinode) -- enough to quantify the gap and
# show it is recoverable, without building a live distributed system.
#
# Usage:
#   python3 analysis/stitch_multinode.py results/alerts.host1.jsonl \
#           results/alerts.host2.jsonl --pod-ips results/pod_ips.json
#
# Input alert schema (emitted by src/ebpf_agent.py with --node-name):
#   {ts, node, category, rule, pid, comm, pod, namespace, detail "ip:port", ...}
# =============================================================================
import argparse
import json
import sys


def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def load_pod_ips(path):
    """ip -> {pod, node}. Lets us resolve a connect's destination IP back to the
    pod (and node) that owns it -- the cluster-global identity the per-node
    cgroup_id keys cannot provide across kernels."""
    if not path:
        return {}
    with open(path) as f:
        data = json.load(f)
    return {e["ip"]: {"pod": e.get("pod", "?"), "node": e.get("node", "?")}
            for e in data if e.get("ip")}


def parse_dst(detail):
    """'10.42.1.7:8080' -> ('10.42.1.7', 8080); tolerate missing port."""
    if not detail:
        return None, None
    host, _, port = str(detail).rpartition(":")
    if not host:                      # no ':' -> detail was just an ip
        host = str(detail)
    try:
        return host, int(port)
    except ValueError:
        return host, None


def main():
    ap = argparse.ArgumentParser(
        description="Stitch per-node alerts into cross-node attack chains.")
    ap.add_argument("alerts", nargs="+",
                    help="per-node alert JSONL files (e.g. alerts.host1.jsonl "
                         "alerts.host2.jsonl)")
    ap.add_argument("--pod-ips", default=None,
                    help="pod_ips.json (ip->{pod,node}) from "
                         "attack_lateral_multinode.sh; enables dst-IP->pod join")
    ap.add_argument("--window", type=float, default=30.0,
                    help="max seconds between a hop and the next (default 30)")
    ap.add_argument("--rule", default="cross-namespace-connect",
                    help="connect rule to chain on (default cross-namespace-connect)")
    ap.add_argument("--json-out", default=None,
                    help="write the stitched chains + summary to this JSON path")
    args = ap.parse_args()

    pod_ips = load_pod_ips(args.pod_ips)

    # Merge every node's alerts, tagging the source file as a fallback node id.
    alerts = []
    for path in args.alerts:
        for a in load_jsonl(path):
            a.setdefault("node", "?")
            alerts.append(a)
    alerts.sort(key=lambda a: a.get("ts", 0))
    nodes = sorted({a["node"] for a in alerts})

    connects = [a for a in alerts if a.get("rule") == args.rule]

    # ---- 1. THE GAP: what each node sees in isolation -----------------------
    print("=" * 64)
    print("Cross-node stitch  (rule = %s, window = %gs)" % (args.rule, args.window))
    print("=" * 64)
    print("\n[1] Per-node views (the gap) -- nodes: %s" % ", ".join(nodes))
    by_node = {n: [c for c in connects if c["node"] == n] for n in nodes}
    for n in nodes:
        print("  node %-8s : %d %s alert(s)" % (n, len(by_node[n]), args.rule))
        for c in by_node[n]:
            dst_ip, dst_port = parse_dst(c.get("detail"))
            owner = pod_ips.get(dst_ip, {})
            print("      %.3f  src_pod=%-14s -> %s:%s  (dst pod=%s@%s)"
                  % (c.get("ts", 0), c.get("pod", "?"), dst_ip, dst_port,
                     owner.get("pod", "?"), owner.get("node", "?")))

    # ---- 2. THE FIX: stitch hops into cross-node chains ---------------------
    # Build directed hops: src_pod@src_node --(ts)--> dst_pod@dst_node.
    hops = []
    for c in connects:
        dst_ip, dst_port = parse_dst(c.get("detail"))
        owner = pod_ips.get(dst_ip)
        hops.append({
            "ts": c.get("ts", 0),
            "src_pod": c.get("pod", "?"),
            "src_node": c.get("node", "?"),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_pod": owner.get("pod") if owner else None,
            "dst_node": owner.get("node") if owner else None,
        })
    hops.sort(key=lambda h: h["ts"])

    # Chain: a hop whose destination POD is the source POD of a later hop (within
    # the window) is the same pivot continuing onward. The two hops can live on
    # DIFFERENT nodes -- that join is exactly what no single agent could make.
    chains = []
    used_next = set()
    for i, h in enumerate(hops):
        if h["dst_pod"] is None:
            continue
        for j in range(i + 1, len(hops)):
            nxt = hops[j]
            if j in used_next:
                continue
            if nxt["ts"] - h["ts"] > args.window:
                break
            if nxt["src_pod"] == h["dst_pod"] and nxt["src_pod"] != "?":
                cross = (h["src_node"] != nxt["src_node"])
                chains.append({"leg1": h, "leg2": nxt, "cross_node": cross})
                used_next.add(j)
                break

    print("\n[2] Stitched chains (cluster-global join on dst-IP -> pod):")
    if not chains:
        print("  (none -- no hop's destination pod initiated an onward connect "
              "within the window)")
    cross_node_chains = [c for c in chains if c["cross_node"]]
    for c in chains:
        a, b = c["leg1"], c["leg2"]
        tag = "CROSS-NODE" if c["cross_node"] else "same-node"
        print("  [%s] %s@%s --> %s@%s --> %s:%s"
              % (tag, a["src_pod"], a["src_node"],
                 b["src_pod"], b["src_node"], b["dst_ip"], b["dst_port"]))
        if c["cross_node"]:
            print("       leg1 observed by agent '%s'; leg2 observed by agent "
                  "'%s' -- neither alone saw the full chain." %
                  (a["src_node"], b["src_node"]))

    # ---- 3. Verdict ---------------------------------------------------------
    print("\n[3] Result:")
    multi_node_run = len(nodes) > 1
    gap = multi_node_run and all(
        not (any(h["src_node"] == n for h in [c["leg1"] for c in chains]) and
             any(h["src_node"] == n for h in [c["leg2"] for c in chains]))
        for n in nodes) if chains else multi_node_run
    print("  nodes observed              : %d (%s)" % (len(nodes), ", ".join(nodes)))
    print("  %s alerts        : %d" % (args.rule, len(connects)))
    print("  chains reconstructed        : %d" % len(chains))
    print("  CROSS-NODE chains recovered : %d  <-- the stitch payoff" %
          len(cross_node_chains))
    if cross_node_chains:
        print("  VERDICT: gap confirmed (no single agent held the full chain) "
              "AND recovered by the cluster-global stitch.")
    elif multi_node_run:
        print("  VERDICT: multi-node alerts present but no cross-node pivot "
              "chained -- check pod_ips.json and the --window.")
    else:
        print("  VERDICT: single node only -- run agents on both hosts and merge "
              "both alert files.")

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({
                "nodes": nodes,
                "connect_alerts": len(connects),
                "chains": chains,
                "cross_node_chains": len(cross_node_chains),
            }, f, indent=2, default=str)
        print("\n  wrote %s" % args.json_out)

    return 0 if (not multi_node_run or cross_node_chains) else 1


if __name__ == "__main__":
    sys.exit(main())
