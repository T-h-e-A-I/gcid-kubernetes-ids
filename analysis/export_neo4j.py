#!/usr/bin/env python3
# =============================================================================
# export_neo4j.py -- Import a recorded dependency graph into Neo4j (FIGURE-ONLY)
# -----------------------------------------------------------------------------
# Per plan decision #1: the runtime detection path uses an in-memory NetworkX
# graph; Neo4j is used ONLY to render a publication-quality attack-chain figure
# for the thesis (matching Chen et al.). This script is never on the hot path.
#
# Input: the JSON produced by `ebpf_agent.py --graph-out graph.json`.
#
# Two modes:
#   1. --neo4j  : push nodes/edges to a running Neo4j (bolt://) instance, then
#                 open the Neo4j Browser and screenshot the attack chain.
#   2. (default): emit a Graphviz .dot file you can render with `dot -Tpng`,
#                 requiring no database at all -- the simplest path to a figure.
#
# Cypher to visualise after import (mode 1):
#   MATCH (n)-[r]->(m) RETURN n,r,m
# =============================================================================
import argparse
import json
import sys


def load_graph(path):
    with open(path) as f:
        return json.load(f)


def graph_from_alerts(alerts_path, category=None, pod_substr=None, rule=None):
    """Build a compact attack-chain graph directly from the alerts.

    This is the RECOMMENDED path for the thesis figure. Each alert is itself an
    attack-chain edge: a process (pid/comm/pod) acted on a resource (a sensitive
    file or a socket) and a detection rule fired. We synthesise exactly those
    nodes/edges -- nothing from the benign cluster activity -- so the figure is
    small, readable, and shows only the attack (Chen et al. style).

    Optional narrowing (for a single clean scenario):
      category   -- keep only ESCAPE / LATERAL / EXEC alerts
      pod_substr -- keep only alerts whose pod name contains this (e.g.
                    "attacker-escape" to isolate one scenario from benign FPs)
      rule       -- keep only one detection rule (e.g. "nsenter-bosc")
    """
    nodes, edges, seen_n, seen_e = [], [], set(), set()

    def add_node(nid, **attrs):
        if nid not in seen_n:
            seen_n.add(nid)
            nodes.append({"id": nid, **attrs})

    def add_edge(src, dst, rel):
        key = (src, dst, rel)
        if key not in seen_e:
            seen_e.add(key)
            edges.append({"src": src, "dst": dst, "rel": rel})

    with open(alerts_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except ValueError:
                continue
            # Optional narrowing to isolate a single scenario for the figure.
            if category and a.get("category") != category:
                continue
            if rule and a.get("rule") != rule:
                continue
            if pod_substr and pod_substr not in (a.get("pod", "") or ""):
                continue
            pid = a.get("pid", -1)
            comm = a.get("comm", "?")
            pod = "%s/%s" % (a.get("namespace", "?"), a.get("pod", "?"))
            # Process node: stable id per pid (fallback to comm for auditd's -1).
            pnode = "proc:%s" % (pid if isinstance(pid, int) and pid > 0
                                 else comm)
            add_node(pnode, kind="process", comm=comm, pid=pid, pod=pod)
            # Resource node: socket for LATERAL ip:port, else a file/target.
            detail = a.get("detail", "")
            if a.get("category") == "LATERAL" and ":" in detail:
                rid = "sock:%s" % detail
                ip, _, port = detail.partition(":")
                add_node(rid, kind="socket", ip=ip, port=port)
            else:
                rid = "file:%s" % detail
                add_node(rid, kind="file", path=detail)
            add_edge(pnode, rid, a.get("rule", "alert"))

    print("attack-chain graph from alerts: %d nodes, %d edges"
          % (len(nodes), len(edges)))
    return {"nodes": nodes, "edges": edges}


def filter_graph(graph, alerts_path=None, max_nodes=200):
    """Reduce the full recorded graph to a small, renderable ATTACK CHAIN.

    The agent records a node/edge for every syscall from every container, so the
    raw graph is far too large for Graphviz `dot` (thousands of nodes). For the
    thesis figure we keep only the process nodes that triggered an alert plus
    the file/socket nodes directly connected to them -- i.e. the actual attack
    chain (Chen et al.), not the whole cluster's benign file activity.

    If no alerts file is given, we fall back to a hard node cap so `dot` never
    hangs.
    """
    keep = set()
    if alerts_path:
        pids = set()
        try:
            with open(alerts_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    pid = rec.get("pid", -1)
                    if isinstance(pid, int) and pid > 0:
                        pids.add(pid)
        except FileNotFoundError:
            print("alerts file %s not found; skipping alert filter"
                  % alerts_path, file=sys.stderr)
        # Seed with the process nodes that fired alerts.
        keep = {"proc:%d" % p for p in pids}
        present = {n["id"] for n in graph["nodes"]}
        keep &= present
        # Expand one hop: include every file/socket those processes touched.
        for e in graph["edges"]:
            if e["src"] in keep or e["dst"] in keep:
                keep.add(e["src"])
                keep.add(e["dst"])

    if keep:
        nodes = [n for n in graph["nodes"] if n["id"] in keep]
        edges = [e for e in graph["edges"]
                 if e["src"] in keep and e["dst"] in keep]
    else:
        nodes, edges = graph["nodes"], graph["edges"]

    # Safety cap so Graphviz never chokes, even without an alerts filter.
    if max_nodes and len(nodes) > max_nodes:
        print("graph still has %d nodes; capping to %d (use --alerts for a "
              "focused attack chain)" % (len(nodes), max_nodes),
              file=sys.stderr)
        nodes = nodes[:max_nodes]
        ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["src"] in ids and e["dst"] in ids]

    print("filtered graph: %d nodes, %d edges" % (len(nodes), len(edges)))
    return {"nodes": nodes, "edges": edges}


def to_dot(graph, out):
    """Render the dependency graph as Graphviz DOT (no DB needed)."""
    kind_style = {
        "process": 'shape=box, style=filled, fillcolor="#a8dadc"',
        "file":    'shape=note, style=filled, fillcolor="#f1faee"',
        "socket":  'shape=ellipse, style=filled, fillcolor="#ffd6a5"',
    }
    lines = ["digraph dependency {", '  rankdir=LR;', '  node [fontname="Helvetica"];']
    idmap = {}
    for i, n in enumerate(graph["nodes"]):
        idmap[n["id"]] = "n%d" % i
        label = n["id"]
        if n.get("kind") == "process":
            label = "%s\\npid=%s pod=%s" % (n.get("comm", "?"),
                                            n.get("pid", "?"),
                                            n.get("pod", "?"))
        elif n.get("kind") == "file":
            label = n.get("path", n["id"])
        style = kind_style.get(n.get("kind"), "")
        lines.append('  %s [label="%s", %s];' % (idmap[n["id"]], label, style))
    for e in graph["edges"]:
        s, d = idmap.get(e["src"]), idmap.get(e["dst"])
        if s and d:
            lines.append('  %s -> %s [label="%s"];' % (s, d, e.get("rel", "")))
    lines.append("}")
    with open(out, "w") as f:
        f.write("\n".join(lines))
    print("DOT written to %s" % out)
    print("Render with: dot -Tpng %s -o attack_chain.png" % out)


def to_neo4j(graph, uri, user, password):
    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("neo4j driver not installed: pip install neo4j", file=sys.stderr)
        sys.exit(1)
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")  # clear (figure scratch DB)
        for n in graph["nodes"]:
            s.run("CREATE (:%s {id:$id, label:$label})"
                  % n.get("kind", "Node").capitalize(),
                  id=n["id"], label=n.get("comm") or n.get("path") or n["id"])
        for e in graph["edges"]:
            s.run("MATCH (a {id:$s}),(b {id:$d}) "
                  "CREATE (a)-[:REL {rel:$r}]->(b)",
                  s=e["src"], d=e["dst"], r=e.get("rel", ""))
    driver.close()
    print("Imported %d nodes / %d edges into %s"
          % (len(graph["nodes"]), len(graph["edges"]), uri))
    print("Visualise in Neo4j Browser: MATCH (n)-[r]->(m) RETURN n,r,m")


def main():
    p = argparse.ArgumentParser(description="Export agent graph to Neo4j/DOT")
    p.add_argument("graph_json", nargs="?",
                   help="output of ebpf_agent.py --graph-out (optional when "
                        "--alerts is used)")
    p.add_argument("--dot", default="attack_chain.dot",
                   help="DOT output path (default mode)")
    p.add_argument("--neo4j", metavar="BOLT_URI",
                   help="push to a Neo4j instance, e.g. bolt://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="neo4j")
    p.add_argument("--alerts", default=None,
                   help="alerts.jsonl: build a compact attack-chain figure "
                        "directly from the alerts (RECOMMENDED -- the raw graph "
                        "has thousands of benign nodes and will hang Graphviz).")
    p.add_argument("--max-nodes", type=int, default=200,
                   help="hard cap on nodes so Graphviz never hangs (default 200)")
    p.add_argument("--category", choices=["ESCAPE", "LATERAL", "EXEC"],
                   help="keep only this alert category (narrows the figure)")
    p.add_argument("--pod", dest="pod_substr",
                   help="keep only alerts whose pod name contains this string "
                        "(e.g. attacker-escape) -- isolates one scenario")
    p.add_argument("--rule", help="keep only this detection rule "
                                  "(e.g. nsenter-bosc, file-boundary)")
    args = p.parse_args()

    if args.alerts:
        # Preferred: synthesise the attack chain straight from the alerts.
        graph = graph_from_alerts(args.alerts, category=args.category,
                                  pod_substr=args.pod_substr, rule=args.rule)
    elif args.graph_json:
        # Fallback: the full recorded graph, capped so `dot` cannot hang.
        graph = filter_graph(load_graph(args.graph_json), max_nodes=args.max_nodes)
    else:
        p.error("provide a graph JSON file and/or --alerts")
    if args.neo4j:
        to_neo4j(graph, args.neo4j, args.user, args.password)
    else:
        to_dot(graph, args.dot)


if __name__ == "__main__":
    main()
