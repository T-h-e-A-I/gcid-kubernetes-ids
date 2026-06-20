#!/usr/bin/env python3
# =============================================================================
# auditd_agent.py -- Baseline detection agent (auditd log parsing)
# -----------------------------------------------------------------------------
# Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
#         eBPF Syscall Monitoring.
#
# This is the COMPARISON BASELINE for the eBPF agent. It implements the SAME
# detection capability (sensitive-file access, exec, connect) but using the
# traditional approach: tailing and string-parsing /var/log/audit/audit.log in
# user space. The point of the thesis is that this approach is functionally
# comparable but far more expensive (CPU/latency) than eBPF -- so this agent is
# deliberately faithful to how auditd-based detection actually works, including
# the heavy string parsing that creates the overhead.
#
# To keep the comparison fair (plan section 3.3):
#   - identical Kubernetes-sensitive path list as ebpf_agent.py
#   - identical structured-metrics output (alerts.jsonl) so analysis/score.py
#     scores both agents the same way
# =============================================================================

import argparse
import json
import os
import time
from collections import defaultdict

AUDIT_LOG_PATH = "/var/log/audit/audit.log"

# Mirror the eBPF agent's detection scope for a fair comparison (only
# performance should differ). As in the eBPF agent (plan P0-B), /etc/passwd and
# /etc/shadow are deliberately NOT flagged on their own -- a container reading
# its own copy is not an escape. The service-account token is a distinct,
# lower-noise rule (token-access).
TOKEN_PATHS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
]

HOST_ONLY_OBJECTS = [
    "/run/containerd/containerd.sock",
    "/var/run/docker.sock",
    "/etc/kubernetes/pki",
    "/var/lib/kubelet",
]

HOST_MOUNT_PREFIXES = ["/host", "/host_mnt", "/hostfs", "/rootfs"]


class Metrics:
    """Same structured-metrics contract as ebpf_agent.py's Metrics class so
    analysis/score.py can score both agents identically."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "w") if path else None   # truncate per run (v2 P1-5)
        self.total_events = 0
        self.alerts = 0
        self.by_rule = defaultdict(int)
        self.start = time.time()

    def record_event(self):
        self.total_events += 1

    def record_alert(self, record):
        self.alerts += 1
        self.by_rule[record["rule"]] += 1
        if self.f:
            self.f.write(json.dumps(record) + "\n")
            self.f.flush()

    def summary(self):
        return {
            "duration_s": round(time.time() - self.start, 2),
            "total_events": self.total_events,
            "alerts": self.alerts,
            "by_rule": dict(self.by_rule),
        }

    def close(self):
        if self.f:
            self.f.close()


def tail_audit_log(filename):
    """Generator yielding new lines in the audit log (like `tail -f`)."""
    try:
        with open(filename, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)  # avoid a hot spin while idle
                    continue
                yield line
    except PermissionError:
        print("Error: run as root to read %s" % filename)
        raise SystemExit(1)
    except FileNotFoundError:
        print("Error: %s not found. Is auditd installed/running?" % filename)
        raise SystemExit(1)


def extract_field(line, prefix):
    """Pull a `key=value` token out of an audit log line."""
    for part in line.split():
        if part.startswith(prefix):
            return part.split("=", 1)[1].strip('"')
    return None


def classify_path(name):
    """Return the detection rule for a PATH record, or None if benign.
    Mirrors the eBPF agent's scoped file-boundary logic. A bare SA-token read is
    NOT flagged (every pod does it -- the eBPF agent detects token *exfil* via
    cgroup-level token+Kube-API correlation, which a log parser cannot do;
    noted as a baseline capability gap)."""
    if any(name.startswith(p) for p in HOST_MOUNT_PREFIXES):
        return "file-boundary"
    if any(s in name for s in HOST_ONLY_OBJECTS):
        return "file-boundary"
    return None


# Cluster network ranges (set from CLI in main) -- needed to classify the
# connect destinations decoded from SOCKADDR records.
NET = {"pod": None, "svc": None, "kube_api": "10.43.0.1"}


def decode_saddr(saddr_hex):
    """Decode an audit SOCKADDR `saddr=` hex blob to (ip, port) for IPv4.
    Layout: family(2 LE) port(2 BE) addr(4). Returns None for non-IPv4.

    This is the closest auditd can get to eBPF's direct sock-struct read, and it
    requires a separate SOCKADDR record (only emitted when a `connect` audit
    rule is loaded) -- representative of auditd's clunkier path to the same data."""
    try:
        if len(saddr_hex) < 16:
            return None
        family = int(saddr_hex[2:4] + saddr_hex[0:2], 16)  # little-endian u16
        if family != 2:                                     # AF_INET only
            return None
        port = int(saddr_hex[4:8], 16)                      # network order
        ip = ".".join(str(int(saddr_hex[i:i + 2], 16)) for i in range(8, 16, 2))
        return ip, port
    except (ValueError, TypeError):
        return None


def _in(net, ip):
    import ipaddress
    try:
        return net is not None and ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def parse_audit_line(line, metrics):
    """Parse a single audit record. The deliberately heavy, sequential string
    matching here is representative of real auditd-based detection overhead.

    Attempts the SAME scenarios as the eBPF agent where the audit log permits.
    Known unavoidable gaps (auditd limitations vs eBPF, documented):
      - serviceaccount-token-exfil: needs token-read -> Kube-API correlation by
        container; auditd has no cgroup/namespace context to link them.
      - host vs container: auditd cannot cheaply tell whether a setns/open came
        from a container, so nsenter detection keys on the `nsenter` comm only.
    """
    if "type=SYSCALL" in line:
        metrics.record_event()
        if "arch=c000003e" not in line:  # x86_64 only
            return
        # 59=execve, 257=openat, 42=connect, 165=mount, 308=setns
        if "syscall=59" in line:                            # execve
            pid = extract_field(line, "pid=")
            exe = extract_field(line, "exe=")
            comm = extract_field(line, "comm=")
            if exe in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
                _alert(metrics, "EXEC", "suspicious-shell", pid, comm, exe,
                       severity="info")
            # E4: a host-path binary executed (component-vuln escape signature).
            if exe and any(exe.startswith(p) for p in HOST_MOUNT_PREFIXES):
                _alert(metrics, "ESCAPE", "host-binary-exec", pid, comm, exe)
        elif "syscall=165" in line:                         # mount
            pid = extract_field(line, "pid=")
            comm = extract_field(line, "comm=")
            if comm not in ("runc", "containerd", "kubelet"):  # crude runtime skip
                _alert(metrics, "ESCAPE", "privileged-mount", pid, comm, "mount()")
        elif "syscall=308" in line:                         # setns (E3, weak)
            comm = extract_field(line, "comm=")
            if comm == "nsenter":   # auditd has no namespace context -> comm only
                _alert(metrics, "ESCAPE", "nsenter-bosc",
                       extract_field(line, "pid="), comm, "setns by nsenter")

    elif "type=SOCKADDR" in line:                           # connect destination
        dec = decode_saddr(extract_field(line, "saddr="))
        if dec:
            ip, port = dec
            if ip == NET["kube_api"] or (port == 443 and _in(NET["svc"], ip)):
                _alert(metrics, "LATERAL", "kube-api-access", None, None,
                       "%s:%d" % (ip, port))
            elif _in(NET["pod"], ip) or _in(NET["svc"], ip):
                _alert(metrics, "LATERAL", "cross-namespace-connect", None, None,
                       "%s:%d" % (ip, port))

    elif "type=PATH" in line:                               # file access (E1)
        name = extract_field(line, "name=")
        if name:
            rule = classify_path(name)
            if rule:
                _alert(metrics, "ESCAPE", rule, None, None, name)


def _alert(metrics, category, rule, pid, comm, detail, severity="alert"):
    record = {
        "ts": time.time(),
        "category": category,
        "rule": rule,
        "severity": severity,
        "pid": int(pid) if pid and pid.isdigit() else -1,
        "comm": comm or "?",
        "pod": "?",          # auditd has no native Pod context (a key drawback)
        "namespace": "?",
        "container": "?",
        "detail": detail,
        "source": "auditd",
    }
    metrics.record_alert(record)
    print("[%s] (%s) %s :: %s" % (category, rule, comm or pid, detail),
          flush=True)


def main():
    import ipaddress
    p = argparse.ArgumentParser(description="auditd baseline detection agent")
    p.add_argument("--log", default=AUDIT_LOG_PATH)
    p.add_argument("--metrics",
                   default=os.environ.get("METRICS_FILE", "alerts_auditd.jsonl"))
    p.add_argument("--pod-cidr",
                   default=os.environ.get("KUBE_POD_CIDR", "10.42.0.0/16"))
    p.add_argument("--svc-cidr",
                   default=os.environ.get("KUBE_SERVICE_CIDR", "10.43.0.0/16"))
    p.add_argument("--kube-api",
                   default=os.environ.get("KUBE_API_IP", "10.43.0.1"))
    args = p.parse_args()

    NET["pod"] = ipaddress.ip_network(args.pod_cidr)
    NET["svc"] = ipaddress.ip_network(args.svc_cidr)
    NET["kube_api"] = args.kube_api

    metrics = Metrics(args.metrics)
    print("=" * 60)
    print("Auditd Baseline Detection Agent")
    print("=" * 60)
    print("Tailing: %s" % args.log)
    print("Metrics: %s" % args.metrics)
    print("Pod/Svc CIDR: %s / %s | Kube-API: %s"
          % (args.pod_cidr, args.svc_cidr, args.kube_api))
    print("Listening... (Ctrl+C to stop)\n")

    try:
        for line in tail_audit_log(args.log):
            parse_audit_line(line, metrics)
    except KeyboardInterrupt:
        print("\nStopping auditd agent.")
    finally:
        print("\n[metrics] " + json.dumps(metrics.summary()))
        metrics.close()


if __name__ == "__main__":
    main()
