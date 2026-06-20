#!/usr/bin/env python3
# =============================================================================
# ebpf_agent.py -- User-space detection engine (PRODUCTION agent)
# -----------------------------------------------------------------------------
# Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
#         eBPF Syscall Monitoring.
#
# Loads the kprobe data plane (ebpf_probes.c), consumes events from the perf
# ring buffer, enriches them with Kubernetes Pod/namespace context, and runs a
# stateful *dependency-graph* detection engine that flags:
#
#   - Vertical container escape (file-boundary rule, Chen et al.)
#       * privileged host-filesystem mount + host-file read
#       * service-account-token theft + Kube-API access
#   - Namespace-switch escape (BoSC signature, Bertinatto et al.)
#       * openat("/proc/<pid>/ns/mnt") followed by setns(CLONE_NEWNS)
#   - Horizontal lateral movement (cross-namespace correlation)
#       * connections into the Pod/Service CIDR not permitted by policy
#       * internal scanning across Pods
#
# Design decisions baked in (Roadmap/implementation-plan-v2.md, section 9):
#   #1 in-memory NetworkX graph for runtime; optional graph dump for a Neo4j
#      thesis figure (see analysis/export_neo4j.py).
#   #2 kprobe is the production mechanism (this agent loads ebpf_probes.c).
#   #3 run manually for the lab; deploy/ ships a DaemonSet manifest as an
#      appendix artifact.
#
# Every detection emits a structured JSON line to the metrics file so that
# analysis/score.py can compute ADR / FPR / latency offline.
# =============================================================================

import argparse
import ctypes as ct
import ipaddress
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque

# BCC is only needed for LIVE capture. REPLAY mode (--replay, the
# language-comparison study) runs without eBPF, so the import is deferred into
# main() so the agent can replay a recorded stream on a host without BCC.
BPF = None

# NetworkX is used for the in-memory dependency graph. It is a hard dependency
# of the detection engine but we degrade gracefully so the agent can still run
# (alerts only, no graph export) if it is missing.
try:
    import networkx as nx
    HAVE_NX = True
except ImportError:
    HAVE_NX = False

# -----------------------------------------------------------------------------
# Event type discriminators -- MUST match the #define values in ebpf_probes.c
# -----------------------------------------------------------------------------
EVENT_EXEC = 1
EVENT_OPEN = 2
EVENT_CONNECT = 3
EVENT_MOUNT = 4
EVENT_SETNS = 5
EVENT_UNSHARE = 6

EVENT_NAMES = {
    EVENT_EXEC: "EXEC", EVENT_OPEN: "OPEN", EVENT_CONNECT: "CONNECT",
    EVENT_MOUNT: "MOUNT", EVENT_SETNS: "SETNS", EVENT_UNSHARE: "UNSHARE",
}

# CLONE_NEWNS = mount-namespace flag passed to setns() during an nsenter escape.
CLONE_NEWNS = 0x00020000

# BoSC sliding window length (Bertinatto et al. use the last 100 syscalls).
BOSC_WINDOW = 100


# -----------------------------------------------------------------------------
# ctypes mirror of `struct event_t` in ebpf_probes.c. Field order/types MUST
# match exactly or decoding will silently corrupt.
# -----------------------------------------------------------------------------
class Event(ct.Structure):
    _fields_ = [
        ("event_type", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("mnt_ns", ct.c_uint64),
        ("net_ns", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),
        ("flags", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
        ("daddr", ct.c_uint32),
        ("dport", ct.c_uint16),
    ]


# -----------------------------------------------------------------------------
# Service-account token. Reading it is NOT alerted on by itself: every pod
# mounts and reads its token, so a standalone alert is pure noise (the first
# runs flagged metrics-server/traefik/coredns, never the attacker). Instead a
# token read is recorded per-container and only escalates to the
# `serviceaccount-token-exfil` rule when the SAME container subsequently reaches
# the Kube-API -- a rare, attacker-specific event. (re-posed E2, v2 follow-up)
# -----------------------------------------------------------------------------
TOKEN_PATHS = [
    b"/var/run/secrets/kubernetes.io/serviceaccount/token",
    b"/run/secrets/kubernetes.io/serviceaccount/token",
]

# -----------------------------------------------------------------------------
# Host-only objects that should never be reachable from inside a normal app
# container: their presence inside one implies a host mount (a boundary
# crossing). NOTE the deliberate ABSENCE of /etc/passwd and /etc/shadow -- every
# container has its OWN copy and reads them routinely (dpkg, NSS, useradd), so
# flagging them produced ~2,800 false positives in the first run (plan P0-B).
# The real escape is reading the HOST's copy via a mount, which the host-mount
# prefix check below catches.
# -----------------------------------------------------------------------------
HOST_ONLY_OBJECTS = [
    b"/run/containerd/containerd.sock",
    b"/var/run/docker.sock",
    b"/etc/kubernetes/pki",
    b"/var/lib/kubelet",
]

# Alerts with the same (pid, rule, detail) within this window are collapsed to
# one, to prevent a single logical action (e.g. apt reading a file repeatedly)
# from emitting an alert storm. (plan P1-1)
DEDUP_WINDOW_S = 10.0

# Perf ring buffer size in pages (power of two). The default (8) overflowed
# under load and dropped the decisive events; a larger ring plus the new
# in-kernel filtering keeps loss near zero. (plan v2 P0-1)
PERF_PAGES = 256

# Container-runtime / init process names whose mount() calls are legitimate
# (pod setup), so they must not be flagged as privileged-mount escapes.
RUNTIME_COMMS = ("runc", "containerd", "containerd-shim", "systemd",
                 "kubelet", "dockerd", "conmon", "crio")

# Token-exfil correlation window: a container that read its SA token and then
# reaches the Kube-API within this window is flagged as a token-exfil chain.
TOKEN_EXFIL_WINDOW_S = 60.0

# Bind mounts the kernel/runtime legitimately injects into every container.
# Excluded from the file-boundary rule to suppress false positives
# (Chen et al. whitelist).
BIND_MOUNT_WHITELIST = [
    b"/proc", b"/sys", b"/dev",
    b"/etc/resolv.conf", b"/etc/hostname", b"/etc/hosts",
]

# Host-filesystem mount points commonly used by hostPath-mount escapes. A
# container reading under one of these is reading the host's filesystem.
HOST_MOUNT_PREFIXES = [b"/host", b"/host_mnt", b"/hostfs", b"/rootfs"]


# =============================================================================
# Kubernetes metadata enrichment
# =============================================================================
class PodResolver:
    """Map a container process to its Kubernetes Pod / namespace.

    ASYNC design (v2 follow-up): the first runs stalled because `resolve()` ran
    a synchronous `crictl inspect` (up to 2 s) inside the perf-buffer callback,
    blocking event draining and dropping the decisive events (E3 0/10, E2 4 s
    latency). Now:
      - A background thread batch-lists ALL containers with ONE `crictl ps`
        call every few seconds, building container_id -> Pod metadata.
      - `resolve()` is NON-BLOCKING: a fast /proc/<pid>/cgroup read plus a dict
        lookup. It never spawns a subprocess on the hot path. If the batch
        cache has not seen the container yet, it returns the short id and the
        Pod label fills in on a later alert.
    """

    def __init__(self, enabled=True, refresh_interval=5.0):
        self.enabled = enabled
        self._pid_cache = {}   # pid -> container_id (cheap cgroup parse)
        self._cid_meta = {}    # container_id -> meta (batch crictl ps)
        self._ip_ns = {}       # pod IP / service clusterIP -> namespace (kubectl)
        self._pod_sa = {}      # (namespace, pod) -> serviceAccountName (kubectl)
        self._pod_cgids = set()  # cgroup_ids (kernfs inodes) under kubepods.slice
        self._cgid_uid = {}    # cgroup_id (inode) -> pod UID  (cheap fs walk)
        self._uid_meta = {}    # pod UID -> {namespace, pod, sa}  (kubectl)
        self._lock = threading.Lock()
        self._stop = False
        if enabled:
            self._refresh()    # prime once at startup (best-effort)
            threading.Thread(target=self._refresh_loop,
                             args=(refresh_interval,), daemon=True).start()
            # FAST cold-start loop: the cgroup directory (which encodes the pod
            # UID) is created at CONTAINER-CREATE -- seconds before crictl reports
            # the container "running" -- and `kubectl` lists pods (with UID + SA)
            # the moment they are created. So a cgroup_id->UID->SA path resolves a
            # new pod's identity BEFORE its first API call, closing the resolver
            # cold-start window that leaked token-exfil false positives on churning
            # API clients (GATE 1c) and caused the E5 cold-start mount miss. We
            # refresh these two cheap maps frequently (the crictl path stays on the
            # slower full-refresh loop, since it is only the legacy fallback).
            threading.Thread(target=self._fast_loop, daemon=True).start()

    def _fast_loop(self):
        while not self._stop:
            time.sleep(1.5)
            self._refresh_pod_cgids()   # cgroup_id -> UID (fs walk, no subprocess)
            self._refresh_ipns()        # UID -> SA + IP -> ns (one kubectl call)

    @staticmethod
    def _container_id_from_cgroup(pid):
        """Extract a container id from /proc/<pid>/cgroup (fast, no subprocess).
        Handles cgroupfs (/kubepods/.../<id>) and systemd
        (cri-containerd-<id>.scope) layouts."""
        try:
            with open("/proc/%d/cgroup" % pid, "r") as f:
                data = f.read()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            return None
        import re
        m = re.search(r"([0-9a-f]{64})", data)
        if m:
            return m.group(1)
        m = re.search(r"(?:cri-containerd-|docker-|crio-)([0-9a-f]+)\.scope",
                      data)
        return m.group(1) if m else None

    def _refresh_loop(self, interval):
        while not self._stop:
            time.sleep(interval)
            self._refresh()

    def _refresh(self):
        """One batch `crictl ps` lists every running container with its Pod
        labels. Runs off the hot path (background thread / startup only)."""
        try:
            out = subprocess.check_output(
                ["crictl", "ps", "-o", "json"],
                stderr=subprocess.DEVNULL, timeout=5)
            data = json.loads(out)
        except (subprocess.SubprocessError, OSError, ValueError):
            return
        meta = {}
        for c in data.get("containers", []):
            cid = c.get("id", "")
            labels = c.get("labels", {}) or {}
            meta[cid] = {
                "pod": labels.get("io.kubernetes.pod.name", "?"),
                "namespace": labels.get("io.kubernetes.pod.namespace", "?"),
                "container": labels.get("io.kubernetes.container.name", "?"),
                "container_id": cid[:12],
            }
        with self._lock:
            self._cid_meta = meta
        self._refresh_ipns()
        self._refresh_pod_cgids()

    def _refresh_pod_cgids(self):
        """Set of cgroup_ids (kernfs dir inodes) under kubepods.slice / kubepods.
        A mount's in-kernel cgroup_id is matched against this to tell a POD
        process (real container escape) from a HOST daemon (e.g. fwupd/falcoctl
        in a private mount namespace that slips past is_host()). Robust to
        short-lived processes: the cgroup_id is captured in-kernel while the
        process is alive, unlike a /proc/<pid> lookup at alert time. (A9)"""
        import re
        cgids = set()
        cgid_uid = {}
        # Pod UID appears in the cgroup path as `pod<uid>` with dashes replaced by
        # underscores (systemd: kubepods-burstable-pod<uid>.slice) or as `pod<uid>`
        # (cgroupfs). Map every inode under a pod's subtree to that pod's UID.
        uid_re = re.compile(r"pod([0-9a-fA-F]{8}[_-][0-9a-fA-F]{4}[_-][0-9a-fA-F]{4}"
                            r"[_-][0-9a-fA-F]{4}[_-][0-9a-fA-F]{12})")
        for base in ("/sys/fs/cgroup/kubepods.slice", "/sys/fs/cgroup/kubepods"):
            if not os.path.isdir(base):
                continue
            for root, dirs, _ in os.walk(base):
                for d in dirs:
                    p = os.path.join(root, d)
                    try:
                        ino = os.stat(p).st_ino
                    except OSError:
                        continue
                    cgids.add(ino)
                    m = uid_re.search(p)
                    if m:
                        cgid_uid[ino] = m.group(1).replace("_", "-").lower()
        if cgids:
            with self._lock:
                self._pod_cgids = cgids
                if cgid_uid:
                    self._cgid_uid = cgid_uid

    def is_pod_cgid(self, cgid):
        """True if cgid belongs to a Kubernetes pod. Fail-OPEN (returns True)
        when the pod-cgid set is empty/unknown, so a missing cgroup walk never
        silently suppresses a real detection."""
        with self._lock:
            if not self._pod_cgids:
                return True
            return cgid in self._pod_cgids

    def _refresh_ipns(self):
        """Build a destination IP -> namespace map (pod IPs + service clusterIPs)
        so the connect rule can tell a genuine CROSS-namespace connection from a
        benign SAME-namespace service call. One batched `kubectl get` off the hot
        path, mirroring the crictl refresh. Best-effort: on any failure the map
        is left unchanged and the connect rule falls back to alerting (it only
        suppresses on a CONFIRMED same-namespace match)."""
        try:
            out = subprocess.check_output(
                ["kubectl", "get", "pods,services", "-A", "-o", "json"],
                stderr=subprocess.DEVNULL, timeout=5)
            data = json.loads(out)
        except (subprocess.SubprocessError, OSError, ValueError):
            return
        ipns = {}
        podsa = {}
        uidmeta = {}
        for item in data.get("items", []):
            md = item.get("metadata", {}) or {}
            ns = md.get("namespace")
            if not ns:
                continue
            status = item.get("status", {}) or {}
            spec = item.get("spec", {}) or {}
            pip = status.get("podIP")           # Pod
            if pip:
                ipns[pip] = ns
            for p in status.get("podIPs", []) or []:
                if p.get("ip"):
                    ipns[p["ip"]] = ns
            cip = spec.get("clusterIP")          # Service
            if cip and cip != "None":
                ipns[cip] = ns
            for c in spec.get("clusterIPs", []) or []:
                if c and c != "None":
                    ipns[c] = ns
            # Pod -> service-account identity, for the token-exfil allowlist
            # (which workloads are LEGITIMATELY allowed to use the Kube-API).
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount")
            name = md.get("name")
            if sa and name:
                podsa[(ns, name)] = sa
            # Pod UID -> identity, for cold-start-fast cgroup_id-based resolution
            # (kubectl lists a pod the moment it is created, with UID + SA).
            uid = md.get("uid")
            if uid:
                uidmeta[uid.lower()] = {"namespace": ns, "pod": name or "?",
                                        "sa": sa}
        if ipns:
            with self._lock:
                self._ip_ns = ipns
                if podsa:
                    self._pod_sa = podsa
                if uidmeta:
                    self._uid_meta = uidmeta

    def resolve_cgid(self, cgid):
        """Resolve a pod's identity from its in-kernel cgroup_id, via the
        cgroup_id->UID (fs) and UID->SA (kubectl) maps. Resolves a freshly
        created pod BEFORE crictl reports its container running, so it closes
        the cold-start window. Returns {namespace, pod, sa} or {}."""
        if not cgid:
            return {}
        with self._lock:
            uid = self._cgid_uid.get(cgid)
            return dict(self._uid_meta.get(uid, {})) if uid else {}

    def uid_from_pid(self, pid):
        """Parse the pod UID directly from the LIVE process's own
        /proc/<pid>/cgroup path (which contains `pod<UID>`). Zero timing lag and
        no crictl/fs dependency: the connecting process is alive, so this resolves
        a brand-new pod's identity at connect time even before any background map
        has refreshed -- the reliable cold-start path."""
        try:
            with open("/proc/%d/cgroup" % pid, "r") as f:
                data = f.read()
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            return None
        import re
        m = re.search(r"pod([0-9a-fA-F]{8}[_-][0-9a-fA-F]{4}[_-][0-9a-fA-F]{4}"
                      r"[_-][0-9a-fA-F]{4}[_-][0-9a-fA-F]{12})", data)
        return m.group(1).replace("_", "-").lower() if m else None

    def sa_via_pid_cgroup(self, pid):
        """Service-account of `pid`'s pod via the live /proc cgroup UID path, as
        ('namespace/sa', 'sa') or (). Lag-free cold-start resolution."""
        uid = self.uid_from_pid(pid)
        if not uid:
            return ()
        with self._lock:
            meta = self._uid_meta.get(uid)
        if not meta or not meta.get("sa"):
            return ()
        ns, sa = meta.get("namespace"), meta["sa"]
        return ("%s/%s" % (ns, sa), sa) if ns else (sa,)

    def namespace_for_ip(self, ip):
        """Namespace owning a destination pod IP / service clusterIP, or None if
        not an in-cluster address we know about (refreshed every few seconds)."""
        with self._lock:
            return self._ip_ns.get(ip)

    def sa_for_pid(self, pid):
        """Service-account of the SOURCE pod for `pid` ("namespace/sa" and bare
        "sa"), or () if unknown. Used by the token-exfil allowlist to suppress
        the chain alert for workloads legitimately authorised to use the
        Kube-API (controllers/operators/CronJobs run under dedicated SAs)."""
        meta = self.resolve(pid)
        ns, pod = meta.get("namespace"), meta.get("pod")
        if not ns or not pod or ns == "?" or pod == "?":
            return ()
        with self._lock:
            sa = self._pod_sa.get((ns, pod))
        return ("%s/%s" % (ns, sa), sa) if sa else ()

    def resolve(self, pid):
        """NON-BLOCKING: fast cgroup parse + cached dict lookup. No subprocess
        on the hot path."""
        if not self.enabled:
            return {}
        cid = self._pid_cache.get(pid)
        if cid is None:
            cid = self._container_id_from_cgroup(pid) or ""
            self._pid_cache[pid] = cid
        if not cid:
            return {}
        with self._lock:
            meta = self._cid_meta.get(cid)
        return meta if meta else {"container_id": cid[:12]}


# =============================================================================
# Dependency-graph detection engine
# =============================================================================
class DetectionEngine:
    """Stateful dependency graph + traversal rules.

    Nodes:  Process (proc:<pid>), File (file:<path>), Socket (sock:<ip>:<port>)
    Edges:  used (proc->file, openat), wasGeneratedBy (file->proc, write),
            connectedTo (proc->sock), executed (proc->file, execve)

    Detection is performed as edges are added (incremental traversal), which is
    what keeps latency low while still recording the full attack chain for the
    Neo4j thesis figure.
    """

    def __init__(self, pod_cidr, svc_cidr, kube_api, metrics, resolver,
                 node_name=None, token_api_allowlist=None, token_window=None):
        self.token_window = float(token_window) if token_window else TOKEN_EXFIL_WINDOW_S
        self.pod_cidr = ipaddress.ip_network(pod_cidr)
        self.svc_cidr = ipaddress.ip_network(svc_cidr)
        self.kube_api = kube_api
        self.metrics = metrics
        self.resolver = resolver        # Pod enrichment, called lazily at alert
        # Service accounts LEGITIMATELY authorised to use the Kube-API. When a
        # token-read->API-connect chain comes from one of these (a real
        # controller/operator/CronJob), the chain is benign and the token-exfil
        # alert is suppressed -- the syscall correlation alone cannot tell a
        # compromised app pod from an authorised client, so identity is required
        # for PRECISION (GATE 1). Empty set = off (legacy behaviour, fires on any
        # token-read->API chain). Entries may be "namespace/sa" or bare "sa".
        self.token_api_allowlist = set(token_api_allowlist or ())
        # Identity of the host this agent runs on. Stamped into every alert so a
        # multi-node run can tell which node's kernel observed each event (the
        # eBPF data plane is per-kernel). Defaults to the hostname.
        self.node_name = node_name or socket.gethostname()
        self.graph = nx.MultiDiGraph() if HAVE_NX else None
        # Per-process Bag-of-System-Calls sliding windows (Bertinatto BoSC).
        self.bosc = defaultdict(lambda: deque(maxlen=BOSC_WINDOW))
        # cgroup_id -> timestamp of last SA-token read by that CONTAINER. Keyed
        # by container (not pid) so a token read by one process and the Kube-API
        # call by another in the same container correlate (re-posed E2).
        self.token_read_cg = {}
        # (pid, rule, detail) -> last-emitted ts, for alert de-duplication.
        self._dedup = {}
        # Time source. In LIVE mode this stays None and now() returns the wall
        # clock. In REPLAY mode (--replay) the driver sets it to the recorded
        # event timestamp before each dispatch, so dedup/token-window/alert ts
        # are driven by EVENT time, not processing time -- making replay
        # deterministic and independent of replay speed (so a Python and a Go
        # replay of the same stream produce byte-identical detection logic).
        self._now = None

    def now(self):
        return self._now if self._now is not None else time.time()

    # ---- graph helpers -------------------------------------------------------
    def _proc_node(self, pid, comm):
        nid = "proc:%d" % pid
        if self.graph is not None and not self.graph.has_node(nid):
            # Pod labels are filled lazily at alert time (off the hot path).
            self.graph.add_node(nid, kind="process", pid=pid, comm=comm,
                                pod="", namespace="", container="")
        return nid

    def _file_node(self, path):
        nid = "file:%s" % path
        if self.graph is not None and not self.graph.has_node(nid):
            self.graph.add_node(nid, kind="file", path=path)
        return nid

    def _sock_node(self, ip, port):
        nid = "sock:%s:%d" % (ip, port)
        if self.graph is not None and not self.graph.has_node(nid):
            self.graph.add_node(nid, kind="socket", ip=ip, port=port)
        return nid

    def _edge(self, src, dst, rel, **attrs):
        if self.graph is not None:
            self.graph.add_edge(src, dst, key=rel, rel=rel, ts=self.now(),
                                **attrs)

    def graph_size(self):
        """(nodes, edges) of the provenance graph; (0,0) if disabled."""
        if self.graph is None:
            return (0, 0)
        return (self.graph.number_of_nodes(), self.graph.number_of_edges())

    def prune_graph(self, cutoff_ts):
        """Evict provenance edges older than cutoff_ts and any nodes left
        isolated. The graph is for forensic explainability only; the
        detection-critical state (BoSC deques, token_read_cg) is separate and
        bounded, so this bounds memory with ZERO detection impact (B3)."""
        if self.graph is None:
            return (0, 0)
        old = [(u, v, k) for u, v, k, d
               in self.graph.edges(keys=True, data=True)
               if d.get("ts", 0) < cutoff_ts]
        self.graph.remove_edges_from(old)
        iso = [n for n in list(self.graph.nodes) if self.graph.degree(n) == 0]
        self.graph.remove_nodes_from(iso)
        return (len(old), len(iso))

    # ---- detection rules -----------------------------------------------------
    @staticmethod
    def _whitelisted(path_b):
        return any(path_b == w or path_b.startswith(w + b"/")
                   for w in BIND_MOUNT_WHITELIST)

    def _is_host_path(self, path_b):
        """File-boundary rule (Chen et al.): a container crosses its boundary
        when it accesses (a) a path under a host-mount prefix, or (b) a
        host-only object that should never exist inside a normal container.

        Critically, a container reading its OWN /etc/passwd or /etc/shadow is
        NOT a boundary crossing and is not flagged here (plan P0-B). In a full
        deployment (b) generalises to an inode/overlay-root check; the lab's
        hostPath escapes are captured by the prefix check (a)."""
        if self._whitelisted(path_b):
            return False
        if any(path_b.startswith(p) for p in HOST_MOUNT_PREFIXES):
            return True
        return any(s in path_b for s in HOST_ONLY_OBJECTS)

    def on_open(self, pid, comm, path_b, cgroup_id):
        proc = self._proc_node(pid, comm)
        fnode = self._file_node(path_b.decode("utf-8", "replace"))
        self._edge(proc, fnode, "used", syscall="openat")
        # BoSC: record the token relevant to the namespace-switch signature.
        if b"/ns/mnt" in path_b:
            self.bosc[pid].append("open_ns_mnt")
        # Service-account token read: NOT alerted on its own -- every pod reads
        # its token, so a standalone alert is pure noise (the first run proved
        # this). We record it at CONTAINER (cgroup) level so a later Kube-API
        # call from the same container becomes a token-exfil chain (re-posed E2).
        if any(t in path_b for t in TOKEN_PATHS):
            self.token_read_cg[cgroup_id] = self.now()
        elif self._is_host_path(path_b) and not comm.startswith(RUNTIME_COMMS):
            # Exclude the container runtime/init: runc:[2:INIT] legitimately
            # reads /host/sys/fs/cgroup during pod setup -- those were ~70 false
            # positives AND were spuriously satisfying E1 in scoring instead of
            # the attacker's genuine `head /host/etc/shadow` read.
            self._alert("ESCAPE", "file-boundary", pid, comm,
                        detail=path_b.decode("utf-8", "replace"))

    def on_mount(self, pid, comm, target_b, flags, cgroup_id=0):
        # The container runtime / init legitimately performs many mounts during
        # pod setup; flagging those produced ~955 false positives (v2 P1-4).
        # A workload process issuing mount() remains a strong escape indicator.
        if comm.startswith(RUNTIME_COMMS):
            return
        # A container escape is, by definition, performed from INSIDE a pod. A
        # mount whose cgroup_id is NOT under kubepods is a HOST daemon (e.g. fwupd
        # / falcoctl in a PRIVATE mount namespace that slips past the is_host()
        # host-mnt-ns filter), not a container escape -- skip it. cgroup_id is
        # captured in-kernel, so this is robust to the short-lived `mount` process
        # (a /proc lookup at alert time would fail). (A9)
        if self.resolver and self.resolver.enabled \
                and not self.resolver.is_pod_cgid(cgroup_id):
            return
        proc = self._proc_node(pid, comm)
        fnode = self._file_node("mount:" + target_b.decode("utf-8", "replace"))
        self._edge(proc, fnode, "mounted", flags=flags)
        self._alert("ESCAPE", "privileged-mount", pid, comm,
                    detail="mount target=%s flags=0x%x"
                           % (target_b.decode("utf-8", "replace"), flags))

    def on_setns(self, pid, comm, flags):
        self.bosc[pid].append("setns")
        # Namespace-switch escape (nsenter-style). The classic Bertinatto BoSC
        # signature is openat(/proc/<pid>/ns/mnt) THEN setns -- but MODERN
        # nsenter uses pidfd_open(target) + setns(pidfd, ...) with NO ns-file
        # open at all (confirmed on the lab kernel: "pidfd_open by nsenter" then
        # "setns by nsenter"). Requiring the open precursor therefore missed
        # every real nsenter. We instead flag the setns DIRECTLY when it comes
        # from a container workload, excluding the container runtime/init
        # (runc/containerd), whose setns calls are legitimate pod/exec setup and
        # which is the only other setns caller that survives the is_host filter.
        if comm.startswith(RUNTIME_COMMS):
            return
        via = "openat+setns (BoSC)" if "open_ns_mnt" in self.bosc[pid] \
            else "pidfd+setns"
        self._alert("ESCAPE", "nsenter-bosc", pid, comm,
                    detail="namespace-switch via %s [nstype=0x%x]"
                           % (via, flags))

    def on_exec(self, pid, comm, path_b):
        proc = self._proc_node(pid, comm)
        fname = path_b.decode("utf-8", "replace")
        fnode = self._file_node(fname)
        self._edge(proc, fnode, "executed", syscall="execve")
        if fname in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
            # Demoted to informational (v2 P1-4): a shell exec is a weak signal
            # on its own and our test harness uses `sh -c` heavily; scored as
            # context, not a detection/false-positive.
            self._alert("EXEC", "suspicious-shell", pid, comm,
                        detail=fname, severity="info")
        # execve of a binary living on a host mount = component-vuln escape
        # signature (E4 stand-in: poisoned host binary executed).
        if any(fname.startswith(p.decode()) for p in HOST_MOUNT_PREFIXES):
            self._alert("ESCAPE", "host-binary-exec", pid, comm, detail=fname)

    def on_connect(self, pid, comm, ip, port, cgroup_id):
        proc = self._proc_node(pid, comm)
        snode = self._sock_node(ip, port)
        self._edge(proc, snode, "connectedTo")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if ip == self.kube_api or (port == 443 and addr in self.svc_cidr):
            # Token-exfil chain (re-posed E2): this CONTAINER read its SA token
            # shortly before reaching the Kube-API. The Kube-API connect is rare
            # (normal workloads don't), so token-read + API-connect is a strong,
            # attacker-specific signal -- unlike the bare token read.
            t = self.token_read_cg.get(cgroup_id)
            if t and (self.now() - t) <= self.token_window:
                # Identity-scoping (GATE 1): suppress the chain for service
                # accounts allowlisted as legitimate Kube-API clients. The
                # token-read->API correlation is identical for a benign
                # controller and a credential thief; without this allowlist the
                # rule false-fires on every client-go workload (proven in GATE 1:
                # 25/25 benign sessions). A compromised app pod runs under a
                # non-allowlisted SA, so the chain still fires for it.
                # Resolve the connecting pod's service account by BOTH paths and
                # union them: the cgroup_id path resolves a freshly created pod
                # before crictl does (closes the cold-start window, §6.3.1), while
                # the pid path is the steady-state fallback.
                sa_ids = set(self.resolver.sa_for_pid(pid)) if self.resolver else set()
                if self.resolver:
                    # Lag-free cold-start path: UID straight from the live
                    # /proc/<pid>/cgroup, then UID->SA. Resolves a brand-new pod
                    # at connect time before crictl/background maps catch up.
                    sa_ids.update(self.resolver.sa_via_pid_cgroup(pid))
                    cm = self.resolver.resolve_cgid(cgroup_id)
                    csa = cm.get("sa")
                    if csa:
                        sa_ids.add(csa)
                        if cm.get("namespace"):
                            sa_ids.add("%s/%s" % (cm["namespace"], csa))
                allowed = any(s in self.token_api_allowlist for s in sa_ids)
                if not allowed:
                    self._alert("LATERAL", "serviceaccount-token-exfil", pid,
                                comm, detail="token-read container -> kube-api "
                                "%s:%d" % (ip, port), severity="critical")
                elif self.token_api_allowlist:
                    _sa = next((s for s in sa_ids if s in self.token_api_allowlist),
                               "?")
                    self._alert("LATERAL", "token-exfil-suppressed-allowlist",
                                pid, comm, detail="benign API client sa=%s" % _sa,
                                severity="info")
            self._alert("LATERAL", "kube-api-access", pid, comm,
                        detail="%s:%d" % (ip, port))
        elif addr in self.pod_cidr or addr in self.svc_cidr:
            # Only a genuine CROSS-namespace connection is lateral movement. A
            # same-namespace service call (e.g. Online Boutique checkout->email)
            # is benign and previously caused a false positive. Suppress ONLY
            # when both namespaces are known AND equal; cross-namespace and
            # unresolved destinations still alert, so real L1/L2 lateral movement
            # (and cold-cache cases) are never missed.
            src_ns = (self.resolver.resolve(pid) or {}).get("namespace") \
                if self.resolver else None
            dst_ns = self.resolver.namespace_for_ip(ip) if self.resolver else None
            if src_ns and dst_ns and src_ns == dst_ns:
                return   # confirmed same-namespace -> benign, do not alert
            self._alert("LATERAL", "cross-namespace-connect", pid, comm,
                        detail="%s:%d (src_ns=%s dst_ns=%s)"
                               % (ip, port, src_ns or "?", dst_ns or "?"))

    # ---- alerting / metrics --------------------------------------------------
    def _alert(self, category, rule, pid, comm, detail="", severity="alert"):
        # De-duplicate: collapse repeats of the same (pid, rule, detail) within
        # DEDUP_WINDOW_S so one logical action does not become an alert storm.
        key = (pid, rule, detail)
        now = self.now()
        last = self._dedup.get(key)
        if last is not None and now - last < DEDUP_WINDOW_S:
            self.metrics.record_suppressed()
            return
        self._dedup[key] = now
        if len(self._dedup) > 100000:          # coarse memory bound
            self._dedup.clear()

        # Enrich with Pod metadata ONLY here -- the single place the (relatively
        # expensive) crictl lookup happens, keeping per-event latency low and
        # avoiding it entirely for suppressed/benign events. (plan P1-5)
        meta = self.resolver.resolve(pid) if self.resolver else {}

        # Backfill the process node's Pod label for the attack-chain figure.
        nid = "proc:%d" % pid
        if self.graph is not None and self.graph.has_node(nid):
            self.graph.nodes[nid]["pod"] = meta.get("pod", "")
            self.graph.nodes[nid]["namespace"] = meta.get("namespace", "")

        record = {
            "ts": now,
            "node": self.node_name,    # which host's kernel observed this event
            "category": category,      # ESCAPE | LATERAL | EXEC
            "rule": rule,              # which detection rule fired
            "severity": severity,
            "pid": pid,
            "comm": comm,
            "pod": meta.get("pod", "?"),
            "namespace": meta.get("namespace", "?"),
            "container": meta.get("container", meta.get("container_id", "?")),
            "detail": detail,
        }
        self.metrics.record_alert(record)
        loc = "%s/%s" % (record["namespace"], record["pod"])
        print("[%s] (%s) pid=%d comm=%s pod=%s :: %s"
              % (category, rule, pid, comm, loc, detail), flush=True)

    def reset_state(self):
        """Clear per-trial detection state so repeated trials are independent
        (improvement-plan methodology). Triggered by SIGUSR1 between trials."""
        self.bosc.clear()
        self.token_read_cg.clear()
        self._dedup.clear()
        if self.graph is not None:
            self.graph.clear()
        print("[reset] detection state cleared (BoSC / graph / token / dedup)",
              flush=True)

    def dump_graph(self, path):
        """Persist the recorded dependency graph for offline Neo4j import /
        thesis figure generation (analysis/export_neo4j.py)."""
        if self.graph is None:
            print("[warn] networkx not available; cannot dump graph",
                  file=sys.stderr)
            return
        nodes = [{"id": n, **d} for n, d in self.graph.nodes(data=True)]
        edges = [{"src": u, "dst": v, **d}
                 for u, v, d in self.graph.edges(data=True)]
        with open(path, "w") as f:
            json.dump({"nodes": nodes, "edges": edges}, f, indent=2)
        print("[info] dependency graph written to %s (%d nodes, %d edges)"
              % (path, len(nodes), len(edges)))


# =============================================================================
# Metrics collection -- structured output consumed by analysis/score.py
# =============================================================================
class Metrics:
    def __init__(self, path, append=False):
        self.path = path
        # Default TRUNCATE mode (v2 P1-5): appending across agent restarts
        # previously merged multiple runs into one alerts.jsonl, corrupting the
        # FPR analysis and the attack-chain figure. One agent run = one file.
        #
        # APPEND mode (--append) is the deliberate exception for CRASH RECOVERY:
        # when an interrupted evaluation is resumed, the agent is restarted with
        # --append so alerts from already-completed trials are NOT wiped. The
        # resumable harness (run_evaluation.sh) keeps ground_truth.jsonl in step,
        # and score.py matches by rule+time-window (not trial index), so the
        # combined file scores correctly.
        self.f = open(path, "a" if append else "w") if path else None
        self.total_events = 0
        self.alerts = 0
        self.suppressed = 0
        self.lost = 0
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

    def record_suppressed(self):
        self.suppressed += 1

    def record_lost(self, n):
        self.lost += int(n)

    def summary(self):
        return {
            "duration_s": round(time.time() - self.start, 2),
            "total_events": self.total_events,   # FPR denominator (plan P1)
            "alerts": self.alerts,
            "suppressed_duplicates": self.suppressed,
            "perf_events_lost": self.lost,       # ring-buffer drops (v2 P0-1)
            "by_rule": dict(self.by_rule),
        }

    def close(self):
        if self.f:
            self.f.close()


# =============================================================================
# Agent hardening (CODAX security model, decision in plan section 3.2)
# =============================================================================
def lock_down_bpf():
    """After all eBPF programs are loaded, prevent this process (and thus any
    attacker who later compromises it) from issuing further bpf() syscalls, by
    installing a seccomp filter that blocks bpf (x86-64 syscall 321).

    Best-effort: requires the `seccomp` python bindings (libseccomp). If absent
    we log the intent so the limitation is visible in the experiment logs.
    """
    try:
        from seccomp import SyscallFilter, ALLOW, ERRNO
        f = SyscallFilter(defaction=ALLOW)
        f.add_rule(ERRNO(1), "bpf")  # EPERM on any future bpf() call
        f.load()
        print("[hardening] seccomp filter installed: bpf() syscall locked")
    except Exception as e:  # noqa: BLE001 -- intentionally broad, best-effort
        print("[hardening] seccomp lockdown unavailable (%s); "
              "install libseccomp python bindings to enable" % e,
              file=sys.stderr)


# =============================================================================
# Replay driver (language-comparison study, todo/plan_lang_rewrite.md)
# -----------------------------------------------------------------------------
# Feeds a stream recorded with --record-events through the SAME DetectionEngine,
# bypassing eBPF entirely. The eBPF data plane is language-neutral (in-kernel C),
# so replaying the post-filter event stream isolates exactly the user-space
# correlation cost we compare against the Go port. Time is driven by the recorded
# event ts, so the run is deterministic and a Go replay of the same file must
# produce identical alerts (detection-parity control).
# =============================================================================
def run_replay(args, metrics):
    resolver = None  # no crictl off-VM; score.py matches by rule + time window
    engine = DetectionEngine(args.pod_cidr, args.svc_cidr, args.kube_api,
                             metrics, resolver, node_name=args.node_name)
    interval = (1.0 / args.rate) if args.rate and args.rate > 0 else 0.0
    loops = max(1, args.loop)

    print("=" * 60)
    print("REPLAY mode (language-comparison study) -- no eBPF loaded")
    print("Stream   : %s" % args.replay)
    print("Rate     : %s" % ("max" if interval == 0 else "%g ev/s" % args.rate))
    print("Loops    : %d" % loops)
    print("PID      : %d   (sample me with footprint_sample.sh)" % os.getpid())
    print("-" * 60, flush=True)

    def feed_once():
        with open(args.replay) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                metrics.record_event()
                engine._now = rec.get("ts")        # drive engine time by event
                et = rec.get("et")
                pid = rec.get("pid", 0)
                comm = rec.get("comm", "")
                cg = rec.get("cgroup_id", 0)
                flags = rec.get("flags", 0)
                fn = rec.get("filename", "")
                if et == EVENT_OPEN:
                    engine.on_open(pid, comm, fn.encode("utf-8", "replace"), cg)
                elif et == EVENT_EXEC:
                    engine.on_exec(pid, comm, fn.encode("utf-8", "replace"))
                elif et == EVENT_MOUNT:
                    engine.on_mount(pid, comm, fn.encode("utf-8", "replace"),
                                    flags, cg)
                elif et == EVENT_SETNS:
                    engine.on_setns(pid, comm, flags)
                elif et == EVENT_UNSHARE:
                    engine.bosc[pid].append("unshare")
                elif et == EVENT_CONNECT:
                    engine.on_connect(pid, comm, rec.get("ip", ""),
                                      rec.get("dport", 0), cg)
                if interval:
                    time.sleep(interval)

    try:
        for _ in range(loops):
            feed_once()
    except KeyboardInterrupt:
        print("\nReplay interrupted.")
    finally:
        if args.graph_out:
            engine.dump_graph(args.graph_out)
        summary = metrics.summary()
        print("\n[metrics] " + json.dumps(summary))
        if args.summary_out:
            with open(args.summary_out, "w") as sf:
                json.dump(summary, sf, indent=2)
            print("[metrics] summary written to %s" % args.summary_out)
        metrics.close()


# =============================================================================
# Main
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="eBPF Kubernetes intrusion-detection agent")
    p.add_argument("--probes",
                   default=os.path.join(os.path.dirname(__file__),
                                        "ebpf_probes.c"),
                   help="path to the eBPF C source (default: ebpf_probes.c)")
    p.add_argument("--pod-cidr",
                   default=os.environ.get("KUBE_POD_CIDR", "10.42.0.0/16"),
                   help="Kubernetes Pod CIDR (default k3s/Flannel 10.42.0.0/16)")
    p.add_argument("--svc-cidr",
                   default=os.environ.get("KUBE_SERVICE_CIDR", "10.43.0.0/16"),
                   help="Kubernetes Service CIDR (default k3s 10.43.0.0/16)")
    p.add_argument("--kube-api",
                   default=os.environ.get("KUBE_API_IP", "10.43.0.1"),
                   help="Kube-API ClusterIP (default 10.43.0.1)")
    p.add_argument("--token-api-allowlist",
                   default=os.environ.get("TOKEN_API_ALLOWLIST", ""),
                   help="comma-separated service accounts ('namespace/sa' or "
                        "bare 'sa') legitimately authorised to use the Kube-API. "
                        "A token-read->API-connect chain from one of these is "
                        "treated as a benign client and the token-exfil alert is "
                        "suppressed (GATE 1 identity-scoping for precision). "
                        "Empty = off (fires on any token-read->API chain).")
    p.add_argument("--token-window", type=float,
                   default=float(os.environ.get("TOKEN_WINDOW", "0") or 0),
                   help="token-read->Kube-API correlation window in seconds "
                        "(default 60). Wider catches slower chains but retains "
                        "more per-cgroup state; used for the window-ROC sweep.")
    p.add_argument("--metrics",
                   default=os.environ.get("METRICS_FILE", "alerts.jsonl"),
                   help="path to write structured alert JSONL")
    p.add_argument("--append", action="store_true",
                   default=os.environ.get("METRICS_APPEND", "") not in ("", "0"),
                   help="open the metrics file in APPEND mode instead of "
                        "truncating it. Use this when RESTARTING the agent to "
                        "continue a crashed/interrupted evaluation run, so "
                        "alerts from already-completed trials are preserved. "
                        "(Default: truncate -- one agent run = one file.)")
    p.add_argument("--graph-out", default=None,
                   help="on exit, dump the dependency graph JSON to this path "
                        "(for analysis/export_neo4j.py / thesis figure)")
    p.add_argument("--summary-out", default=None,
                   help="on exit, write the run summary JSON (total_events = FPR "
                        "denominator, perf_events_lost, by_rule) to this path. "
                        "Captures the benign-event denominator that was "
                        "otherwise only printed to stdout and lost.")
    p.add_argument("--no-enrich", action="store_true",
                   help="disable crictl Pod metadata enrichment (faster; for "
                        "overhead-sensitive benchmark runs)")
    p.add_argument("--node-name",
                   default=os.environ.get("NODE_NAME", socket.gethostname()),
                   help="identity of THIS host, stamped into every alert's "
                        "\"node\" field. In a multi-node run, give each node's "
                        "agent a distinct name (e.g. host1/host2) so alerts can "
                        "be attributed to the kernel that observed them and the "
                        "cross-node stitch (analysis/stitch_multinode.py) can "
                        "join the two streams. Default: the hostname.")
    # ---- language-comparison study (todo/plan_lang_rewrite.md) --------------
    p.add_argument("--record-events", default=None, metavar="PATH",
                   help="LIVE mode: also dump every post-filter event (as it "
                        "reaches the engine) to this JSONL path. This recorded "
                        "stream is the shared, byte-identical input replayed "
                        "through both the Python and the Go correlation engine "
                        "to isolate the user-space runtime cost.")
    p.add_argument("--replay", default=None, metavar="PATH",
                   help="REPLAY mode: do NOT load eBPF. Feed a stream recorded "
                        "with --record-events through the identical detection "
                        "engine. Time is driven by the recorded event ts, so "
                        "the result is deterministic and matches a Go replay of "
                        "the same file (detection-parity control).")
    p.add_argument("--rate", type=float, default=0.0, metavar="EV_PER_S",
                   help="REPLAY mode: throttle to this many events/second (for "
                        "matched-rate CPU measurement). 0 = as fast as possible.")
    p.add_argument("--loop", type=int, default=1, metavar="N",
                   help="REPLAY mode: feed the recorded stream N times "
                        "(sustain load long enough for footprint sampling).")
    p.add_argument("--harden", action="store_true",
                   help="install seccomp filter locking bpf() after load")
    # ---- B3 graph scalability / pruning -------------------------------------
    p.add_argument("--stats-out", default=None, metavar="PATH",
                   help="LIVE mode: every --stats-interval seconds append "
                        "t_s,events,nodes,edges,rss_kb to this CSV (graph "
                        "scalability measurement, B3).")
    p.add_argument("--stats-interval", type=float, default=5.0, metavar="SEC",
                   help="seconds between --stats-out samples / prune passes.")
    p.add_argument("--prune-window", type=float, default=0.0, metavar="SEC",
                   help="time-windowed provenance-graph pruning: evict edges "
                        "older than SEC and isolated nodes, every "
                        "--stats-interval. 0 = off (unbounded). Detection state "
                        "is separate and bounded, so pruning has no detection "
                        "impact (B3).")
    return p.parse_args()


def main():
    args = parse_args()

    # REPLAY mode: no eBPF, no root needed -- feed a recorded stream through the
    # detection engine (language-comparison study). Handled entirely here.
    if args.replay:
        metrics = Metrics(args.metrics, append=args.append)
        run_replay(args, metrics)
        return

    # LIVE mode needs BCC; import it here so REPLAY mode does not require it.
    global BPF
    from bcc import BPF as _BPF
    BPF = _BPF

    # Host mount namespace -> distinguishes container processes from host.
    try:
        host_mnt_ns = os.stat("/proc/1/ns/mnt").st_ino
    except (FileNotFoundError, PermissionError):
        print("Error: must run as root to read /proc/1/ns/mnt", file=sys.stderr)
        sys.exit(1)

    if not HAVE_NX:
        print("[warn] networkx not installed: graph export disabled, alerts "
              "still functional. `pip install networkx` to enable.",
              file=sys.stderr)

    metrics = Metrics(args.metrics, append=args.append)
    if args.append:
        print("[resume] metrics file opened in APPEND mode (preserving prior "
              "alerts for a continued evaluation run).")
    resolver = PodResolver(enabled=not args.no_enrich)
    _allow = [s.strip() for s in (args.token_api_allowlist or "").split(",")
              if s.strip()]
    engine = DetectionEngine(args.pod_cidr, args.svc_cidr, args.kube_api,
                             metrics, resolver, node_name=args.node_name,
                             token_api_allowlist=_allow,
                             token_window=args.token_window or None)
    if _allow:
        print("Token-API allowlist   : %s" % ", ".join(_allow))

    # SIGUSR1 -> clear per-trial detection state so repeated trials stay
    # independent (the evaluation harness sends this between trials).
    signal.signal(signal.SIGUSR1, lambda *_: engine.reset_state())

    print("=" * 60)
    print("eBPF Kubernetes Intrusion Detection Agent")
    print("=" * 60)
    print("Host mount namespace : %d" % host_mnt_ns)
    print("Node name            : %s" % args.node_name)
    print("Pod CIDR             : %s" % args.pod_cidr)
    print("Service CIDR         : %s" % args.svc_cidr)
    print("Kube-API IP          : %s" % args.kube_api)
    print("Metrics file         : %s" % args.metrics)
    print("Pod enrichment       : %s" % ("OFF" if args.no_enrich else "ON"))
    print("-" * 60)

    # ---- load + attach the kprobe data plane --------------------------------
    # Inject the in-kernel filter constants (host mnt-ns + cluster CIDRs) so the
    # eBPF programs drop irrelevant events before they reach user space.
    pod = ipaddress.ip_network(args.pod_cidr)
    svc = ipaddress.ip_network(args.svc_cidr)
    cflags = [
        "-DHOST_MNT_NS=%dULL" % host_mnt_ns,
        "-DPOD_NET=%dU" % int(pod.network_address),
        "-DPOD_MASK=%dU" % int(pod.netmask),
        "-DSVC_NET=%dU" % int(svc.network_address),
        "-DSVC_MASK=%dU" % int(svc.netmask),
    ]
    b = BPF(src_file=args.probes, cflags=cflags)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"),
                    fn_name="syscall__execve")
    b.attach_kprobe(event=b.get_syscall_fnname("openat"),
                    fn_name="syscall__openat")
    # Legacy open() -- the netshoot attacker tools (busybox, util-linux nsenter)
    # use it instead of openat; without this their file opens are invisible.
    b.attach_kprobe(event=b.get_syscall_fnname("open"),
                    fn_name="syscall__open")
    # openat2 (newer kernels) -- best-effort.
    try:
        b.attach_kprobe(event=b.get_syscall_fnname("openat2"),
                        fn_name="syscall__openat2")
    except Exception:  # noqa: BLE001 -- openat2 absent on older kernels
        pass
    b.attach_kprobe(event=b.get_syscall_fnname("mount"),
                    fn_name="syscall__mount")
    # move_mount (new mount API, kernel 5.2+) -- modern util-linux mounts via
    # fsopen/fsmount/move_mount, bypassing legacy mount(2). Best-effort: absent
    # on older kernels. Closes the new-mount-API evasion gap for privileged-mount.
    try:
        b.attach_kprobe(event=b.get_syscall_fnname("move_mount"),
                        fn_name="syscall__move_mount")
    except Exception:  # noqa: BLE001 -- move_mount absent on pre-5.2 kernels
        pass
    b.attach_kprobe(event=b.get_syscall_fnname("setns"),
                    fn_name="syscall__setns")
    b.attach_kprobe(event=b.get_syscall_fnname("unshare"),
                    fn_name="syscall__unshare")
    b.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")

    if args.harden:
        lock_down_bpf()

    # Optional event recorder (--record-events): dumps the post-filter stream
    # for the language-comparison replay study (todo/plan_lang_rewrite.md).
    rec_f = open(args.record_events, "w") if args.record_events else None
    if rec_f:
        print("[record] post-filter event stream -> %s" % args.record_events)

    # ---- perf buffer callback ------------------------------------------------
    def handle_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Event)).contents
        # Kernel-side namespace filter already cheap; double-check container
        # origin in user space (host processes share PID 1's mount namespace).
        if event.mnt_ns == host_mnt_ns:
            return
        metrics.record_event()

        pid = event.pid
        comm = event.comm.decode("utf-8", "replace")
        et = event.event_type
        # NOTE: Pod enrichment is intentionally NOT done here -- it happens
        # lazily inside DetectionEngine._alert, so the hot path stays cheap.

        cg = event.cgroup_id
        if rec_f is not None:
            # Record the exact event the engine sees, so the Python and Go
            # engines replay a byte-identical input stream.
            ip_s = ""
            if et == EVENT_CONNECT:
                ip_s = socket.inet_ntoa(struct.pack("<I", event.daddr))
            rec_f.write(json.dumps({
                "ts": time.time(), "et": et, "pid": pid, "comm": comm,
                "uid": event.uid, "mnt_ns": event.mnt_ns,
                "net_ns": event.net_ns, "cgroup_id": cg, "flags": event.flags,
                "filename": event.filename.decode("utf-8", "replace"),
                "ip": ip_s, "dport": event.dport,
            }) + "\n")
        if et == EVENT_OPEN:
            engine.on_open(pid, comm, event.filename, cg)
        elif et == EVENT_EXEC:
            engine.on_exec(pid, comm, event.filename)
        elif et == EVENT_MOUNT:
            engine.on_mount(pid, comm, event.filename, event.flags, cg)
        elif et == EVENT_SETNS:
            engine.on_setns(pid, comm, event.flags)
        elif et == EVENT_UNSHARE:
            # unshare alone is not an alert; recorded into BoSC for context.
            engine.bosc[pid].append("unshare")
        elif et == EVENT_CONNECT:
            ip = socket.inet_ntoa(struct.pack("<I", event.daddr))
            engine.on_connect(pid, comm, ip, event.dport, cg)

    # Larger ring + a lost-event callback so buffer drops are quantified
    # rather than silent (they previously caused missed detections).
    def lost_cb(*a):
        metrics.record_lost(a[-1])
    b["events"].open_perf_buffer(handle_event, page_cnt=PERF_PAGES,
                                 lost_cb=lost_cb)

    # ---- B3 graph-scalability sampler / pruner (default off) ----------------
    def _rss_kb():
        try:
            for line in open("/proc/self/status"):
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        except Exception:
            pass
        return 0
    stats_f = open(args.stats_out, "w") if args.stats_out else None
    if stats_f:
        stats_f.write("t_s,events,nodes,edges,rss_kb\n")
    start_ts = time.time()
    last_stats = start_ts

    print("Listening for container events... (Ctrl+C to stop)\n")
    try:
        while True:
            # Timeout so the loop wakes even with no events, for periodic
            # stats/prune. perf_buffer_poll timeout is in milliseconds.
            b.perf_buffer_poll(timeout=int(args.stats_interval * 1000)
                               if (stats_f or args.prune_window) else 0)
            if stats_f or args.prune_window:
                now = time.time()
                if now - last_stats >= args.stats_interval:
                    if args.prune_window:
                        engine.prune_graph(now - args.prune_window)
                    if stats_f:
                        n, e = engine.graph_size()
                        stats_f.write("%.1f,%d,%d,%d,%d\n" % (
                            now - start_ts, metrics.total_events,
                            n, e, _rss_kb()))
                        stats_f.flush()
                    last_stats = now
    except KeyboardInterrupt:
        print("\nStopping agent.")
    finally:
        if stats_f is not None:
            stats_f.close()
        if rec_f is not None:
            rec_f.close()
        if args.graph_out:
            engine.dump_graph(args.graph_out)
        summary = metrics.summary()
        print("\n[metrics] " + json.dumps(summary))
        if args.summary_out:
            with open(args.summary_out, "w") as sf:
                json.dump(summary, sf, indent=2)
            print("[metrics] summary written to %s" % args.summary_out)
        metrics.close()


if __name__ == "__main__":
    main()
