// ============================================================================
// ebpf_probes.c  --  Kernel-space eBPF data plane (PRODUCTION / kprobe variant)
// ----------------------------------------------------------------------------
// Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
//         eBPF Syscall Monitoring.
//
// This is the production probe set. It attaches kprobes to security-relevant
// system calls and pushes a compact event record to user space via a perf ring
// buffer.
//
// v2 CHANGE -- IN-KERNEL FILTERING (improvement-plan-v2 P0-1):
//   The first design submitted EVERY syscall from EVERY process to user space
//   and filtered in Python. Under load this saturated the perf ring buffer,
//   causing dropped/late events (E2 flaky, E3 missed), high latency, and ~26%
//   agent CPU. We now filter IN THE KERNEL before perf_submit:
//     * drop host (non-container) events    -- compare mnt_ns to HOST_MNT_NS
//     * openat:  submit only "interesting" paths (host mount / token / ns / ...)
//     * execve:  submit only shells and host-path binaries
//     * connect: submit only destinations inside the Pod/Service CIDR
//   The filter constants are injected by the agent via -D cflags; standalone
//   defaults below disable filtering so the file still compiles on its own.
//
// Hooks (mapped to the Chapter 3 threat model):
//   execve   -> anomalous binary / shell execution (post-exploitation)
//   openat   -> unauthorized host-file access (vertical escape, token theft)
//   mount    -> privileged host-filesystem mount (insecure-config escape step)
//   setns    -> namespace switch escape (nsenter; Bertinatto BoSC signature)
//   unshare  -> namespace manipulation
//   tcp_v4_connect -> lateral movement / internal scanning
// ============================================================================

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <uapi/linux/in.h>   // struct sockaddr_in (connect destination)
#include <bcc/proto.h>

// ---- Filter constants (overridden by the agent via -D cflags) --------------
#ifndef HOST_MNT_NS
#define HOST_MNT_NS 0ULL        // 0 => never matches a real ns => host not dropped
#endif
#ifndef POD_NET
#define POD_NET  0U
#endif
#ifndef POD_MASK
#define POD_MASK 0U             // mask 0 => every address "matches" => no filter
#endif
#ifndef SVC_NET
#define SVC_NET  0U
#endif
#ifndef SVC_MASK
#define SVC_MASK 0U
#endif

// ---- Event type discriminators (must match Python EVENT_* constants) -------
#define EVENT_EXEC     1
#define EVENT_OPEN     2
#define EVENT_CONNECT  3
#define EVENT_MOUNT    4
#define EVENT_SETNS    5
#define EVENT_UNSHARE  6

// ---- The record shipped from kernel space to user space --------------------
// Keep byte-for-byte in sync with `class Event` in src/ebpf_agent.py.
struct event_t {
    u32 event_type;
    u32 pid;
    u32 uid;
    u64 mnt_ns;
    u64 net_ns;
    u64 cgroup_id;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

// The event record (~330 B) is too large for the 512 B BPF stack once the
// in-kernel filtering locals are added, so we keep it in a per-CPU scratch map
// instead of on the stack. One entry, reused per probe invocation.
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);

// ----------------------------------------------------------------------------
// Namespace inode helpers. mnt_namespace is opaque (fs/mount.h not on the BPF
// include path); its first member is a complete `struct ns_common`, so we read
// that from the pointer base. struct net is fully defined, so it uses the
// named field.
// ----------------------------------------------------------------------------
static inline void get_namespaces(u64 *mnt_ns, u64 *net_ns) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        void *mnt;
        bpf_probe_read_kernel(&mnt, sizeof(mnt), &nsproxy->mnt_ns);
        if (mnt) {
            struct ns_common nsc = {};
            bpf_probe_read_kernel(&nsc, sizeof(nsc), mnt);
            *mnt_ns = nsc.inum;
        }
        struct net *net;
        bpf_probe_read_kernel(&net, sizeof(net), &nsproxy->net_ns);
        if (net) {
            bpf_probe_read_kernel(net_ns, sizeof(*net_ns), &net->ns.inum);
        }
    }
}

// get_event -- fetch the per-CPU scratch event, zero it, and populate the
// fields every event shares. Returns NULL only if the map lookup fails (the
// verifier requires the caller to check).
static inline struct event_t *get_event(u32 type) {
    int zero = 0;
    struct event_t *event = scratch.lookup(&zero);
    if (!event)
        return NULL;
    __builtin_memset(event, 0, sizeof(*event));   // clear stale per-CPU data
    event->event_type = type;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_namespaces(&event->mnt_ns, &event->net_ns);
    return event;
}

// is_host -- true if the current task is a host (non-container) process, i.e.
// its mount namespace equals the host init mount namespace. Filtering these in
// the kernel removes the bulk of irrelevant events.
static inline int is_host(struct event_t *event) {
    return event->mnt_ns == HOST_MNT_NS;
}

// startswith -- compile-time-bounded prefix compare against a string literal.
// `n` is a constant at every call site, so the loop is fully unrolled and the
// verifier sees a small, bounded sequence of byte comparisons.
static inline int startswith(const char *s, const char *pfx, int n) {
#pragma unroll
    for (int i = 0; i < n; i++) {
        if (pfx[i] == '\0') return 1;
        if (s[i] != pfx[i]) return 0;
    }
    return 1;
}

// contains_ns -- bounded scan for "/ns/" within the first 48 bytes, to catch
// /proc/<pid>/ns/mnt regardless of the PID's length (nsenter target).
static inline int contains_ns(const char *s) {
#pragma unroll
    for (int i = 0; i < 48; i++) {
        if (s[i] == '\0') break;
        if (s[i] == '/' && s[i + 1] == 'n' && s[i + 2] == 's' && s[i + 3] == '/')
            return 1;
    }
    return 0;
}

// interesting_open -- keep only paths relevant to the detection rules; this is
// what collapses the openat flood. Mirrors the user-space HOST_MOUNT_PREFIXES /
// TOKEN_PATHS / HOST_ONLY_OBJECTS sets.
static inline int interesting_open(const char *fn) {
    if (startswith(fn, "/host", 5)) return 1;                 // host mount
    if (startswith(fn, "/var/run/secrets", 16)) return 1;     // SA token
    if (startswith(fn, "/run/secrets", 12)) return 1;
    if (startswith(fn, "/run/containerd", 15)) return 1;      // host-only sock
    if (startswith(fn, "/var/run/docker.sock", 20)) return 1;
    if (startswith(fn, "/var/lib/kubelet", 16)) return 1;
    if (startswith(fn, "/etc/kubernetes/pki", 19)) return 1;
    if (startswith(fn, "/proc", 5) && contains_ns(fn)) return 1; // ns switch
    return 0;
}

// interesting_exec -- shells (post-exploitation) and host-path binaries
// (component-vuln escape). Everything else is dropped in-kernel.
static inline int interesting_exec(const char *fn) {
    if (startswith(fn, "/host", 5)) return 1;
    if (startswith(fn, "/bin/sh", 7)) return 1;
    if (startswith(fn, "/bin/bash", 9)) return 1;
    if (startswith(fn, "/usr/bin/sh", 11)) return 1;
    if (startswith(fn, "/usr/bin/bash", 13)) return 1;
    return 0;
}

// to_host -- byte-swap a network-order IPv4 to host order for CIDR comparison.
static inline u32 to_host(u32 n) {
    return ((n & 0x000000ffU) << 24) | ((n & 0x0000ff00U) << 8) |
           ((n & 0x00ff0000U) >> 8)  | ((n & 0xff000000U) >> 24);
}

// in_cluster -- true if a network-order IPv4 lies in the Pod or Service CIDR.
static inline int in_cluster(u32 net_order_addr) {
    u32 d = to_host(net_order_addr);
    if ((d & POD_MASK) == POD_NET) return 1;
    if ((d & SVC_MASK) == SVC_NET) return 1;
    return 0;
}

// 1. execve
int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    struct event_t *event = get_event(EVENT_EXEC);
    if (!event) return 0;
    if (is_host(event)) return 0;                        // kernel-side filter
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    if (!interesting_exec(event->filename)) return 0;    // drop benign execs
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 2. openat
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename,
                    int flags, int mode)
{
    struct event_t *event = get_event(EVENT_OPEN);
    if (!event) return 0;
    if (is_host(event)) return 0;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    if (!interesting_open(event->filename)) return 0;    // drop the openat flood
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 2b. open -- LEGACY open syscall. Confirmed essential by diagnosis: the
//     netshoot attacker image's tools (busybox head/cat/cp, util-linux nsenter)
//     call open(), NOT openat() -- so without this hook the attacker's file
//     opens (E1 host file, E2 token, E3 /proc/<pid>/ns/mnt) were all invisible
//     while system Go binaries (which use openat) were captured. Filename is
//     the FIRST argument for open().
int syscall__open(struct pt_regs *ctx, const char __user *filename,
                  int flags, int mode)
{
    struct event_t *event = get_event(EVENT_OPEN);
    if (!event) return 0;
    if (is_host(event)) return 0;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    if (!interesting_open(event->filename)) return 0;
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 2c. openat2 -- newer open variant. Same handling; best-effort attach.
int syscall__openat2(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct event_t *event = get_event(EVENT_OPEN);
    if (!event) return 0;
    if (is_host(event)) return 0;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    if (!interesting_open(event->filename)) return 0;
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 3. mount -- privileged host-filesystem mount. Rare; submit all container
//    mounts (user space scopes out the container runtime's own mounts).
int syscall__mount(struct pt_regs *ctx, const char __user *source,
                   const char __user *target, const char __user *fstype,
                   unsigned long mountflags, const void __user *data)
{
    struct event_t *event = get_event(EVENT_MOUNT);
    if (!event) return 0;
    if (is_host(event)) return 0;
    event->flags = (u32)mountflags;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), target);
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 3b. move_mount -- the NEW mount API. Modern util-linux (and an evasive
//     attacker) mounts via fsopen()+fsmount()+move_mount() instead of the
//     legacy mount(2) syscall, which would otherwise bypass syscall__mount
//     entirely. move_mount() is the step that attaches the mount into the
//     filesystem tree, so it is the meaningful "a mount happened" signal.
//     Reported as EVENT_MOUNT so user space treats it identically.
int syscall__move_mount(struct pt_regs *ctx, int from_dfd,
                        const char __user *from_path, int to_dfd,
                        const char __user *to_path, unsigned int flags)
{
    struct event_t *event = get_event(EVENT_MOUNT);
    if (!event) return 0;
    if (is_host(event)) return 0;
    event->flags = (u32)flags;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), to_path);
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 4. setns -- namespace-switch escape. The nstype flag is captured but user
//    space no longer requires CLONE_NEWNS (nsenter often passes nstype=0).
int syscall__setns(struct pt_regs *ctx, int fd, int nstype)
{
    struct event_t *event = get_event(EVENT_SETNS);
    if (!event) return 0;
    if (is_host(event)) return 0;
    event->flags = (u32)nstype;
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 5. unshare
int syscall__unshare(struct pt_regs *ctx, int flags)
{
    struct event_t *event = get_event(EVENT_UNSHARE);
    if (!event) return 0;
    if (is_host(event)) return 0;
    event->flags = (u32)flags;
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

// 6. tcp_v4_connect -- lateral movement / internal scanning.
//    The destination is read from the `uaddr` argument (at kprobe entry the
//    socket's skc_daddr is not yet populated -- v1 P0-A fix), and only
//    in-cluster destinations are submitted (v2 P0-1 CIDR prefilter).
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk,
                           struct sockaddr *uaddr)
{
    struct event_t *event = get_event(EVENT_CONNECT);
    if (!event) return 0;
    if (is_host(event)) return 0;

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    u32 daddr = 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sin->sin_port);

    if (!in_cluster(daddr)) return 0;                    // drop external chatter

    event->daddr = daddr;         // network byte order (decoded in user space)
    event->dport = ntohs(dport);
    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
