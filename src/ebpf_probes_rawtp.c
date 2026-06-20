// ============================================================================
// ebpf_probes_rawtp.c  --  RAW-TRACEPOINT variant (EXPERIMENT-ONLY)
// ----------------------------------------------------------------------------
// Thesis: Detecting Container Escape and Lateral Movement in Kubernetes via
//         eBPF Syscall Monitoring.
//
// PURPOSE (see Roadmap/implementation-plan-v2.md, decision #2 + section 5.2):
//   This file is NOT the production data plane. It exists solely to reproduce
//   the Bertinatto et al. overhead comparison between eBPF program types
//   (kprobe vs tracepoint vs raw tracepoint). It attaches a single
//   raw_tracepoint at `sys_enter` and extracts the same syscall information the
//   production kprobe probes capture, so the overhead measured in
//   experiments/bench_program_types.sh is an apples-to-apples comparison.
//
// WHY RAW TRACEPOINTS ARE EXPECTED TO BE FASTER:
//   A raw tracepoint receives the *unformatted* argument array and the program
//   must parse syscall arguments out of `struct pt_regs` itself. Skipping the
//   kernel's automatic argument marshalling is exactly what makes it cheaper
//   than a regular tracepoint, and it avoids the breakpoint machinery a kprobe
//   installs.
//
// PORTABILITY NOTE:
//   Syscall argument registers follow the x86-64 System V syscall ABI:
//     arg0=di, arg1=si, arg2=dx, arg3=r10, arg4=r8, arg5=r9
//   On other architectures the register names differ. Tested target is
//   x86-64, Linux kernel 5.15+ with BTF (matches the thesis lab).
// ============================================================================

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

// x86-64 syscall numbers we care about (match the production hooks).
#define SYS_EXECVE   59
#define SYS_OPENAT  257
#define SYS_CONNECT  42

#define EVENT_EXEC     1
#define EVENT_OPEN     2
#define EVENT_CONNECT  3

// Same wire format as the production probes so the user-space agent and the
// benchmark harness can decode either variant identically.
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

// Per-CPU scratch for the event (too large for the 512 B BPF stack).
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);

static inline void get_namespaces(u64 *mnt_ns, u64 *net_ns) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (nsproxy) {
        // mnt_namespace is opaque (fs/mount.h); its first member is a complete
        // `struct ns_common`, so read that from the pointer base for the inode.
        void *mnt;
        bpf_probe_read_kernel(&mnt, sizeof(mnt), &nsproxy->mnt_ns);
        if (mnt) {
            struct ns_common nsc = {};
            bpf_probe_read_kernel(&nsc, sizeof(nsc), mnt);
            *mnt_ns = nsc.inum;
        }
        struct net *net;
        bpf_probe_read_kernel(&net, sizeof(net), &nsproxy->net_ns);
        if (net) bpf_probe_read_kernel(net_ns, sizeof(*net_ns), &net->ns.inum);
    }
}

// ----------------------------------------------------------------------------
// Single raw tracepoint on sys_enter. ctx->args for sys_enter are:
//   args[0] = struct pt_regs *regs   (the user register state at syscall entry)
//   args[1] = long id                (the syscall number)
// We manually pull syscall arguments out of `regs` (the work a regular
// tracepoint would have done for us -- the source of the overhead difference).
// ----------------------------------------------------------------------------
RAW_TRACEPOINT_PROBE(sys_enter)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    unsigned long id = (unsigned long)ctx->args[1];

    // Only handle the three syscalls the production probes monitor, so the
    // per-event work is comparable across program types.
    u32 type;
    if (id == SYS_EXECVE)       type = EVENT_EXEC;
    else if (id == SYS_OPENAT)  type = EVENT_OPEN;
    else if (id == SYS_CONNECT) type = EVENT_CONNECT;
    else                        return 0;

    int zero = 0;
    struct event_t *event = scratch.lookup(&zero);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = type;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_namespaces(&event->mnt_ns, &event->net_ns);

    // Manually parse the first syscall argument from pt_regs (x86-64 ABI).
    if (type == EVENT_EXEC || type == EVENT_OPEN) {
        // execve: arg0 = filename pointer (di)
        // openat: arg1 = filename pointer (si)
        unsigned long ptr = 0;
        if (type == EVENT_EXEC)
            bpf_probe_read_kernel(&ptr, sizeof(ptr), &regs->di);
        else
            bpf_probe_read_kernel(&ptr, sizeof(ptr), &regs->si);
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename),
                                (void *)ptr);
    }
    // For CONNECT we intentionally do not resolve the sockaddr here: the
    // benchmark only needs comparable per-event cost, and the production path
    // captures connection details at tcp_v4_connect instead.

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
