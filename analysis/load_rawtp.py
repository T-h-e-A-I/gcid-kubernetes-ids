#!/usr/bin/env python3
# =============================================================================
# load_rawtp.py -- Standalone loader for the raw-tracepoint variant
# -----------------------------------------------------------------------------
# Used ONLY by experiments/bench_program_types.sh to attach the raw-tracepoint
# program (src/ebpf_probes_rawtp.c) while the syscall workload runs, so its
# overhead can be measured alongside the kprobe/tracepoint variants.
#
# It drains the perf buffer (to incur realistic end-to-end cost) but does no
# detection. Run as root; killed by the benchmark when the measurement ends.
# =============================================================================
import os
import sys
from bcc import BPF

SRC = os.path.join(os.path.dirname(__file__), "..", "src", "ebpf_probes_rawtp.c")


def main():
    b = BPF(src_file=SRC)
    # RAW_TRACEPOINT_PROBE(sys_enter) auto-attaches by name; nothing else to do.
    # Drain events so the full kernel->user path is exercised during the bench.
    b["events"].open_perf_buffer(lambda cpu, data, size: None)
    sys.stderr.write("[load_rawtp] raw tracepoint attached; draining events\n")
    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
