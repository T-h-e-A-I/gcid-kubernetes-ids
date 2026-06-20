#!/bin/bash
# =============================================================================
# footprint_sample.sh -- Task 2.2: precise user-space CPU/RSS of the eBPF agent
# under in-container (filter-surviving) load.
# -----------------------------------------------------------------------------
# Why not pidstat: its interval must be an INTEGER, and at 1 s it floors sub-1%
# CPU to 0.00 -- the very number we need. Instead we read utime+stime *ticks*
# from /proc/<pid>/stat once per second. Each 1 s sample is tick-quantized
# (coarse), but (a) the MEAN of many samples recovers a precise sub-1% value, and
# (b) we also compute the mean directly from total ticks over the whole window,
# which has resolution ~1/(DUR*CLK_TCK) (e.g. 0.008% over 120 s). RSS is read
# from /proc/<pid>/status (VmRSS).
#
# Usage -- run this WHILE driving in-container filter-surviving load:
#   Terminal A: sudo python3 src/ebpf_agent.py --no-enrich --metrics /dev/null \
#                    --pod-cidr 10.42.0.0/16 --svc-cidr 10.43.0.0/16
#   Terminal B: DURATION=120 ./experiments/benign_fpr.sh
#   Terminal C: DURATION=120 ./experiments/footprint_sample.sh
# =============================================================================
set -uo pipefail
DUR="${DURATION:-120}"
RESULTS_DIR="${RESULTS_DIR:-results}"; mkdir -p "$RESULTS_DIR"
# Select the python3 interpreter, not the sudo wrapper (P0-C).
PID="${PID:-$(ps -C python3 -o pid=,args= | awk '/ebpf_agent\.py/{print $1; exit}')}"
[ -n "$PID" ] || { echo "ERROR: eBPF agent (python3 ebpf_agent.py) not running."; exit 1; }
echo "agent PID=$PID  sampling ${DUR}s  (drive load with benign_fpr.sh now)"

CLK=$(getconf CLK_TCK)
cpu_ticks(){ local s; s=$(< /proc/"$1"/stat); s=${s##*) }; set -- $s; echo $(( ${12} + ${13} )); }
rss_mb(){ awk '/^VmRSS/{printf "%.1f\n",$2/1024}' /proc/"$1"/status; }

CPUF="$RESULTS_DIR/footprint_incontainer_cpu.txt"; : > "$CPUF"
RSSF="$RESULTS_DIR/footprint_incontainer_mem.txt"; : > "$RSSF"
start=$(cpu_ticks "$PID"); prev=$start
for ((i=0; i<DUR; i++)); do
    sleep 1
    cur=$(cpu_ticks "$PID" 2>/dev/null || echo "$prev")
    awk -v d=$((cur - prev)) -v clk="$CLK" 'BEGIN{printf "%.3f\n",(d/clk)*100}' >> "$CPUF"
    rss_mb "$PID" >> "$RSSF"
    printf "\r  elapsed %ds/%ds" "$((i+1))" "$DUR"
    prev=$cur
done
end=$cur; echo ""

python3 - "$CPUF" "$RSSF" "$start" "$end" "$DUR" "$CLK" <<'PY'
import sys, statistics as s
cpuf, rssf, st, en, dur, clk = sys.argv[1:7]
v = [float(x) for x in open(cpuf) if x.strip()]
r = [float(x) for x in open(rssf) if x.strip()]
win = 100.0 * (int(en) - int(st)) / (int(dur) * int(clk))   # precise window mean
print("="*56)
print("eBPF agent user-space footprint (in-container load)")
print("  CPU%%: per-sec mean=%.3f  std=%.3f  | window mean=%.3f  (n=%d)"
      % (s.mean(v), s.pstdev(v), win, len(v)))
print("  RSS : mean=%.1f MB  (max %.1f MB)" % (s.mean(r) if r else 0, max(r) if r else 0))
print("  -> report 'window mean' as the representative CPU number for tab:agent_footprint")
print("="*56)
PY
echo "raw samples: $CPUF , $RSSF"
