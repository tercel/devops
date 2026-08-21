#!/usr/bin/env bash
#
# diag-52x.sh — Diagnose Cloudflare origin errors (520/521/522/524) on this host.
#
# The 52x codes are DIFFERENT failures with different causes. Read the verdict
# against the code the edge actually returned:
#
#   520  The edge connected fine, but this origin answered something empty,
#        malformed or unexpected: a reset mid-response, or headers above
#        Cloudflare's 128 KB limit. It is also what a connection left idle
#        past the 900s Proxy Idle Timeout comes back as. Usually the upstream
#        app crashed / was OOM-killed, or an nginx worker died.
#                                                           -> section 6b
#   521  The origin refused the connection outright: nginx down, or a firewall
#        REJECT rather than DROP.                           -> section 5
#   522  The edge gave up connecting: no SYN+ACK within 19s, or no ACK of its
#        request within 90s once connected. Listen-queue overflow, conntrack
#        exhaustion, memory/IO collapse, or keepalives disabled at the origin.
#                                                           -> section 8/5/4
#   524  The connection succeeded but the origin did not finish the response
#        within the 125s Proxy Read Timeout. A slow upstream, not a
#        connectivity fault.                                -> section 6b
#
# 520 and 522 alternating on the same host usually means one thing: the
# upstream application is restarting under memory pressure.
#
# Usage:
#   sudo ./diag-52x.sh                 # analyse the last 3 hours
#   sudo ./diag-52x.sh -H 6            # analyse the last 6 hours
#   sudo ./diag-52x.sh -d 17/Aug/2026 -w 06,07
#   sudo ./diag-52x.sh -o /tmp/out.txt
#
# Sites, upstream ports and application roots are discovered from the running
# nginx config and from pm2 — nothing about the deployment is hardcoded.
# Override only when the discovery is wrong:
#   -s "name ..."        site names (conventional <name>.access.log layout)
#   -s "/path/acc.log"   explicit log paths for an unconventional layout
#   -n 20                raise the cap on how many sites are analysed
#
# Exit code is always 0; this is a read-only report, never a remediation tool.

set -uo pipefail

# ---------------------------------------------------------------- parameters --
HOURS_BACK=3
LOG_DATE=""
HOUR_LIST=""
OUTFILE="/tmp/diag-52x-$(date +%Y%m%d-%H%M%S).txt"
NGINX_LOG_DIR="/var/log/nginx"
# Sites are discovered from the running nginx config. Override with
# -s "name-or-logpath ..." only when the discovery picks the wrong ones.
SITES=""
MAX_SITES=12

while getopts "H:d:w:o:s:n:h" opt; do
  case "$opt" in
    H) HOURS_BACK="$OPTARG" ;;
    d) LOG_DATE="$OPTARG" ;;
    w) HOUR_LIST="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    s) SITES="$OPTARG" ;;
    n) MAX_SITES="$OPTARG" ;;
    h) sed -n '3,40p' "$0"; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 0 ;;
  esac
done

# -H feeds arithmetic expansion and date(1); a non-numeric value would produce
# a confusing cascade of failures several sections later.
if ! [[ "$HOURS_BACK" =~ ^[0-9]+$ ]] || [ "$HOURS_BACK" -lt 1 ]; then
  echo "-H must be a positive integer number of hours (got: ${HOURS_BACK})" >&2
  exit 0
fi

[ -z "$LOG_DATE" ] && LOG_DATE="$(date +%d/%b/%Y)"

# -d and -w are interpolated into the command strings run() evaluates, so they
# are validated as literal patterns rather than trusted. A log timestamp needs
# none of the characters a shell would act on, and this script runs as root.
if ! [[ "$LOG_DATE" =~ ^[0-9]{2}/[A-Za-z]{3}/[0-9]{4}$ ]]; then
  echo "-d must be dd/Mon/yyyy (e.g. 17/Aug/2026), got: ${LOG_DATE}" >&2
  exit 1
fi
if [ -n "$HOUR_LIST" ] && ! [[ "$HOUR_LIST" =~ ^[0-9]{1,2}(,[0-9]{1,2})*$ ]]; then
  echo "-w must be comma-separated hours (e.g. 06,07), got: ${HOUR_LIST}" >&2
  exit 1
fi
if ! [[ "$MAX_SITES" =~ ^[0-9]+$ ]] || [ "$MAX_SITES" -lt 1 ]; then
  echo "-n must be a positive integer (got: ${MAX_SITES})" >&2
  exit 1
fi

# nginx timestamps access logs as dd/Mon/yyyy but error logs as yyyy/mm/dd.
# Without both forms, -d would silently match nothing in any error log.
ERR_DATE="$(date -d "$(echo "$LOG_DATE" | tr '/' ' ')" +%Y/%m/%d 2>/dev/null \
            || date -j -f '%d/%b/%Y' "$LOG_DATE" +%Y/%m/%d 2>/dev/null \
            || date +%Y/%m/%d)"

# Build an hour regex like (05|06|07) covering the analysis window.
if [ -n "$HOUR_LIST" ]; then
  HOUR_RE="($(echo "$HOUR_LIST" | tr ',' '|'))"
else
  _h=""
  for ((i = HOURS_BACK - 1; i >= 0; i--)); do
    _h="${_h}|$(date -d "$i hours ago" +%H 2>/dev/null || date -v-"${i}"H +%H)"
  done
  HOUR_RE="(${_h#|})"
fi

SAR_START="$(date -d "$HOURS_BACK hours ago" +%H:%M:%S 2>/dev/null || date -v-"${HOURS_BACK}"H +%H:%M:%S)"
SAR_END="$(date +%H:%M:%S)"

# ------------------------------------------------------------------- helpers --
C_RED=$'\033[0;31m'; C_YEL=$'\033[0;33m'; C_GRN=$'\033[0;32m'
C_CYA=$'\033[0;36m'; C_BLD=$'\033[1m';   C_OFF=$'\033[0m'
[ -t 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYA=""; C_BLD=""; C_OFF=""; }

FINDINGS_CRIT=(); FINDINGS_WARN=(); FINDINGS_OK=()
crit() { FINDINGS_CRIT+=("$1"); }
warn() { FINDINGS_WARN+=("$1"); }
ok()   { FINDINGS_OK+=("$1"); }

section() {
  local pad=$((62 - ${#1})); [ "$pad" -lt 3 ] && pad=3
  printf '\n%s%s== %s %s%s\n' "$C_BLD" "$C_CYA" "$1" "$(printf '=%.0s' $(seq 1 "$pad"))" "$C_OFF"
}
step()    { printf '\n%s-- %s%s\n' "$C_BLD" "$1" "$C_OFF"; }
note()    { printf '   %s\n' "$1"; }

# Run a command, tolerate failure, indent output.
run() {
  local out
  out="$(eval "$1" 2>&1)"
  if [ -z "$out" ]; then
    printf '   (no output)\n'
  else
    printf '%s\n' "$out" | sed 's/^/   /'
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# Integer-safe compare that tolerates empty/non-numeric input.
num() { local v="${1:-0}"; [[ "$v" =~ ^-?[0-9]+$ ]] && echo "$v" || echo 0; }

if [ "$(id -u)" -ne 0 ]; then
  printf '%sWARNING: not running as root. Log files and ss/dmesg output will be incomplete.%s\n' "$C_YEL" "$C_OFF"
  printf '%sRe-run with: sudo %s%s\n\n' "$C_YEL" "$0" "$C_OFF"
fi

# Mirror everything to the report file. Colour stays on the terminal only:
# escape codes in the saved file make it unreadable and impossible to grep.
if sed -u '' </dev/null >/dev/null 2>&1; then
  exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' > "$OUTFILE")) 2>&1
else
  exec > >(tee "$OUTFILE") 2>&1
fi
TEE_PID=$!

cat <<EOF
${C_BLD}Cloudflare 522 origin diagnostics${C_OFF}
  host           : $(hostname)
  generated      : $(date '+%F %T %Z')
  kernel         : $(uname -r)
  log date filter: ${LOG_DATE}
  hour filter    : ${HOUR_RE}
  sar window     : ${SAR_START} .. ${SAR_END}
  report file    : ${OUTFILE}
EOF

# ============================================================== 1. OVERVIEW ==
section "1. System overview"

step "Uptime and load (compare load against core count)"
run "uptime"
CORES="$(nproc 2>/dev/null || echo 1)"
note "cores: ${CORES}"
LOAD1="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null | cut -d. -f1)"
if [ "$(num "$LOAD1")" -gt "$((CORES * 2))" ]; then
  crit "Load average ($(cut -d' ' -f1 /proc/loadavg)) is more than 2x the ${CORES} available cores — the box is saturated right now."
elif [ "$(num "$LOAD1")" -gt "$CORES" ]; then
  warn "Load average ($(cut -d' ' -f1 /proc/loadavg)) exceeds the ${CORES} core count."
fi

step "CPU model and count"
run "lscpu | grep -E 'Model name|^CPU\(s\)|Thread|Core' | head -5"

# ================================================================ 2. MEMORY ==
section "2. Memory, swap and OOM"

step "Current memory and swap"
run "free -h"
run "swapon --show"

MEM_TOTAL="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
MEM_AVAIL="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
SWAP_TOTAL="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
SWAP_FREE="$(awk '/SwapFree/{print $2}' /proc/meminfo)"
SWAP_USED=$(( $(num "$SWAP_TOTAL") - $(num "$SWAP_FREE") ))
COMMIT="$(awk '/Committed_AS/{print $2}' /proc/meminfo)"

if [ "$(num "$MEM_TOTAL")" -gt 0 ]; then
  AVAIL_PCT=$(( $(num "$MEM_AVAIL") * 100 / $(num "$MEM_TOTAL") ))
  note "available memory: ${AVAIL_PCT}% of total"
  [ "$AVAIL_PCT" -lt 10 ] && crit "Only ${AVAIL_PCT}% memory available — the host is on the edge of thrashing."
  [ "$AVAIL_PCT" -ge 10 ] && [ "$AVAIL_PCT" -lt 25 ] && warn "Only ${AVAIL_PCT}% memory available; little headroom for a build or traffic spike."

  # Committed_AS far above physical RAM means the host survives only via swap.
  if [ "$(num "$COMMIT")" -gt "$MEM_TOTAL" ]; then
    OVER=$(( $(num "$COMMIT") * 100 / $(num "$MEM_TOTAL") ))
    warn "Committed memory is ${OVER}% of physical RAM ($(( $(num "$COMMIT") / 1024 ))MB committed vs $(( $(num "$MEM_TOTAL") / 1024 ))MB physical) — oversubscribed, leaning on swap."
  fi
fi
# A flat 1GB threshold never fires on a 2GB box with 512MB of swap, which is
# exactly the shape of host that 522s under memory pressure.
if [ "$(num "$SWAP_TOTAL")" -gt 0 ] && [ "$SWAP_USED" -gt 0 ]; then
  SWAP_PCT=$(( SWAP_USED * 100 / $(num "$SWAP_TOTAL") ))
  if [ "$SWAP_PCT" -gt 25 ] || [ "$SWAP_USED" -gt 1048576 ]; then
    warn "Swap in use: $(( SWAP_USED / 1024 ))MB (${SWAP_PCT}% of swap). Sustained swapping means chronic memory pressure; the IO stalls it causes translate directly into 522s."
  else
    note "swap in use: $(( SWAP_USED / 1024 ))MB (${SWAP_PCT}% of swap — low)"
  fi
fi

step "Top 12 memory consumers"
run "ps -eo pid,ppid,user,pmem,rss,etime,comm --sort=-rss | head -13"

step "Kernel OOM kills"
# The dmesg ring buffer wraps, so its silence proves nothing on a busy host.
# journalctl -k reads the persisted copy when journald storage is enabled.
OOM_PAT='out of memory|oom-killer|killed process|oom_reap'
OOM="$(journalctl -k --no-pager --since "${HOURS_BACK} hours ago" 2>/dev/null | grep -iE "$OOM_PAT")"
OOM_SRC="journalctl -k (last ${HOURS_BACK}h)"
if [ -z "$OOM" ]; then
  OOM="$(dmesg -T 2>/dev/null | grep -iE "$OOM_PAT")"
  OOM_SRC="dmesg ring buffer"
fi
note "source: ${OOM_SRC}"
if [ -z "$OOM" ]; then
  if dmesg -T >/dev/null 2>&1 || journalctl -k -n1 >/dev/null 2>&1; then
    ok "No OOM kills in the retained kernel log. Note the ring buffer wraps, so an older kill may simply have scrolled out."
  else
    warn "Could not read the kernel log (needs root) — OOM history unverified."
  fi
  note "(none)"
else
  printf '%s\n' "$OOM" | tail -25 | sed 's/^/   /'
  OOM_N="$(printf '%s\n' "$OOM" | grep -ci 'killed process')"
  # cgroup OOM = a container hit its own limit; system OOM = whole host ran dry.
  CG_N="$(printf '%s\n' "$OOM" | grep -ci 'memory cgroup out of memory')"
  if [ "$(num "$CG_N")" -gt 0 ]; then
    warn "${CG_N} cgroup-level OOM kill(s): a CONTAINER hit its own memory limit. This does not by itself explain a host-wide 522, but it is a real bug to fix."
  fi
  if [ "$(num "$OOM_N")" -gt "$(num "$CG_N")" ]; then
    crit "$(( $(num "$OOM_N") - $(num "$CG_N") )) host-level OOM kill(s) — the whole machine ran out of memory."
  fi
  note "Compare the OOM timestamps above against your outage window; if they differ by hours, OOM is NOT the cause."
fi

step "OOM and errors from journald in the analysis window"
run "journalctl --since '${HOURS_BACK} hours ago' -p err --no-pager 2>/dev/null | tail -30"

# ============================================================= 3. DISK / FD ==
section "3. Disk and file descriptors"

step "Disk usage"
run "df -h -x tmpfs -x devtmpfs"
DISK_PCT="$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')"
[ "$(num "$DISK_PCT")" -gt 90 ] && crit "Root filesystem ${DISK_PCT}% full — nginx cannot write logs, which can stall request handling."
[ "$(num "$DISK_PCT")" -gt 80 ] && [ "$(num "$DISK_PCT")" -le 90 ] && warn "Root filesystem ${DISK_PCT}% full."

step "Inode usage"
run "df -i -x tmpfs -x devtmpfs"

step "File descriptors (system-wide and nginx)"
run "cat /proc/sys/fs/file-nr"
NGINX_PID="$(pgrep -o nginx 2>/dev/null)"
[ -n "$NGINX_PID" ] && run "grep -i 'open files' /proc/${NGINX_PID}/limits"
FD_USED="$(awk '{print $1}' /proc/sys/fs/file-nr 2>/dev/null)"
note "open file handles: $(num "$FD_USED")"

# ================================================== 4. HISTORICAL RESOURCES ==
section "4. Historical resource curves (sar)"

if have sar; then
  step "Memory over time — look for a sudden kbmemfree collapse / kbdirty spike"
  run "sar -r -s ${SAR_START} -e ${SAR_END}"

  step "Swap paging — pswpout spikes mean the box was thrashing"
  run "sar -W -s ${SAR_START} -e ${SAR_END}"

  step "Block IO — a tps spike alongside the memory dip confirms build/IO saturation"
  run "sar -b -s ${SAR_START} -e ${SAR_END}"

  step "CPU — high %iowait is the smoking gun for 522 during IO storms"
  run "sar -u -s ${SAR_START} -e ${SAR_END}"

  step "Run queue and load"
  run "sar -q -s ${SAR_START} -e ${SAR_END}"

  step "Network errors and drops"
  run "sar -n EDEV -s ${SAR_START} -e ${SAR_END} 2>/dev/null | grep -vE '\s0\.00\s+0\.00\s+0\.00' | head -20"
else
  warn "sysstat/sar is not installed — no historical resource data. Install it so the NEXT incident leaves evidence: sudo apt install sysstat && sudo systemctl enable --now sysstat"
  note "sar not available"
fi

# ================================================================= 5. NGINX ==
section "5. Nginx health"

step "Service status"
run "systemctl is-active nginx; systemctl status nginx --no-pager -l 2>/dev/null | head -12"
systemctl is-active nginx >/dev/null 2>&1 || crit "nginx is NOT active — that alone produces 522/521 for every proxied domain."

step "Configuration syntax"
run "nginx -t"
nginx -t >/dev/null 2>&1 || crit "nginx config test FAILED — a reload would not have applied; running config may be stale."

# Dump the running configuration once: nginx -T re-reads every include file,
# and the original code invoked it four times in a row.
NGX_CONF="$(nginx -T 2>/dev/null)"

# ------------------------------------------------------- site discovery -----
# Log paths are read from the running configuration instead of assuming a
# "<name>.access.log" naming convention: that layout is one common convention,
# not a rule, and a hardcoded site list makes the script useless anywhere else.
SITE_LABEL=(); SITE_ACC=(); SITE_ERR=()

# Normalise to one token per line — braces and semicolons split out, comments
# stripped — so a plain depth counter can attribute each directive to its block.
ngx_normalise() {
  printf '%s\n' "$NGX_CONF" \
    | sed 's|^# configuration file \(.*\):$|@@FILE@@ \1|' \
    | sed 's/#.*//' \
    | sed 's/{/\n{\n/g; s/}/\n}\n/g; s/;/\n/g' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | grep -v '^$'
}

discover_from_conf() {
  ngx_normalise | awk '
    /^@@FILE@@/ { next }
    /^server$/  { pending = 1; next }
    $0 == "{" {
      depth++
      if (pending) { srv = depth; acc = ""; err = ""; name = ""; pending = 0 }
      next
    }
    $0 == "}" {
      if (srv && depth == srv) {
        # A server without its own log directives inherits the http-level ones.
        if (acc == "") acc = g_acc
        if (err == "") err = g_err
        if (name == "") name = "server-" (++anon)
        if (acc != "" && acc != "off") printf "%s\t%s\t%s\n", name, acc, err
        srv = 0
      }
      depth--
      next
    }
    depth == 1 && /^access_log / { g_acc = $2 }
    depth == 1 && /^error_log /  { g_err = $2 }
    srv && /^access_log /        { acc = $2 }
    srv && /^error_log /         { err = $2 }
    srv && /^server_name / && name == "" { name = $2 }
  '
}

# Used when nginx -T is unavailable (not root, nginx absent, config broken).
discover_from_disk() {
  local f base
  for f in "$NGINX_LOG_DIR"/*access*.log; do
    [ -r "$f" ] || continue
    base="$(basename "$f" | sed 's/[._-]\?access\.log$//; s/\.log$//')"
    [ -n "$base" ] || base="$(basename "$f")"
    printf '%s\t%s\t%s\n' "$base" "$f" "$(printf '%s' "$f" | sed 's/access/error/')"
  done
}

# -s accepts either a bare site name (the conventional layout) or a full log
# path, so an unusual deployment can still be pointed at explicitly.
sites_from_flag() {
  local tok acc
  for tok in $SITES; do
    if [ -r "$tok" ]; then
      acc="$tok"
    else
      acc="${NGINX_LOG_DIR}/${tok}.access.log"
    fi
    printf '%s\t%s\t%s\n' "$(basename "$tok" | sed 's/\.access\.log$//')" \
      "$acc" "$(printf '%s' "$acc" | sed 's/access/error/')"
  done
}

build_site_list() {
  local raw ranked label acc err mtime
  if [ -n "$SITES" ]; then
    raw="$(sites_from_flag)"
  else
    raw="$(discover_from_conf)"
    [ -z "$raw" ] && raw="$(discover_from_disk)"
  fi
  [ -n "$raw" ] || return 0

  # Rank by last write so the busiest sites are analysed first, dedupe by log
  # path (many servers can share one log), then cap the list.
  ranked="$(printf '%s\n' "$raw" | while IFS="$(printf '\t')" read -r label acc err; do
      [ -n "${acc:-}" ] || continue
      mtime="$(stat -c %Y "$acc" 2>/dev/null || stat -f %m "$acc" 2>/dev/null || echo 0)"
      printf '%s\t%s\t%s\t%s\n' "$mtime" "$label" "$acc" "$err"
    done | sort -rn -k1,1 | awk -F"\t" '!seen[$3]++' | head -"$MAX_SITES")"

  while IFS="$(printf '\t')" read -r mtime label acc err; do
    [ -n "${acc:-}" ] || continue
    # These paths come from `nginx -T` (or -s) and are interpolated into the
    # command strings run() evaluates. Anyone who can write a config fragment
    # could otherwise reach a root shell through an access_log directive, so a
    # path containing anything a shell acts on is refused rather than escaped.
    if ! [[ "$acc" =~ ^[A-Za-z0-9._@:+/-]+$ ]] \
       || { [ -n "${err:-}" ] && ! [[ "$err" =~ ^[A-Za-z0-9._@:+/-]+$ ]]; }; then
      warn "Ignoring a log path containing shell metacharacters: ${acc} (this is not a normal nginx log path — check who can write your nginx config)"
      continue
    fi
    SITE_LABEL+=("$label"); SITE_ACC+=("$acc"); SITE_ERR+=("$err")
  done <<< "$ranked"
}

NGX_NORM="$(ngx_normalise)"

build_site_list

step "Discovered sites"
if [ ${#SITE_LABEL[@]} -eq 0 ]; then
  warn "No nginx access logs found — every per-site section below will be empty. Pass -s explicitly, or check that ${NGINX_LOG_DIR} is readable (needs root)."
else
  note "source: $([ -n "$SITES" ] && echo '-s flag' || { [ -n "$NGX_CONF" ] && echo 'running nginx config' || echo "${NGINX_LOG_DIR} scan"; })"
  for _i in "${!SITE_LABEL[@]}"; do
    printf '   %-34s %s\n' "${SITE_LABEL[$_i]}" "${SITE_ACC[$_i]}"
  done
  [ ${#SITE_LABEL[@]} -ge "$MAX_SITES" ] && note "list capped at ${MAX_SITES}; raise with -n N if some sites are missing"
fi

step "Worker processes and connection limits"
printf '%s\n' "$NGX_CONF" \
  | grep -E '^\s*(worker_processes|worker_connections|worker_rlimit_nofile|keepalive_timeout|keepalive_requests|multi_accept)' \
  | sort -u | sed 's/^/   /'
WCONN="$(printf '%s\n' "$NGX_CONF" | grep -oP 'worker_connections\s+\K[0-9]+' | head -1)"
WPROC="$(printf '%s\n' "$NGX_CONF" | grep -oP 'worker_processes\s+\K\S+' | head -1)"
if [ -n "${WCONN:-}" ]; then
  # Capacity is worker_processes x worker_connections, and what matters is that
  # capacity against ACTUAL usage. A fixed "< 1024 is low" threshold flagged
  # 768 x 4 = 3072 as a problem on a host carrying single-digit concurrency,
  # which is a false alarm that sends the investigation down the wrong path.
  WPROC_N="${WPROC:-1}"
  [ "$WPROC_N" = "auto" ] && WPROC_N="$CORES"
  CAP=$(( $(num "$WCONN") * $(num "$WPROC_N") ))
  CUR="$(ss -ant 2>/dev/null | grep -c ESTAB)"
  note "worker_connections=${WCONN} x worker_processes=${WPROC:-?} => capacity ${CAP}; established now: $(num "$CUR")"
  if [ "$CAP" -gt 0 ]; then
    USE_PCT=$(( $(num "$CUR") * 100 / CAP ))
    if [ "$USE_PCT" -gt 70 ]; then
      warn "Connection capacity is ${USE_PCT}% consumed (${CUR} of ${CAP}). nginx starts refusing new connections near the limit, and the edge reports that as 522."
    else
      ok "Connection capacity ${CAP} against ${CUR} established (${USE_PCT}%) — not a constraint. The authoritative signal is 'worker_connections are not enough' in the error log (section 6), not this number."
    fi
  fi
fi

step "Origin keepalive vs Cloudflare connection reuse"
# Cloudflare holds idle origin connections open for up to 900s and reuses them.
# If the origin closes first, the edge writes into a socket that is already gone
# and reports 522. This is the most common cause of *intermittent* 522 on an
# otherwise healthy host, and it leaves no trace in any log.
# nginx accepts s/m/h/d suffixes, so a bare integer grep reads "15m" as 15
# seconds and "905s" as 905 — one under-reports by 60x, the other is fine.
# Normalise to seconds before comparing anything.
to_seconds() {
  printf '%s' "$1" | awk '{
    v = $0
    unit = substr(v, length(v), 1)
    n = v + 0
    if      (unit == "m") n *= 60
    else if (unit == "h") n *= 3600
    else if (unit == "d") n *= 86400
    printf "%d", n
  }'
}

KA_RAW="$(printf '%s\n' "$NGX_NORM" | grep -oP '^keepalive_timeout\s+\K[0-9]+[smhd]?' | sort -u)"
KA=""
for _k in $KA_RAW; do
  _s="$(to_seconds "$_k")"
  { [ -z "$KA" ] || [ "$_s" -lt "$KA" ]; } && KA="$_s"
done

if [ -n "$KA" ]; then
  note "lowest keepalive_timeout in the running config: ${KA}s (raw: $(printf '%s' "$KA_RAW" | paste -sd' ' -))"
  if [ "$(num "$KA")" -gt 0 ] && [ "$(num "$KA")" -lt 300 ]; then
    warn "keepalive_timeout=${KA}s is shorter than Cloudflare's 900s Proxy Idle Timeout. The edge will eventually reuse a connection this origin has already closed, which the edge reports as 520 (its idle-timeout code) and leaves NOTHING in the nginx logs. Set 'keepalive_timeout 905s;' in the http block."
  else
    ok "keepalive_timeout=${KA}s outlives Cloudflare's connection reuse window."
  fi
else
  # An absent directive is NOT a neutral finding: nginx then uses its compiled
  # default of 75s, which is exactly the broken case. Reporting this as a note
  # kept the single most likely cause out of the verdict summary entirely.
  warn "keepalive_timeout is NOT set anywhere in the running config, so nginx uses its built-in default of 75s — far below Cloudflare's 900s Proxy Idle Timeout. The edge will reuse connections this origin has already closed and report 520, leaving no log line. Set 'keepalive_timeout 905s;' in the http block."
  note "low traffic makes this MORE likely, not less: a busy connection never sits idle long enough to cross the 75s line, while a quiet dev host crosses it constantly."
fi

# Cloudflare speaks HTTP/1.1 to the origin, but nginx proxies upstream with
# HTTP/1.0 unless told otherwise, which disables upstream keepalive entirely.
PHV="$(printf '%s\n' "$NGX_NORM" | grep -cP '^proxy_http_version\s+1\.1')"
if [ "$(num "$PHV")" -eq 0 ]; then
  warn "proxy_http_version is never set to 1.1. nginx defaults to HTTP/1.0 toward the upstream, which forbids keepalive and forces a new upstream connection per request. Add 'proxy_http_version 1.1;' to the http block."
else
  note "proxy_http_version 1.1 present in ${PHV} place(s)"
fi

# Behind Cloudflare, $remote_addr is an edge node unless realip is configured,
# which makes every per-client statistic below meaningless.
REALIP=0
printf '%s\n' "$NGX_CONF" | grep -q 'set_real_ip_from' && REALIP=1

step "Listening sockets"
# Ports are taken from listen and proxy_pass in the running config; hardcoding
# one deployment's upstream port hides every other host's backend.
LISTEN_P="$(printf '%s\n' "$NGX_NORM" | grep -oP '^listen\s+(\[?[0-9a-fA-F.:]*\]?:)?\K[0-9]+' | sort -un)"
UPSTREAM_P="$(printf '%s\n' "$NGX_NORM" | grep -oP 'proxy_pass\s+https?://[^/]*:\K[0-9]+' | sort -un)"
PORT_RE="$(printf '%s\n' "$LISTEN_P" "$UPSTREAM_P" 80 443 | grep -E '^[0-9]+$' | sort -un | paste -sd'|' -)"
[ -n "$PORT_RE" ] || PORT_RE="80|443"
note "ports of interest: ${PORT_RE//|/ }"
run "ss -lntp 2>/dev/null | grep -E ':(${PORT_RE})\s' || netstat -lntp 2>/dev/null | grep -E ':(${PORT_RE})\s'"
ss -lnt 2>/dev/null | grep -qE ':(80|443)\s' || crit "Nothing is listening on :80/:443 — Cloudflare has nowhere to connect."

step "Listen queue overflows (direct cause of 522)"
# Read straight from /proc rather than netstat: net-tools is not installed by
# default on Ubuntu 18.04+, and the original code reported "0 overflows" on
# those hosts instead of admitting it could not measure.
read_queue() {
  awk '/^TcpExt:/ {
         if (!seen) { for (i = 2; i <= NF; i++) col[$i] = i; seen = 1; next }
         o = col["ListenOverflows"] ? $(col["ListenOverflows"]) : 0
         d = col["ListenDrops"]     ? $(col["ListenDrops"])     : 0
         print o, d
       }' /proc/net/netstat 2>/dev/null
}
read -r OVF_A DRP_A <<< "$(read_queue)"
if [ -z "${OVF_A:-}" ]; then
  warn "Could not read /proc/net/netstat — listen-queue overflow status unverified."
else
  # These are since-boot totals. A non-zero total alone says nothing about
  # today's outage, so sample again to see whether it is still climbing.
  sleep 3
  read -r OVF_B DRP_B <<< "$(read_queue)"
  D_OVF=$(( ${OVF_B:-0} - OVF_A )); [ "$D_OVF" -lt 0 ] && D_OVF=0
  D_DRP=$(( ${DRP_B:-0} - DRP_A )); [ "$D_DRP" -lt 0 ] && D_DRP=0
  note "ListenOverflows: ${OVF_A} since boot (+${D_OVF} in a 3s sample)"
  note "ListenDrops    : ${DRP_A} since boot (+${D_DRP} in a 3s sample)"
  if [ "$D_OVF" -gt 0 ] || [ "$D_DRP" -gt 0 ]; then
    crit "The TCP accept queue is overflowing RIGHT NOW (+${D_OVF} overflows, +${D_DRP} drops in 3 seconds). The kernel is dropping inbound connections — this is exactly what Cloudflare reports as 522."
  elif [ "$(num "$OVF_A")" -gt 0 ]; then
    warn "TCP listen queue has overflowed ${OVF_A} time(s) SINCE BOOT, but not during this sample. The counter carries no timestamp, so it may predate today's outage — run watch-52x.sh to find out when it actually moves."
  else
    ok "No TCP listen-queue overflows since boot."
  fi
fi

step "Current socket state summary (many SYN-RECV suggests SYN flood or accept starvation)"
run "ss -s 2>/dev/null | head -5"
SYNRECV="$(ss -ant 2>/dev/null | grep -c SYN-RECV)"
[ "$(num "$SYNRECV")" -gt 100 ] && crit "${SYNRECV} sockets stuck in SYN-RECV — either a SYN flood or nginx is not accepting fast enough."

# ========================================================== 6. NGINX LOGS ====
section "6. Nginx logs in the analysis window"

for _i in "${!SITE_LABEL[@]}"; do
  site="${SITE_LABEL[$_i]}"
  ACCLOG="${SITE_ACC[$_i]}"
  ERRLOG="${SITE_ERR[$_i]}"

  if [ -r "$ERRLOG" ]; then
    step "Errors: ${site} (analysis window only)"
    WINERR="$(grep -E "^${ERR_DATE} ${HOUR_RE}:" "$ERRLOG" 2>/dev/null)"
    if [ -z "$WINERR" ]; then
      printf '   (no entries in the analysis window)\n'
      note "An EMPTY error log during the outage is itself evidence: nginx never received the requests, so the failure was at the TCP layer — consistent with 522."
    else
      printf '%s\n' "$WINERR" | tail -25 | sed 's/^/   /'
      # Counted within the window. Counting the whole file, as before, credited
      # weeks-old upstream failures to today's incident.
      UP_TO="$(printf '%s\n' "$WINERR" | grep -c 'upstream timed out')"
      UP_CF="$(printf '%s\n' "$WINERR" | grep -c 'connect() failed')"
      WRK="$(printf '%s\n' "$WINERR" | grep -c 'worker_connections are not enough')"
      if [ "$(num "$UP_TO")" -gt 0 ] || [ "$(num "$UP_CF")" -gt 0 ]; then
        warn "${site}: upstream timeouts=$(num "$UP_TO") connect-failures=$(num "$UP_CF") inside the window. nginx COULD NOT reach the app — but note this yields 502/504 at the edge, not 522."
      fi
      if [ "$(num "$WRK")" -gt 0 ]; then
        crit "${site}: 'worker_connections are not enough' logged ${WRK} time(s) in the window — nginx stopped accepting connections, which the edge reports as 522. Raise worker_connections."
      fi
    fi
  fi

  if [ -r "$ACCLOG" ]; then
    step "Traffic per hour: ${site}"
    run "grep -oE '${LOG_DATE}:[0-9]{2}' '${ACCLOG}' 2>/dev/null | sort | uniq -c | tail -12"

    step "Busiest minutes in window: ${site}"
    run "grep -E '${LOG_DATE}:${HOUR_RE}:' '${ACCLOG}' 2>/dev/null | grep -oE '${LOG_DATE}:[0-9]{2}:[0-9]{2}' | sort | uniq -c | sort -rn | head -10"

    step "Top client IPs in window: ${site}"
    [ "$REALIP" -eq 1 ] || note "NOTE: set_real_ip_from is not configured, so these are Cloudflare EDGE addresses, not real visitors. Enable ngx_http_realip_module with the Cloudflare ranges before drawing any conclusion from this list."
    run "grep -E '${LOG_DATE}:${HOUR_RE}:' '${ACCLOG}' 2>/dev/null | awk '{print \$1}' | sort | uniq -c | sort -rn | head -12"

    step "Top requested paths in window: ${site}"
    run "grep -E '${LOG_DATE}:${HOUR_RE}:' '${ACCLOG}' 2>/dev/null | awk '{print \$7}' | sort | uniq -c | sort -rn | head -12"

    step "Status code distribution in window: ${site}"
    run "grep -E '${LOG_DATE}:${HOUR_RE}:' '${ACCLOG}' 2>/dev/null | awk '{print \$9}' | sort | uniq -c | sort -rn | head -10"
  fi
done

# ============================================== 6b. UPSTREAM RESPONSE ======
section "6b. Upstream response failures (520 / 524)"

# A 520 means the TCP connection SUCCEEDED and the origin then sent something
# Cloudflare could not parse. That is a completely different failure from 522
# and leaves its own fingerprint in the nginx error log, so count it separately.
step "520-class signatures in the nginx error logs (window only)"

SIG_TOTAL=0
SIG_SEEN=0
for _i in "${!SITE_LABEL[@]}"; do
  site="${SITE_LABEL[$_i]}"
  ERRLOG="${SITE_ERR[$_i]}"
  [ -r "$ERRLOG" ] || continue
  WINERR="$(grep -E "^${ERR_DATE} ${HOUR_RE}:" "$ERRLOG" 2>/dev/null)"
  [ -n "$WINERR" ] || continue
  SIG_SEEN=1

  N_PREM="$(printf '%s\n' "$WINERR" | grep -c 'prematurely closed connection')"
  N_RST="$( printf '%s\n' "$WINERR" | grep -c 'reset by peer')"
  N_HDR="$( printf '%s\n' "$WINERR" | grep -cE 'upstream sent (too big|invalid|no valid)')"
  N_NONE="$(printf '%s\n' "$WINERR" | grep -c 'no live upstreams')"
  N_SLOW="$(printf '%s\n' "$WINERR" | grep -c 'upstream timed out')"

  printf '   %-24s premature-close=%s reset=%s bad-header=%s no-upstream=%s timeout=%s\n' \
    "$site" "$(num "$N_PREM")" "$(num "$N_RST")" "$(num "$N_HDR")" \
    "$(num "$N_NONE")" "$(num "$N_SLOW")"
  SIG_TOTAL=$(( SIG_TOTAL + $(num "$N_PREM") + $(num "$N_RST") + $(num "$N_HDR") + $(num "$N_NONE") ))

  if [ "$(( $(num "$N_PREM") + $(num "$N_RST") ))" -gt 0 ]; then
    crit "${site}: the upstream closed or reset $(( $(num "$N_PREM") + $(num "$N_RST") )) connection(s) MID-RESPONSE during the window. Cloudflare reports exactly this as 520. The application died or was killed while serving a request — cross-check section 2 (OOM) and the app's own crash log below."
  fi
  if [ "$(num "$N_HDR")" -gt 0 ]; then
    crit "${site}: ${N_HDR} oversized or invalid upstream header(s). Cloudflare caps response headers at 128 KB in total; anything larger comes back as 520. Raise proxy_buffer_size, or shrink what the app emits — long Set-Cookie and JWT headers are the usual cause."
  fi
  if [ "$(num "$N_NONE")" -gt 0 ]; then
    crit "${site}: 'no live upstreams' ${N_NONE} time(s) — nginx had marked every backend as failed, so every request in that period failed at the edge."
  fi
  if [ "$(num "$N_SLOW")" -gt 0 ]; then
    warn "${site}: ${N_SLOW} upstream timeout(s). Any single request that exceeds 125s comes back as 524 rather than 502 — check proxy_read_timeout against the slowest endpoint."
  fi
done
[ "$SIG_SEEN" -eq 0 ] && note "(no error-log entries in the window for any configured site)"
[ "$SIG_SEEN" -eq 1 ] && [ "$SIG_TOTAL" -eq 0 ] && ok "No 520-class upstream signatures in the analysis window."

step "nginx worker crashes (a dying worker resets every connection it held => 520)"
WK="$(grep -h 'exited on signal' "${NGINX_LOG_DIR}"/*error.log 2>/dev/null | tail -10)"
if [ -n "$WK" ]; then
  printf '%s\n' "$WK" | sed 's/^/   /'
  WK_N="$(printf '%s\n' "$WK" | grep -c .)"
  crit "${WK_N} nginx worker process(es) exited on a signal. Signal 11 is a segfault (often a third-party module); signal 9 means the kernel OOM-killer took it. Every connection that worker was holding was reset — the edge sees those as 520."
else
  printf '   (none)\n'
  ok "No nginx worker crashes logged."
fi

step "Upstream application crashes (Node heap OOM is the classic 520 source)"
APP_LOGS="$(find /root/.pm2/logs /home/*/.pm2/logs "${HOME}/.pm2/logs" \
             -maxdepth 1 -name '*error*.log' -mmin "-$(( HOURS_BACK * 60 ))" 2>/dev/null \
             | sort -u | head -20)"
if [ -n "$APP_LOGS" ]; then
  # 'JavaScript heap out of memory' is a self-inflicted V8 limit, NOT a kernel
  # OOM kill, so it never appears in dmesg — a report that only checks dmesg
  # would call this host healthy while the app dies every few minutes.
  APP_CRASH="$(grep -hiE 'JavaScript heap out of memory|FATAL ERROR|Allocation failed|SIGSEGV|SIGKILL|unhandledRejection|uncaughtException' \
               $APP_LOGS 2>/dev/null | tail -15)"
  if [ -n "$APP_CRASH" ]; then
    printf '%s\n' "$APP_CRASH" | cut -c1-200 | sed 's/^/   /'
    HEAP_N="$(printf '%s\n' "$APP_CRASH" | grep -ci 'heap out of memory')"
    if [ "$(num "$HEAP_N")" -gt 0 ]; then
      crit "The Node process hit its V8 heap limit ${HEAP_N} time(s) and aborted. This is the single most likely source of intermittent 520 that resolves itself: pm2 restarts the app, the site works again, and the kernel log shows nothing. Raise the limit (--max-old-space-size) or fix the leak."
    else
      crit "The upstream application logged a fatal error during the window; a crash mid-response is delivered to Cloudflare as 520."
    fi
  else
    printf '   (no crash patterns in recent pm2 error logs)\n'
    ok "No upstream application crashes logged in the window."
  fi
else
  note "no recent pm2 error logs found — if the app is not managed by pm2, check its own log location by hand"
fi

step "Live upstream probe (is the backend answering right now?)"
UPS="$(printf '%s\n' "$NGX_CONF" | grep -oP 'proxy_pass\s+https?://\K[A-Za-z0-9_.:-]+' | sort -u | head -8)"
if [ -n "$UPS" ]; then
  for u in $UPS; do
    case "$u" in
      *:*)
        CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${u}/" 2>/dev/null)"
        MS="$(curl -s -o /dev/null -w '%{time_total}' --max-time 5 "http://${u}/" 2>/dev/null \
              | awk '{printf "%d", $1*1000}')"
        printf '   %-28s http=%s  %sms\n' "$u" "${CODE:-000}" "${MS:-?}"
        [ "${CODE:-000}" = "000" ] && crit "Upstream ${u} is not answering at all right now — nginx has nothing to proxy to, which surfaces as 502 or 520 at the edge."
        ;;
      *) printf '   %-28s (named upstream block, not probed)\n' "$u" ;;
    esac
  done
else
  note "no proxy_pass targets found in the running config"
fi

step "Per-vhost proxy settings (a missing proxy_read_timeout truncates streaming responses => 520)"
# nginx defaults proxy_read_timeout to 60s. A streaming SSR response that holds
# the connection open longer is cut off mid-flight, and the edge receives a
# truncated body it reports as 520. The directive is inherited, so an http-block
# setting covers every vhost — check that BEFORE blaming an individual file.
PRT_GLOBAL="$(printf '%s\n' "$NGX_NORM" | awk '
  $0 == "{" { depth++; next }
  $0 == "}" { depth--; next }
  # depth 1 == directly inside http {}, which every server block inherits
  depth == 1 && /^proxy_read_timeout / { found = 1 }
  END { print found + 0 }')"
note "proxy_read_timeout set at the http level (inherited by all vhosts): $([ "$PRT_GLOBAL" = 1 ] && echo yes || echo no)"

# nginx -T marks each included file, which is what lets a finding name the
# vhost that is actually wrong instead of reporting "somewhere in the config".
VHOSTS="$(printf '%s\n' "$NGX_CONF" | awk '
  /^# configuration file / { f = $4; sub(/:$/, "", f); next }
  f != "" { c[f] = c[f] "\n" $0 }
  END {
    for (f in c) {
      if (c[f] !~ /proxy_pass/) continue
      prt   = (c[f] ~ /proxy_read_timeout/)                ? 1 : 0
      phv   = (c[f] ~ /proxy_http_version[ \t]+1\.1/)      ? 1 : 0
      host  = (c[f] ~ /proxy_set_header[ \t]+Host/)        ? 1 : 0
      xfp   = (c[f] ~ /X-Forwarded-Proto/)                 ? 1 : 0
      slash = (c[f] ~ /proxy_pass[ \t]+https?:\/\/[^;]*\/[ \t]*;/) ? 1 : 0
      printf "%s|%d|%d|%d|%d|%d\n", f, prt, phv, host, xfp, slash
    }
  }')"

if [ -z "$VHOSTS" ]; then
  note "no vhost file with a proxy_pass found in the running config"
else
  printf '   %-34s %-12s %-8s %-6s %-8s %s\n' "vhost" "read_tmout" "http1.1" "Host" "X-Fwd-P" "trail-/"
  while IFS='|' read -r vf prt phv host xfp slash; do
    [ -n "${vf:-}" ] || continue
    yn() { [ "$1" = 1 ] && printf 'yes' || printf 'NO'; }
    printf '   %-34s %-12s %-8s %-6s %-8s %s\n' \
      "$(basename "$vf")" "$(yn "$prt")" "$(yn "$phv")" "$(yn "$host")" "$(yn "$xfp")" \
      "$([ "$slash" = 1 ] && printf 'yes' || printf 'no')"

    if [ "$prt" = 0 ] && [ "$PRT_GLOBAL" = 0 ]; then
      crit "$(basename "$vf"): no proxy_read_timeout here and none inherited from the http block, so nginx applies its 60s default. Any streaming or slow SSR response that runs past 60s is cut off mid-body, and Cloudflare reports the truncated response as 520. Add 'proxy_read_timeout 300s;'."
    fi
    if [ "$phv" = 0 ]; then
      warn "$(basename "$vf"): no 'proxy_http_version 1.1', so nginx talks HTTP/1.0 upstream and cannot keep the connection alive — it reconnects for every request. Add it, or set it once in the http block."
    fi
    [ "$host" = 0 ] && note "$(basename "$vf"): no 'proxy_set_header Host \$host' — the upstream sees the proxy_pass target as its Host, which breaks absolute redirects and host-based routing."
    [ "$xfp" = 0 ] && note "$(basename "$vf"): no X-Forwarded-Proto — an app behind TLS termination sees plain http and may emit a redirect loop."
    [ "$slash" = 1 ] && note "$(basename "$vf"): proxy_pass ends with '/', which makes nginx REWRITE the URI instead of passing it through. Drop the trailing slash unless the rewrite is intended."
  done <<< "$VHOSTS"
fi

step "Proxy buffers vs Cloudflare's header cap"
PBS="$(printf '%s\n' "$NGX_NORM" | grep -oP '^proxy_buffer_size\s+\K\S+' | head -1)"
if [ -z "${PBS:-}" ]; then
  note "proxy_buffer_size not set (nginx default is 4k or 8k). If the app ever emits a large Set-Cookie or auth header, nginx fails the response and the edge shows 520. Setting 'proxy_buffer_size 16k; proxy_buffers 4 32k;' costs nothing."
else
  note "proxy_buffer_size=${PBS}"
fi

step "Slow requests (524 = origin exceeded Cloudflare's 125s response budget)"
if printf '%s\n' "$NGX_CONF" | grep -q 'request_time'; then
  for _i in "${!SITE_LABEL[@]}"; do
    site="${SITE_LABEL[$_i]}"
    ACCLOG="${SITE_ACC[$_i]}"
    [ -r "$ACCLOG" ] || continue
    SLOW="$(grep -E "${LOG_DATE}:${HOUR_RE}:" "$ACCLOG" 2>/dev/null \
            | grep -oE 'rt=[0-9]+\.[0-9]+' | cut -d= -f2 | sort -rn | head -5 | paste -sd' ' -)"
    [ -n "$SLOW" ] && printf '   %-24s slowest rt: %s\n' "$site" "$SLOW"
  done
  note "Any value above 100 would have been returned to the visitor as 524."
else
  note "log_format has no \$request_time, so 524 cannot be confirmed from the access log."
  note "Add it once and the next incident is self-explanatory:"
  note "  log_format t '\$remote_addr \$status rt=\$request_time uct=\$upstream_connect_time urt=\$upstream_response_time \"\$request\"';"
fi

step "Origin certificate validity (an expired cert is 526, not 520)"
CERTS="$(printf '%s\n' "$NGX_NORM" | grep -oP '^ssl_certificate\s+\K\S+' | sort -u | head -5)"
if [ -n "$CERTS" ] && have openssl; then
  for c in $CERTS; do
    [ -r "$c" ] || continue
    END="$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)"
    [ -n "$END" ] || continue
    END_EPOCH="$(date -d "$END" +%s 2>/dev/null || echo 0)"
    NOW_EPOCH="$(date +%s)"
    DAYS=$(( ( $(num "$END_EPOCH") - NOW_EPOCH ) / 86400 ))
    printf '   %-46s expires in %s day(s)\n' "$(basename "$c")" "$DAYS"
    if [ "$(num "$END_EPOCH")" -gt 0 ] && [ "$DAYS" -lt 0 ]; then
      crit "Origin certificate $(basename "$c") EXPIRED. With Cloudflare SSL mode Full (strict) every request returns 526."
    elif [ "$(num "$END_EPOCH")" -gt 0 ] && [ "$DAYS" -lt 14 ]; then
      warn "Origin certificate $(basename "$c") expires in ${DAYS} day(s)."
    fi
  done
else
  note "no ssl_certificate directives found, or openssl unavailable"
fi

# ====================================================== 7. BUILD ACTIVITY ====
section "7. Build / deploy activity"

# The application roots are whatever pm2 is actually running and whatever
# nginx serves, discovered per host — not one machine's home directory.
APP_ROOTS=""
if have pm2 && have python3; then
  APP_ROOTS="$(pm2 jlist 2>/dev/null | python3 -c '
import sys, json
try:
    apps = json.load(sys.stdin)
except Exception:
    sys.exit(0)
seen = set()
for a in apps:
    e = a.get("pm2_env", {}) or {}
    for key in ("pm_cwd", "cwd"):
        v = e.get(key)
        if v and v not in seen:
            seen.add(v)
            print(v)
' 2>/dev/null)"
fi
# nginx root directives cover statically served apps that pm2 knows nothing of.
NGX_ROOTS="$(printf '%s\n' "$NGX_NORM" | grep -oP '^root\s+\K.+' | tr -d '"' | sort -u)"
APP_ROOTS="$(printf '%s\n' "$APP_ROOTS" "$NGX_ROOTS" | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u)"

step "Application roots in use"
if [ -n "$APP_ROOTS" ]; then
  printf '%s\n' "$APP_ROOTS" | sed 's/^/   /'
else
  note "none discovered from pm2 or nginx — the two build checks below will be skipped"
fi

step "Build directory timestamps (a build inside the outage window is the prime suspect)"
FOUND_BUILD=0
if [ -n "$APP_ROOTS" ]; then
  while IFS= read -r base; do
    [ -d "$base" ] || continue
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      FOUND_BUILD=1
      printf '   %-52s %s\n' "${d}" \
        "$(stat -c '%y' "$d" 2>/dev/null | cut -d. -f1 || stat -f '%Sm' "$d" 2>/dev/null)"
    done < <(find "$base" -maxdepth 3 \( -name '.next' -o -name 'dist' -o -name 'build' -o -name '.nuxt' \) -type d 2>/dev/null | head -20)
  done <<< "$APP_ROOTS"
fi
[ "$FOUND_BUILD" -eq 0 ] && printf '   (no build directories found under the discovered roots)\n'
note "If a timestamp lands inside the outage window, the build caused the resource spike."

step "Recently modified directories under the app roots (last 6 hours)"
if [ -n "$APP_ROOTS" ]; then
  while IFS= read -r base; do
    [ -d "$base" ] || continue
    find "$base" -maxdepth 2 -newermt '6 hours ago' -type d 2>/dev/null | head -10 | sed 's/^/   /'
  done <<< "$APP_ROOTS"
else
  printf '   (no application roots discovered)\n'
fi

step "pm2 process table"
if have pm2; then
  run "pm2 list"
  step "pm2 restart detail per process"
  # 'unstable restarts' distinguishes crash loops from deploy-triggered restarts.
  run "pm2 jlist 2>/dev/null | tr ',' '\n' | grep -E 'name|restart_time|unstable_restarts|status' | head -60"
  note "unstable_restarts near 0 means restarts were DEPLOYS, not crash loops."

  step "pm2 execution mode (a single fork instance means every deploy has a hard gap)"
  # exec_mode and instances decide whether a deploy is zero-downtime. A single
  # fork process is stopped before the replacement starts, so nginx has no
  # upstream at all for those seconds — dumping restart_time alone never
  # surfaced this, which is why deploy-window 52x looked unexplained.
  PM2_TABLE=""
  if have python3; then
    PM2_TABLE="$(pm2 jlist 2>/dev/null | python3 -c '
import sys, json
try:
    apps = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in apps:
    e = a.get("pm2_env", {}) or {}
    print("\t".join(str(x) for x in [
        a.get("name", "?"),
        e.get("exec_mode", "?"),
        e.get("instances", 1),
        e.get("restart_time", 0),
        e.get("unstable_restarts", 0),
        e.get("status", "?"),
    ]))
' 2>/dev/null)"
  fi

  if [ -n "$PM2_TABLE" ]; then
    printf '   %-24s %-12s %-10s %-9s %-9s %s\n' NAME MODE INSTANCES RESTARTS UNSTABLE STATUS
    while IFS="$(printf '\t')" read -r pname pmode pinst prst punst pstat; do
      [ -n "${pname:-}" ] || continue
      printf '   %-24s %-12s %-10s %-9s %-9s %s\n' \
        "$pname" "$pmode" "$pinst" "$prst" "$punst" "$pstat"

      case "$pmode" in
        *fork*)
          if [ "$(num "$pinst")" -le 1 ]; then
            warn "pm2 app '${pname}' runs in fork mode with ${pinst} instance. 'pm2 restart' stops that single process before the replacement is listening, so nginx has NO upstream for the whole restart — every request in that window is 502/522 at the edge. Switch to cluster mode with 2+ instances and deploy with 'pm2 reload' instead."
          fi
          ;;
      esac
      if [ "$(num "$punst")" -gt 0 ]; then
        crit "pm2 app '${pname}' has ${punst} unstable restart(s): it is crash-looping, not being deployed. A crash mid-response reaches Cloudflare as 520."
      fi
      if [ "$pstat" != "online" ]; then
        crit "pm2 app '${pname}' status is '${pstat}' — nginx has nothing to proxy to."
      fi
    done <<< "$PM2_TABLE"
  else
    note "could not parse 'pm2 jlist' (python3 missing, or pm2 returned nothing) — read the raw table above by hand: exec_mode should be cluster_mode with instances >= 2"
  fi
else
  note "pm2 not found in PATH"
fi

# ========================================================== 8. CONNTRACK ====
section "8. Connection tracking and kernel limits"

step "nf_conntrack table (a full table silently drops new connections => 522)"
CT_COUNT="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
CT_MAX="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
if [ -n "${CT_COUNT:-}" ] && [ -n "${CT_MAX:-}" ] && [ "$(num "$CT_MAX")" -gt 0 ]; then
  CT_PCT=$(( $(num "$CT_COUNT") * 100 / $(num "$CT_MAX") ))
  note "conntrack: ${CT_COUNT} / ${CT_MAX} (${CT_PCT}%)"
  [ "$CT_PCT" -gt 80 ] && crit "conntrack table ${CT_PCT}% full — new connections are being dropped, a textbook 522 cause."
  [ "$CT_PCT" -gt 60 ] && [ "$CT_PCT" -le 80 ] && warn "conntrack table ${CT_PCT}% full."
else
  note "conntrack not loaded (fine if no stateful firewall is in use)"
fi
run "dmesg -T 2>/dev/null | grep -i 'conntrack.*table full' | tail -5"

step "Key TCP tunables"
run "sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range net.core.netdev_max_backlog 2>/dev/null"
SOMAX="$(sysctl -n net.core.somaxconn 2>/dev/null)"
if [ -n "${SOMAX:-}" ] && [ "$(num "$SOMAX")" -gt 0 ] && [ "$(num "$SOMAX")" -lt 1024 ]; then
  warn "net.core.somaxconn=${SOMAX} is low for a busy reverse proxy; raise to 4096."
fi

step "Firewall state"
run "ufw status 2>/dev/null | head -15"
run "iptables -L INPUT -n --line-numbers 2>/dev/null | head -20"

# ============================================================ 9. SECURITY ====
section "9. Attack indicators"

step "Origin IP exposure — requests NOT coming from Cloudflare ranges"
# Cached per-uid so another user on the box cannot pre-seed the list we trust.
CFIPS="/tmp/.cf-ips-v4-$(id -u)"
CFIPS6="/tmp/.cf-ips-v6-$(id -u)"
for _pair in "v4:$CFIPS" "v6:$CFIPS6"; do
  _ver="${_pair%%:*}"; _f="${_pair#*:}"
  if [ ! -s "$_f" ] || [ -n "$(find "$_f" -mmin +1440 2>/dev/null)" ]; then
    curl -fsS --max-time 15 "https://www.cloudflare.com/ips-${_ver}" -o "$_f" 2>/dev/null
  fi
done

if [ "$REALIP" -eq 1 ]; then
  note "SKIPPED: set_real_ip_from is configured, so \$remote_addr already holds the real visitor address and cannot be compared against Cloudflare ranges."
  note "To detect direct-to-origin hits with realip enabled, log \$realip_remote_addr as a separate field, or check the cloud security group instead."
elif [ -s "$CFIPS" ]; then
  CIDRS="$(tr '\n' ' ' < "$CFIPS")"
  # Cloudflare's v6 blocks are /29../32, so the first two hextets are a safe
  # (marginally generous) prefix test.
  V6PFX="$(cut -d/ -f1 "$CFIPS6" 2>/dev/null | awk -F: 'NF>1{print tolower($1":"$2)}' | sort -u | paste -sd'|' -)"
  [ -z "$V6PFX" ] && V6PFX='2400:cb00|2606:4700|2803:f800|2405:b500|2405:8100|2a06:98c0|2c0f:f248'

  for _i in "${!SITE_LABEL[@]}"; do
    site="${SITE_LABEL[$_i]}"
    ACCLOG="${SITE_ACC[$_i]}"
    [ -r "$ACCLOG" ] || continue
    # Real CIDR containment. The previous /16 decimal-prefix substring test was
    # wrong in both directions: it flagged 104.17.x.x (inside Cloudflare's
    # 104.16.0.0/13) as a leak, and accepted 204.104.16.5 as Cloudflare — so it
    # reported an "origin IP leaked" warning on perfectly healthy hosts.
    NONCF="$(grep -E "${LOG_DATE}:${HOUR_RE}:" "$ACCLOG" 2>/dev/null \
             | awk '{print $1}' | sort -u \
             | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|::1$|fe80:|unix:|-$)' \
             | grep -viE "^(${V6PFX})" \
             | awk -v cidrs="$CIDRS" '
                 function ip2int(ip,   a) {
                   if (split(ip, a, ".") != 4) return -1
                   return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4]
                 }
                 BEGIN {
                   n = split(cidrs, c, " ")
                   for (i = 1; i <= n; i++) {
                     if (c[i] !~ /\//) { lo[i] = -1; continue }
                     split(c[i], p, "/")
                     lo[i] = ip2int(p[1]); sz[i] = 2 ^ (32 - p[2])
                   }
                 }
                 {
                   v = ip2int($0)
                   if (v < 0) { print; next }   # IPv6: already prefix-filtered above
                   for (i = 1; i <= n; i++)
                     if (lo[i] >= 0 && v >= lo[i] && v < lo[i] + sz[i]) next
                   print
                 }')"
    NONCF_N="$(printf '%s' "$NONCF" | grep -c . || true)"
    if [ "$(num "$NONCF_N")" -gt 0 ]; then
      printf '   %s%s: %s non-Cloudflare source IP(s) in the window:%s\n' "$C_YEL" "$site" "$NONCF_N" "$C_OFF"
      printf '%s\n' "$NONCF" | head -25 | sed 's/^/     /'
      warn "${site}: ${NONCF_N} non-Cloudflare source IP(s) reached this origin during the window. If the domain is proxied (orange cloud), your ORIGIN IP HAS LEAKED — restrict the security group to https://www.cloudflare.com/ips/ and port 80/443 only."
    else
      printf '   %s: all sources in the window are Cloudflare ranges.\n' "$site"
      ok "${site}: no direct-to-origin traffic during the window."
    fi
  done
else
  note "could not fetch the Cloudflare IP list (no egress?) — skipping this check"
fi

step "Crawler and scanner user agents in window"
for _i in "${!SITE_LABEL[@]}"; do
  site="${SITE_LABEL[$_i]}"
  ACCLOG="${SITE_ACC[$_i]}"
  [ -r "$ACCLOG" ] || continue
  printf '   %s:\n' "$site"
  grep -E "${LOG_DATE}:${HOUR_RE}:" "$ACCLOG" 2>/dev/null \
    | grep -oiE 'GPTBot|ClaudeBot|OAI-SearchBot|PerplexityBot|Bytespider|SemrushBot|AhrefsBot|MJ12bot|DotBot|DataForSeoBot|Amazonbot|python-requests|curl/|scrapy|Go-http-client|zgrab|masscan' \
    | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /' || true
done
note "Heavy crawler volume is not an attack, but it exhausts the same resources. Rate-limit at Cloudflare if the counts are large."

step "Current connections grouped by peer IP"
run "ss -ant 2>/dev/null | awk 'NR>1{split(\$5,a,\":\"); if (a[1] != \"\") print a[1]}' | sort | uniq -c | sort -rn | head -15"

step "SSH brute-force attempts"
run "grep -h 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{print \$(NF-3)}' | sort | uniq -c | sort -rn | head -10"
# awk, not bc: bc is not installed by default and would silently yield 0.
SSHFAIL="$(grep -hc 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{t += $1} END {print t + 0}')"
[ "$(num "$SSHFAIL")" -gt 1000 ] && warn "${SSHFAIL} failed SSH password attempts logged. Not the 522 cause, but disable password auth and install fail2ban."

# ============================================================= 10. DOCKER ====
section "10. Containers"

if have docker && docker ps >/dev/null 2>&1; then
  step "Container resource usage"
  run "docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}'"
  step "Container status and restart counts"
  run "docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'"
  step "Containers with configured memory limits"
  run "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} mem_limit={{.HostConfig.Memory}}' 2>/dev/null | head -20"
  note "mem_limit=0 means unlimited: that container can consume the whole host."
else
  note "docker unavailable or not permitted for this user"
fi

# ============================================================= 11. VERDICT ====
section "11. Verdict"

printf '\n'
if [ ${#FINDINGS_CRIT[@]} -gt 0 ]; then
  printf '%s%sCRITICAL (%d)%s\n' "$C_BLD" "$C_RED" "${#FINDINGS_CRIT[@]}" "$C_OFF"
  for f in "${FINDINGS_CRIT[@]}"; do printf '%s  [!] %s%s\n' "$C_RED" "$f" "$C_OFF"; done
  printf '\n'
fi
if [ ${#FINDINGS_WARN[@]} -gt 0 ]; then
  printf '%s%sWARNINGS (%d)%s\n' "$C_BLD" "$C_YEL" "${#FINDINGS_WARN[@]}" "$C_OFF"
  for f in "${FINDINGS_WARN[@]}"; do printf '%s  [~] %s%s\n' "$C_YEL" "$f" "$C_OFF"; done
  printf '\n'
fi
if [ ${#FINDINGS_OK[@]} -gt 0 ]; then
  printf '%s%sHEALTHY (%d)%s\n' "$C_BLD" "$C_GRN" "${#FINDINGS_OK[@]}" "$C_OFF"
  for f in "${FINDINGS_OK[@]}"; do printf '%s  [+] %s%s\n' "$C_GRN" "$f" "$C_OFF"; done
  printf '\n'
fi
if [ ${#FINDINGS_CRIT[@]} -eq 0 ] && [ ${#FINDINGS_WARN[@]} -eq 0 ]; then
  printf '%s  Nothing anomalous detected in this snapshot.%s\n' "$C_GRN" "$C_OFF"
  printf '  A 522 is transient by nature: if the incident has passed, the evidence\n'
  printf '  may be gone. Run the companion watcher so the next one leaves a trace.\n\n'
fi

cat <<EOF
${C_BLD}How to read this report${C_OFF}

  Start from the code the edge actually returned — they are not the same bug.

  ${C_BLD}520${C_OFF} — the edge connected; the origin answered something unparseable.
    1. Upstream app crashed or was OOM-killed mid-response -> section 6b / 2
       (Node's "JavaScript heap out of memory" is a self-inflicted V8 limit
        and never reaches dmesg, so section 2 can look perfectly clean while
        the app dies every few minutes and pm2 silently restarts it. That is
        the textbook "520, then fine again a minute later".)
    2. nginx worker exited on a signal                     -> section 6b
    3. Response headers above Cloudflare's 128 KB cap      -> section 6b
    4. Upstream reset the connection mid-response          -> section 6b
    5. keepalive_timeout below Cloudflare's 900s idle window -> section 5
       (the classic INTERMITTENT failure on a host that looks healthy: the
        edge reuses a connection this origin already closed. Cloudflare's
        Proxy Idle Timeout is 900s and returns 520 when it fires. It leaves
        no log line anywhere, so a clean report plus a short keepalive_timeout
        IS the finding.)

  ${C_BLD}522${C_OFF} — the edge never completed a TCP handshake.
    1. Listen-queue overflow or conntrack full             -> section 8 / 5
    2. Memory collapse or IO storm (often a build)         -> section 4 / 7
    3. nginx down or config not loaded                     -> section 5
    4. Keepalives refused outright by the origin           -> section 5
       (Cloudflare lists "keepalives are disabled at the origin" as a 522
        cause. A keepalive_timeout that is merely SHORT returns 520 instead
        — see the 520 list above.)
    5. Origin IP leaked and being hit directly             -> section 9
    6. Security group not tracking Cloudflare's current ranges
       (invisible from this host — verify it in the cloud console)

  ${C_BLD}521${C_OFF} — connection refused: nginx down, or a firewall REJECT  -> section 5
  ${C_BLD}524${C_OFF} — connected, but no complete response within 125s       -> section 6b
  ${C_BLD}526${C_OFF} — origin certificate expired or untrusted               -> section 6b

  ${C_BLD}520 and 522 alternating${C_OFF} on one host is a finding in itself: the upstream
  is restarting under memory pressure. While it is down the edge cannot connect
  (522); while it is dying mid-request the edge gets a truncated response (520);
  once pm2 restarts it, everything looks fine again.

  An EMPTY nginx error log during a 522 is a positive finding, not a gap: it
  proves the requests never reached nginx. For 520 the opposite holds — the
  error log is where the evidence lives, so an empty one rules 520 out.

  Nothing conclusive? Run the watcher with an edge probe so that the next
  incident is timestamped:
    sudo ./watch-52x.sh -e https://<your-domain>/


${C_BLD}Report saved to${C_OFF} ${OUTFILE}
EOF

# Close the pipe and let tee flush, or the report file loses its last lines.
exec 1>&- 2>&-
wait "$TEE_PID" 2>/dev/null
exit 0