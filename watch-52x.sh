#!/usr/bin/env bash
#
# watch-52x.sh — Always-on recorder for intermittent Cloudflare 52x incidents.
#
# A 52x is transient: by the time you SSH in, the evidence is gone. This samples
# the metrics that actually explain 520/521/522/524 (memory, IO wait, steal,
# listen-queue overflows, conntrack, socket states) plus three HTTP probes, and
# appends one CSV row per interval.
#
# The three probes are what make a row conclusive, because 520 and 522 are
# different failures and the probes separate them without guesswork:
#
#   edge (-e)      what Cloudflare returns   -> WHEN the incident happened
#   local          nginx on 127.0.0.1        -> was nginx itself alive
#   upstream (-p)  the app port directly     -> was the backend alive
#
#   edge=522, local=200            the host served fine but the edge could not
#                                  reach it: network, firewall, or keepalive
#   edge=520, upstream=000         the backend was down; nginx had nothing to
#                                  proxy to. This is the common cause of a 520
#                                  that fixes itself once pm2 restarts the app.
#   edge=520, upstream=200         the backend answered but produced something
#                                  unparseable — check header size and resets
#   edge=52x, iowait/steal spike   resource stall, see the same row
#
# Usage:
#   sudo ./watch-52x.sh                                  # foreground, 30s
#   sudo ./watch-52x.sh -i 15                            # 15s interval
#   sudo ./watch-52x.sh -n example.com                   # local probe Host header
#   sudo ./watch-52x.sh -p 3000                          # probe the app port too
#   sudo ./watch-52x.sh -e https://example.com/          # probe via the edge
#   sudo nohup ./watch-52x.sh -e https://example.com/ >/dev/null 2>&1 &
#
# The Host header and the upstream port are read from the running nginx config
# when -n / -p are omitted, so the common case needs neither flag.
#   sudo ./watch-52x.sh -k                               # stop background instance
#
# Analyse afterwards:
#   column -s, -t /var/log/52x-watch.csv | less -S
#   awk -F, 'NR==1 || $21>=500'       /var/log/52x-watch.csv  # every edge failure
#   awk -F, 'NR==1 || $19==0'         /var/log/52x-watch.csv  # upstream was down
#   awk -F, 'NR==1 || $11>0 || $12>0' /var/log/52x-watch.csv  # queue overflow
#   awk -F, 'NR==1 || $6>50 || $7>20' /var/log/52x-watch.csv  # iowait / steal

set -uo pipefail

# curl -w and awk both honour LC_NUMERIC; a comma decimal separator would
# corrupt the CSV it is written into.
export LC_ALL=C

INTERVAL=30
CSV=/var/log/52x-watch.csv
PIDFILE=/var/run/52x-watch.pid
KILL_MODE=0
LOCAL_URL="http://127.0.0.1/"
LOCAL_HOST=""
EDGE_URL=""
UP_PORT=""
MAX_MB=200

while getopts "i:f:n:u:e:p:m:kh" opt; do
  case "$opt" in
    i) INTERVAL="$OPTARG" ;;
    f) CSV="$OPTARG" ;;
    n) LOCAL_HOST="$OPTARG" ;;
    u) LOCAL_URL="$OPTARG" ;;
    e) EDGE_URL="$OPTARG" ;;
    p) UP_PORT="$OPTARG" ;;
    m) MAX_MB="$OPTARG" ;;
    k) KILL_MODE=1 ;;
    h) sed -n '3,42p' "$0"; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 1 ;;
  esac
done

# ------------------------------------------------------------------ stop mode --
if [ "$KILL_MODE" -eq 1 ]; then
  stopped=0
  if [ -r "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    kill "$(cat "$PIDFILE")" && rm -f "$PIDFILE" && stopped=1
    echo "watcher stopped (pidfile)"
  fi
  if [ "$stopped" -eq 0 ]; then
    # Exclude this process and its sudo parent, which also carry the script name
    # on their command line and would otherwise be killed along with the watcher.
    victims="$(pgrep -f '[w]atch-52(2|x)\.sh' 2>/dev/null \
               | grep -vxF -e "$$" -e "$PPID" | paste -sd' ' -)"
    if [ -n "$victims" ]; then
      # shellcheck disable=SC2086
      kill $victims 2>/dev/null && echo "watcher stopped (by name: $victims)"
    else
      echo "no watcher running"
    fi
  fi
  exit 0
fi

for _v in "i:$INTERVAL" "m:$MAX_MB" ${UP_PORT:+"p:$UP_PORT"}; do
  if ! [[ "${_v#*:}" =~ ^[0-9]+$ ]]; then
    echo "-${_v%%:*} must be numeric (got: ${_v#*:})" >&2; exit 1
  fi
done
[ "$INTERVAL" -ge 1 ] || { echo "-i must be at least 1 second" >&2; exit 1; }
if [ -n "$UP_PORT" ] && { [ "$UP_PORT" -lt 1 ] || [ "$UP_PORT" -gt 65535 ]; }; then
  echo "-p must be a valid port (1-65535)" >&2; exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root so ss/conntrack/logs are readable: sudo $0" >&2
  exit 1
fi

# Refuse to start a second instance: two writers on one CSV interleave rows and
# each keeps its own counter baseline, which corrupts every delta column.
if [ -r "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
  echo "watcher already running as PID $(cat "$PIDFILE") — stop it with: $0 -k" >&2
  exit 1
fi

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v ss   >/dev/null 2>&1 || { echo "ss (iproute2) is required" >&2; exit 1; }

# Read the upstream port and a Host header off the running config rather than
# making the operator supply values the machine already knows. Explicit flags
# always win.
if [ -z "$UP_PORT" ] || [ -z "$LOCAL_HOST" ]; then
  NGX_DUMP="$(nginx -T 2>/dev/null)"
  if [ -n "$NGX_DUMP" ]; then
    if [ -z "$UP_PORT" ]; then
      UP_PORT="$(printf '%s\n' "$NGX_DUMP" \
        | grep -oP 'proxy_pass\s+https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]):\K[0-9]+' \
        | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')"
      [ -n "$UP_PORT" ] && echo "discovered upstream port: ${UP_PORT}"
    fi
    if [ -z "$LOCAL_HOST" ]; then
      LOCAL_HOST="$(printf '%s\n' "$NGX_DUMP" \
        | grep -oP '(?:^|;)\s*server_name\s+\K[^;]+' \
        | tr ' ' '\n' | grep -vE '^(_|\*|localhost)$' | grep -E '\.' | head -1)"
      [ -n "$LOCAL_HOST" ] && echo "discovered Host header: ${LOCAL_HOST}"
    fi
    if [ -z "$EDGE_URL" ]; then
      CANDIDATES="$(printf '%s\n' "$NGX_DUMP" | grep -oP '(?:^|;)\s*server_name\s+\K[^;]+' \
        | tr ' ' '\n' | grep -vE '^(_|\*|localhost)$' | grep -E '\.' | sort -u | head -5 | paste -sd' ' -)"
      [ -n "$CANDIDATES" ] && echo "no -e edge probe set; candidates on this host: ${CANDIDATES}"
    fi
  fi
fi

echo $$ > "$PIDFILE" 2>/dev/null || true
trap 'rm -f "$PIDFILE"; exit 0' INT TERM

HEADER="ts,load1,mem_avail_mb,swap_used_mb,dirty_mb,iowait_pct,steal_pct,estab,syn_recv,time_wait,listen_ovf,listen_drop,conntrack,ct_pct,nginx_up,nginx_workers,local_code,local_ms,up_code,up_ms,edge_code,edge_ms"

# A schema change would silently misalign every awk filter written against the
# old columns, so retire the old file instead of appending to it.
if [ -s "$CSV" ] && [ "$(head -1 "$CSV")" != "$HEADER" ]; then
  mv "$CSV" "${CSV}.$(date +%Y%m%d-%H%M%S).old"
  echo "column layout changed; previous CSV archived as ${CSV}.*.old" >&2
fi
[ -s "$CSV" ] || echo "$HEADER" > "$CSV"

# ------------------------------------------------------------------- samplers --
# Read the listen-queue counters straight from /proc: no net-tools, no bc. The
# old netstat|bc pipeline silently produced 0 on hosts lacking either package.
read_queue() {
  awk '/^TcpExt:/ {
         if (!seen) { for (i = 2; i <= NF; i++) col[$i] = i; seen = 1; next }
         o = col["ListenOverflows"] ? $(col["ListenOverflows"]) : 0
         d = col["ListenDrops"]     ? $(col["ListenDrops"])     : 0
         print o, d
       }' /proc/net/netstat 2>/dev/null
}

# total excludes guest time but includes steal, so the percentages below sum
# correctly on oversubscribed cloud instances.
read_cpu() {
  awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $6, $9}' /proc/stat
}

# curl always prints time_total, even when the connection is refused, so the
# status code is the only reliable way to tell "fast" from "failed".
probe() {
  local url="$1" host="$2" out
  if [ -n "$host" ]; then
    out=$(curl -s -o /dev/null -H "Host: ${host}" -w '%{http_code} %{time_total}' \
          --max-time 5 "$url" 2>/dev/null)
  else
    out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' \
          --max-time 5 "$url" 2>/dev/null)
  fi
  [ -z "$out" ] && out="000 -0.001"
  printf '%s' "$out" | awk '{printf "%d,%d", $1, $2*1000}'
}

CT_MAX="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
[[ "$CT_MAX" =~ ^[0-9]+$ ]] || CT_MAX=0

read -r prev_ovf prev_drop <<< "$(read_queue)"
prev_ovf=${prev_ovf:-0}; prev_drop=${prev_drop:-0}
read -r prev_tot prev_iow prev_stl <<< "$(read_cpu)"

if [ "$prev_ovf" = "0" ] && [ ! -r /proc/net/netstat ]; then
  echo "WARNING: /proc/net/netstat unreadable — listen_ovf/listen_drop will stay 0" >&2
fi

# ----------------------------------------------------------------- main loop --
while :; do
  loop_start=$SECONDS
  ts=$(date '+%F %T')

  load1=$(cut -d' ' -f1 /proc/loadavg)
  mem_avail=$(( $(awk '/MemAvailable/{print $2}' /proc/meminfo) / 1024 ))
  swap_total=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
  swap_free=$(awk '/SwapFree/{print $2}' /proc/meminfo)
  swap_used=$(( (swap_total - swap_free) / 1024 ))
  dirty=$(( $(awk '/^Dirty:/{print $2}' /proc/meminfo) / 1024 ))

  read -r cur_tot cur_iow cur_stl <<< "$(read_cpu)"
  tot_d=$(( cur_tot - prev_tot ))
  iowait=0; steal=0
  if [ "$tot_d" -gt 0 ]; then
    iowait=$(( (cur_iow - prev_iow) * 100 / tot_d ))
    steal=$((  (cur_stl - prev_stl) * 100 / tot_d ))
  fi
  prev_tot=$cur_tot; prev_iow=$cur_iow; prev_stl=$cur_stl

  # One ss invocation for all three socket states instead of three.
  read -r estab synrecv timewait <<< "$(ss -ant 2>/dev/null \
    | awk 'NR>1{s[$1]++} END{printf "%d %d %d", s["ESTAB"], s["SYN-RECV"], s["TIME-WAIT"]}')"

  read -r cur_ovf cur_drop <<< "$(read_queue)"
  cur_ovf=${cur_ovf:-0}; cur_drop=${cur_drop:-0}
  ovf_d=$(( cur_ovf - prev_ovf ));   [ "$ovf_d"  -lt 0 ] && ovf_d=0
  drop_d=$(( cur_drop - prev_drop )); [ "$drop_d" -lt 0 ] && drop_d=0
  prev_ovf=$cur_ovf; prev_drop=$cur_drop

  ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  ct_pct=0
  [ "$CT_MAX" -gt 0 ] && ct_pct=$(( ct * 100 / CT_MAX ))

  nginx_up=$(systemctl is-active nginx >/dev/null 2>&1 && echo 1 || echo 0)
  # A worker count that drops between rows means a worker died, which resets
  # every connection it was holding — the edge reports those as 520.
  nginx_workers=$(pgrep -c -f 'nginx: worker' 2>/dev/null || echo 0)

  # Local probe pins a slow origin to this host; the edge probe records what
  # Cloudflare actually returned, which is the only way to timestamp a real 522.
  local_probe=$(probe "$LOCAL_URL" "$LOCAL_HOST")
  # Probing the app port directly is what separates "nginx broke" from "the
  # backend died": with only a local probe, both look identical.
  if [ -n "$UP_PORT" ]; then
    up_probe=$(probe "http://127.0.0.1:${UP_PORT}/" "$LOCAL_HOST")
  else
    up_probe="0,-1"
  fi
  if [ -n "$EDGE_URL" ]; then
    edge_probe=$(probe "$EDGE_URL" "")
  else
    edge_probe="0,-1"
  fi

  echo "${ts},${load1},${mem_avail},${swap_used},${dirty},${iowait},${steal},${estab},${synrecv},${timewait},${ovf_d},${drop_d},${ct},${ct_pct},${nginx_up},${nginx_workers},${local_probe},${up_probe},${edge_probe}" >> "$CSV"

  # Unbounded growth would eventually fill the same disk whose exhaustion this
  # script is meant to detect.
  if [ "$MAX_MB" -gt 0 ] && [ "$(( $(stat -c %s "$CSV" 2>/dev/null || echo 0) / 1048576 ))" -ge "$MAX_MB" ]; then
    mv "$CSV" "${CSV}.1"
    echo "$HEADER" > "$CSV"
  fi

  # Subtract sampling time so rows stay on a regular grid even when a probe
  # burns its full 5s timeout.
  elapsed=$(( SECONDS - loop_start ))
  nap=$(( INTERVAL - elapsed ))
  [ "$nap" -lt 1 ] && nap=1
  sleep "$nap"
done
