#!/usr/bin/env bash
#
# probe-52x.sh — External watcher for Cloudflare 52x, run from your OWN machine.
#
# The server-side watcher has a structural blind spot: it is both the observer
# and the thing being observed. When the host stalls, its own probe stalls with
# it; when the host goes down, the recording stops at exactly the moment that
# matters. And because Cloudflare is anycast, a probe sent FROM the origin hits
# whichever PoP is nearest the origin — not the PoP your visitors hit, which is
# where 522 usually lives.
#
# This script fills those gaps from outside:
#
#   * keeps recording while the origin is unreachable
#   * records the CF-RAY colo, so "only some regions fail" becomes visible
#   * splits DNS / TCP / TLS / TTFB, so a slow handshake is distinguishable
#     from a slow application
#   * with -o, probes Cloudflare AND the origin directly in the same second,
#     which settles the only question that matters during an incident:
#
#         edge fails + origin OK    -> the fault is between Cloudflare and the
#                                      origin (keepalive, firewall, PoP route)
#         edge fails + origin fails -> the origin itself is down
#         both OK                   -> it already recovered; check the CSV for
#                                      when, then correlate on the server
#
# Runs on macOS and Linux. No root required.
#
# A local proxy (VPN, Clash, corporate proxy) invalidates every measurement
# here: the timings become proxy->Cloudflare and edge_ip becomes the proxy.
# The script detects one, warns, and marks those rows via_proxy=1. Use -P to
# bypass the proxy instead — but only if the site is reachable without it.
#
# Usage:
#   ./probe-52x.sh https://example.com/                    # loop, 60s
#   ./probe-52x.sh -1 https://example.com/                 # single check, verbose
#   ./probe-52x.sh -P https://example.com/                 # ignore the local proxy
#   ./probe-52x.sh -i 30 https://example.com/ https://staging.example.com/
#   ./probe-52x.sh -o 203.0.113.10 -k https://example.com/ # compare against origin
#   nohup ./probe-52x.sh https://example.com/ >/dev/null 2>&1 &
#
# Analyse afterwards:
#   column -s, -t ~/52x-probe.csv | less -S
#   awk -F, 'NR==1 || $3>=500' ~/52x-probe.csv           # every failure
#   awk -F, '$3>=500 {print $4}' ~/52x-probe.csv | sort | uniq -c   # by colo
#   awk -F, 'NR==1 || ($3>=500 && $15<500)' ~/52x-probe.csv  # edge bad, origin OK

set -uo pipefail
export LC_ALL=C

INTERVAL=60
CSV="${HOME}/52x-probe.csv"
SNAPDIR="${HOME}/52x-snapshots"
ORIGIN_IP=""
ONCE=0
INSECURE=""
NOPROXY=""
FAILS=0

while getopts "i:f:d:o:kP1h" opt; do
  case "$opt" in
    i) INTERVAL="$OPTARG" ;;
    f) CSV="$OPTARG" ;;
    d) SNAPDIR="$OPTARG" ;;
    o) ORIGIN_IP="$OPTARG" ;;
    k) INSECURE="-k" ;;
    P) NOPROXY="--noproxy *" ;;
    1) ONCE=1 ;;
    h) sed -n '3,46p' "$0"; exit 0 ;;
    *) echo "Unknown option. Use -h for help." >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

URLS=("$@")
if [ ${#URLS[@]} -eq 0 ]; then
  echo "No URL given. Example: $0 https://example.com/" >&2
  exit 1
fi
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 5 ]; then
  echo "-i must be an integer of at least 5 seconds" >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

C_RED=$'\033[0;31m'; C_YEL=$'\033[0;33m'; C_GRN=$'\033[0;32m'; C_OFF=$'\033[0m'
[ -t 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_OFF=""; }

# A local proxy silently replaces the network path under measurement: every
# timing becomes "proxy -> Cloudflare", the edge IP becomes the proxy's, and a
# 52x seen here may belong to the proxy rather than to the origin. Recorded per
# row so the CSV stays self-explanatory months later.
VIA_PROXY=0
if [ -n "$NOPROXY" ]; then
  VIA_PROXY=0
elif [ -n "${https_proxy:-${HTTPS_PROXY:-${all_proxy:-${ALL_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}}}}" ]; then
  VIA_PROXY=1
  printf '%sWARNING: a proxy is configured in this shell (%s).%s\n' "$C_YEL" \
    "${https_proxy:-${HTTPS_PROXY:-${all_proxy:-${ALL_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}}}}" "$C_OFF"
  printf '%s  Every timing below then measures PROXY -> Cloudflare, not you -> Cloudflare,%s\n' "$C_YEL" "$C_OFF"
  printf '%s  and edge_ip will be the proxy. Re-run with -P to bypass it, or keep going%s\n' "$C_YEL" "$C_OFF"
  printf '%s  knowing the via_proxy column marks these rows.%s\n\n' "$C_YEL" "$C_OFF"
fi

mkdir -p "$SNAPDIR" 2>/dev/null || true

HEADER="ts,url,code,colo,edge_ip,dns_ms,tcp_ms,tls_ms,ttfb_ms,dl_ms,total_ms,bytes,cf_cache,via_proxy,origin_code,origin_ttfb_ms"
if [ -s "$CSV" ] && [ "$(head -1 "$CSV")" != "$HEADER" ]; then
  mv "$CSV" "${CSV}.$(date +%Y%m%d-%H%M%S).old"
  echo "column layout changed; previous CSV archived" >&2
fi
[ -s "$CSV" ] || echo "$HEADER" > "$CSV"

# curl reports cumulative timestamps; convert them to per-phase durations so a
# slow TLS handshake cannot hide inside a large total.
TIMEFMT='%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{size_download} %{remote_ip}'

probe_edge() {
  local url="$1" hdr="$2" raw
  raw="$(curl -sS $INSECURE $NOPROXY -o /dev/null -D "$hdr" --max-time 20 \
         -w "$TIMEFMT" "$url" 2>"${hdr}.err")"
  [ -z "$raw" ] && raw="000 0 0 0 0 0 0 -"
  # Phases must sum to total, otherwise a large body download looks like a
  # slow server: dl is the part after the first byte arrived.
  printf '%s' "$raw" | awk '{
    dns  = $2 * 1000
    tcp  = ($3 > 0 ? $3 - $2 : 0) * 1000
    tls  = ($4 > 0 ? $4 - $3 : 0) * 1000
    ttfb = ($5 > 0 ? $5 - ($4 > 0 ? $4 : $3) : 0) * 1000
    dl   = ($6 > 0 && $5 > 0 ? $6 - $5 : 0) * 1000
    # curl leaves remote_ip empty when it never connected; an empty CSV cell
    # would shift every awk filter written against later columns.
    ip   = ($8 == "" ? "-" : $8)
    printf "%d %d %d %d %d %d %d %d %s", $1, dns, tcp, tls, ttfb, dl, $6 * 1000, $7, ip
  }'
}

# --resolve pins the connection to the origin while keeping Host and SNI intact,
# so this is the same request the edge would make — just without the edge.
probe_origin() {
  local url="$1" host port raw
  host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://##; s#/.*##; s#:.*##')"
  case "$url" in https://*) port=443 ;; *) port=80 ;; esac
  raw="$(curl -sS -k --noproxy '*' -o /dev/null --max-time 20 \
         --resolve "${host}:${port}:${ORIGIN_IP}" \
         -w '%{http_code} %{time_starttransfer}' "$url" 2>/dev/null)"
  [ -z "$raw" ] && raw="000 0"
  printf '%s' "$raw" | awk '{printf "%d,%d", $1, $2 * 1000}'
}

check_once() {
  local url="$1" hdr ts code colo edge_ip dns tcp tls ttfb dl total bytes cache org
  hdr="$(mktemp "${TMPDIR:-/tmp}/probe-52x.XXXXXX")"
  ts="$(date '+%F %T')"

  read -r code dns tcp tls ttfb dl total bytes edge_ip <<< "$(probe_edge "$url" "$hdr")"

  # CF-Ray's suffix is the colo that served the request; without it you cannot
  # tell a global outage from one bad PoP.
  colo="$(grep -i '^cf-ray:' "$hdr" 2>/dev/null | tr -d '\r' | awk -F- '{print $NF}' | head -1)"
  [ -z "$colo" ] && colo="-"
  cache="$(grep -i '^cf-cache-status:' "$hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}' | head -1)"
  [ -z "$cache" ] && cache="-"

  if [ -n "$ORIGIN_IP" ]; then
    org="$(probe_origin "$url")"
  else
    org="0,-1"
  fi

  echo "${ts},${url},${code},${colo},${edge_ip},${dns},${tcp},${tls},${ttfb},${dl},${total},${bytes},${cache},${VIA_PROXY},${org}" >> "$CSV"

  local col="$C_GRN" mark="ok"
  if [ "$code" -ge 500 ] || [ "$code" -eq 0 ]; then
    col="$C_RED"; mark="FAIL"
    FAILS=$((FAILS + 1))
    # Keep the full response headers from the failing request: the CSV records
    # that it broke, the snapshot records what the edge actually said.
    local snap="${SNAPDIR}/$(date +%Y%m%d-%H%M%S)-${code}-${colo}.txt"
    {
      printf 'url      : %s\n' "$url"
      printf 'code     : %s\n' "$code"
      printf 'colo     : %s\n' "$colo"
      printf 'edge_ip  : %s\n' "$edge_ip"
      printf 'via_proxy: %s\n' "$VIA_PROXY"
      printf 'timing   : dns=%sms tcp=%sms tls=%sms ttfb=%sms dl=%sms total=%sms\n\n' \
        "$dns" "$tcp" "$tls" "$ttfb" "$dl" "$total"
      if [ -s "$hdr" ]; then
        printf -- '--- response headers ---\n'; cat "$hdr"
      else
        printf -- '--- no response headers: the connection never completed ---\n'
      fi
      if [ -s "${hdr}.err" ]; then
        printf -- '\n--- curl stderr ---\n'; cat "${hdr}.err"
      fi
    } > "$snap" 2>/dev/null || true
  elif [ "$code" -ge 400 ]; then
    col="$C_YEL"; mark="4xx"
  fi

  printf '%s%s  %-3s %-4s colo=%-4s dns=%sms tcp=%sms tls=%sms ttfb=%sms dl=%sms total=%sms%s' \
    "$col" "$ts" "$code" "$mark" "$colo" "$dns" "$tcp" "$tls" "$ttfb" "$dl" "$total" "$C_OFF"
  if [ -n "$ORIGIN_IP" ]; then
    printf '  |  origin=%s (%sms)' "${org%,*}" "${org#*,}"
  fi
  printf '\n'

  if [ "$ONCE" -eq 1 ]; then
    printf '\n--- response headers ---\n'
    sed 's/^/  /' "$hdr"
    if ! grep -qi '^cf-ray:' "$hdr" 2>/dev/null; then
      printf '\n%sNOTE: no CF-Ray header — this request did NOT go through Cloudflare.%s\n' "$C_YEL" "$C_OFF"
      printf '  Either the DNS record is grey-clouded (DNS-only), or something\n'
      printf '  local is resolving the name straight to the origin. A 52x cannot\n'
      printf '  come from a hostname that never reaches Cloudflare.\n'
    fi
  fi

  rm -f "$hdr" "${hdr}.err"
}

if [ "$ONCE" -eq 1 ]; then
  for u in "${URLS[@]}"; do check_once "$u"; done
  exit 0
fi

printf 'probing every %ss — CSV: %s — snapshots: %s\n' "$INTERVAL" "$CSV" "$SNAPDIR"
printf 'stop with Ctrl-C\n\n'
trap 'printf "\n%s failure(s) recorded. CSV: %s\n" "$FAILS" "$CSV"; exit 0' INT TERM

while :; do
  start=$(date +%s)
  for u in "${URLS[@]}"; do check_once "$u"; done
  elapsed=$(( $(date +%s) - start ))
  nap=$(( INTERVAL - elapsed ))
  [ "$nap" -lt 1 ] && nap=1
  sleep "$nap"
done
