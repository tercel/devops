# Cloudflare 52x Troubleshooting Toolkit

Three scripts for diagnosing Cloudflare origin errors (520/521/522/524/526).
All three are read-only: they observe and record, they never change anything.

```
diag-52x.sh    run on the server    post-incident forensics: why it broke
watch-52x.sh   run on the server    continuous recording: what the host was doing that second
probe-52x.sh   run on your laptop   outside view: when it broke, which PoP, whose fault
```

---

## 1. First, identify which error code

52x is not one failure — it is a family. **Read the code Cloudflare actually
returned before deciding what to investigate**, or the whole effort points in
the wrong direction from the start.

| Code | Meaning | Typical cause | Where the evidence is |
|---|---|---|---|
| **520** | The edge connected; the origin replied with something unparseable | Upstream app crashed or was OOM-killed, nginx worker died, response headers over 32KB, connection reset | **In the nginx error log** |
| **521** | The origin refused the connection | nginx not running, or a firewall REJECT (not DROP) | Service status, firewall |
| **522** | The TCP handshake never completed | Listen-queue overflow, conntrack full, memory/IO collapse, **keepalive_timeout shorter than Cloudflare's reuse window** | Kernel counters; **the nginx log is empty** |
| **524** | Connected, but no complete response within 100s | Slow upstream, or `proxy_read_timeout` cutting a streaming response short | `$request_time` in the access log |
| **526** | Origin certificate expired or untrusted | Certificate expiry (when SSL mode is Full strict) | Certificate validity |

Two counter-intuitive readings that matter:

- **An empty nginx error log during a 522 is positive evidence, not a gap.**
  It proves the requests never reached nginx, which is exactly what 522 means.
- **For 520 the opposite holds.** The evidence lives in the error log, so a
  clean log largely rules 520 out.

**520 and 522 alternating on one host is itself a finding**: the upstream is
restarting under memory pressure. While it is down the edge cannot connect
(522); while it dies mid-request the edge receives a truncated response (520);
once the process manager restarts it, everything looks fine again.

---

## 2. Typical workflow

```bash
# 1. Gather evidence on the server (last 6 hours)
sudo ./diag-52x.sh -H 6

# 2. Start the recorder so the next incident leaves a trace
sudo nohup ./watch-52x.sh -e https://your-domain.example/ >/dev/null 2>&1 &

# 3. Run one locally too, to cover the server's blind spots
./probe-52x.sh https://your-domain.example/
```

Step 1 often returns nothing conclusive — a 52x is transient, and by the time
you SSH in the evidence is usually gone. The point of steps 2 and 3 is to make
the **next** incident leave a timestamped trail.

---

## 3. diag-52x.sh — post-incident forensics

Runs on the server, needs root (otherwise logs, `ss` and the kernel ring buffer
are unreadable). Produces a report ending in a verdict.

```bash
sudo ./diag-52x.sh                           # last 3 hours
sudo ./diag-52x.sh -H 6                      # last 6 hours
sudo ./diag-52x.sh -d 17/Aug/2026 -w 06,07   # specific date and hours
sudo ./diag-52x.sh -o /tmp/report.txt        # custom report path
```

| Option | Default | Description |
|---|---|---|
| `-H N` | `3` | Analyse the last N hours |
| `-d DATE` | today | Log date, format `dd/Mon/yyyy` (e.g. `17/Aug/2026`) |
| `-w HH,HH` | derived from `-H` | Restrict to specific hours, e.g. `06,07` |
| `-o FILE` | `/tmp/diag-52x-<timestamp>.txt` | Report path |
| `-s "..."` | auto-discovered | Override sites. Accepts site names (the `<name>.access.log` convention) or full log paths |
| `-n N` | `12` | Maximum number of sites to analyse |

**Sites, upstream ports and application roots are all auto-discovered** — no
configuration required:

- **Sites**: parsed from the actual `access_log`/`error_log` paths in each
  server block of `nginx -T`. No naming convention is assumed; inherited
  http-level logs, `access_log off` and custom paths are all handled.
- **Ports**: extracted from `listen` and `proxy_pass`.
- **App roots**: taken from pm2's `pm_cwd` and nginx's `root` directives.

The first thing it prints is **"Discovered sites"**. Check that section found
the right things before reading anything below it.

### Report structure

| Section | What it covers |
|---|---|
| 1–4 | Load, memory/swap/OOM, disk/FD, historical `sar` curves |
| 5 | nginx service and config: worker capacity, **keepalive vs Cloudflare's reuse window**, listening ports, **listen-queue overflow** |
| 6 | nginx logs within the window: errors, traffic distribution, status codes, client IPs |
| **6b** | **520/524 specifics**: upstream close/reset mid-response, worker crashes, **Node heap OOM**, oversized headers, live upstream probe, **per-vhost proxy config audit**, certificate validity |
| 7 | Build/deploy activity, **pm2 execution mode and instance count** |
| 8 | conntrack, TCP tunables, firewall |
| 9 | Origin IP exposure (real CIDR matching), crawlers, SSH brute force |
| 11 | **Verdict**: CRITICAL / WARNINGS / HEALTHY, plus a reading guide organised by error code |

---

## 4. watch-52x.sh — server-side recorder

Needs root. Appends one CSV row per interval to `/var/log/52x-watch.csv`.

```bash
sudo ./watch-52x.sh                              # foreground, every 30s
sudo ./watch-52x.sh -i 15                        # every 15s
sudo nohup ./watch-52x.sh -e https://your-domain.example/ >/dev/null 2>&1 &
sudo ./watch-52x.sh -k                           # stop a background instance
```

| Option | Default | Description |
|---|---|---|
| `-i N` | `30` | Sampling interval in seconds, minimum 1 |
| `-e URL` | none | **Edge probe**: records the status code Cloudflare actually returns |
| `-p PORT` | auto-discovered | Upstream application port, probed directly |
| `-n HOST` | auto-discovered | `Host` header sent by the local probe |
| `-u URL` | `http://127.0.0.1/` | Local probe target |
| `-f FILE` | `/var/log/52x-watch.csv` | CSV path |
| `-m MB` | `200` | Rotate the CSV once it exceeds this size |
| `-k` | — | Stop a background instance |

> When `-p` and `-n` are omitted they are read from the running nginx config,
> and the discovered values are printed at startup. When `-e` is omitted, the
> hostnames found on this machine are listed as candidates.

### The three-probe decision matrix

This is the core value of the script. 520 and 522 are different failures, and
the combination of the three probes classifies an incident without guesswork:

| edge | local | upstream | Conclusion |
|---|---|---|---|
| 522 | 200 | 200 | The host served fine locally; the edge could not reach it → network / firewall / keepalive |
| 520 | 502 | **000** | **The backend was down**, nginx had nothing to proxy to → the classic "it fixed itself a minute later" |
| 520 | 200 | 200 | The backend answered but produced something unparseable → check header size and connection resets |
| any 5xx | — | — | Read `iowait_pct` / `steal_pct` on the same row → resource stall |

### CSV columns

```
1 ts             8 estab          15 nginx_up
2 load1          9 syn_recv       16 nginx_workers   <- a drop means a worker died
3 mem_avail_mb  10 time_wait      17 local_code
4 swap_used_mb  11 listen_ovf     18 local_ms
5 dirty_mb      12 listen_drop    19 up_code         <- 000 means the backend was unreachable
6 iowait_pct    13 conntrack      20 up_ms
7 steal_pct     14 ct_pct         21 edge_code       <- 522/520 shows up here
                                  22 edge_ms
```

Common queries:

```bash
column -s, -t /var/log/52x-watch.csv | less -S
awk -F, 'NR==1 || $21>=500'       /var/log/52x-watch.csv   # every edge failure
awk -F, 'NR==1 || $19==0'         /var/log/52x-watch.csv   # backend unreachable
awk -F, 'NR==1 || $11>0 || $12>0' /var/log/52x-watch.csv   # listen-queue overflow
awk -F, 'NR==1 || $6>50 || $7>20' /var/log/52x-watch.csv   # iowait / steal spikes
```

---

## 5. probe-52x.sh — external probe from your machine

Runs on **your own computer**, works on macOS and Linux, no root required.

It covers a structural blind spot in the server-side recorder, which is both
the observer and the thing being observed:

- It keeps recording while the server is down or unreachable.
- Cloudflare is anycast: a probe sent *from* the origin hits whichever PoP is
  nearest the origin, not the one your visitors hit. 522 often lives between
  one specific PoP and the origin.
- When the server is saturated, its own probe is saturated too, so its numbers
  cannot be trusted.

```bash
./probe-52x.sh -1 https://your-domain.example/            # single check, prints full headers
./probe-52x.sh https://your-domain.example/               # loop, every 60s
./probe-52x.sh -o ORIGIN_IP -k https://your-domain.example/   # compare against the origin
```

| Option | Default | Description |
|---|---|---|
| `-1` | — | Single check, prints the full response headers |
| `-i N` | `60` | Loop interval in seconds, minimum 5 |
| `-o IP` | none | **Also probe the origin directly** (via `--resolve`, keeping Host and SNI intact) |
| `-k` | — | Accept untrusted certificates (usually needed when probing the origin directly) |
| `-P` | — | Bypass the local proxy |
| `-f FILE` | `~/52x-probe.csv` | CSV path |
| `-d DIR` | `~/52x-snapshots` | Failure snapshot directory |

### `-o`: settling where the fault lies

Two requests in the same second — one through Cloudflare, one straight to the
origin:

| Edge | Direct to origin | Conclusion |
|---|---|---|
| fails | OK | The fault is between Cloudflare and the origin (keepalive, firewall, PoP route) |
| fails | fails | The origin itself is down |
| OK | OK | Already recovered; find the timestamp in the CSV, then correlate on the server |

> **Note**: if the security group is correctly locked down to Cloudflare's
> ranges, the direct probe will time out by design. That is the configuration
> working, not an origin failure.

### About local proxies

**With a VPN, Clash or corporate proxy active, every measurement becomes
"proxy → Cloudflare"** — `edge_ip` records the proxy's address, and a 522 you
see may belong to the proxy rather than the origin. The script detects this,
warns, and marks every affected row with `via_proxy=1`. Use `-P` to bypass.

### CSV columns

```
1 ts    3 code   5 edge_ip  7 tcp_ms  9 ttfb_ms  11 total_ms  13 cf_cache   15 origin_code
2 url   4 colo   6 dns_ms   8 tls_ms  10 dl_ms   12 bytes     14 via_proxy  16 origin_ttfb_ms
```

`colo` is the PoP suffix from `CF-Ray` (e.g. `NRT`, `HKG`). Whether failures
cluster on one PoP or are global takes one command:

```bash
awk -F, '$3>=500 {print $4}' ~/52x-probe.csv | sort | uniq -c
awk -F, 'NR==1 || ($3>=500 && $15<500)' ~/52x-probe.csv   # edge bad, origin fine
```

On failure, the full response headers plus curl's own error message are written
to the snapshot directory.

---

## 6. Common causes at a glance

| Symptom | Cause | Which script finds it |
|---|---|---|
| Random 520, clean logs, recovers on its own | Node's `JavaScript heap out of memory`. This is V8's own limit — it **never goes through the kernel OOM killer, so dmesg shows nothing** | `diag` 6b |
| Random 520/522 while every host metric looks fine | `keepalive_timeout` shorter than Cloudflare's 900s reuse window. **Low-traffic sites are more exposed**, not less — an idle connection is what crosses the timeout | `diag` 5 |
| 520 on streaming requests for one vhost | That vhost is missing `proxy_read_timeout`, so nginx cuts the response at its 60s default | `diag` 6b (per-vhost audit names the file) |
| 502/522 during deploys | Process manager running a single fork instance; `restart` leaves a window with no upstream at all | `diag` 7; `up_code=000` in `watch` |
| 522 under load | Listen-queue overflow or conntrack exhaustion | `diag` 5, 8; `listen_ovf` in `watch` |
| 522 in some regions only | A problem between one Cloudflare PoP and the origin | `colo` column in `probe` |
| Sudden site-wide 526 | Origin certificate expired | `diag` 6b |

---

## 7. Dependencies

**Server side**: `bash`, `curl`, `ss` (iproute2), `awk`, `sed`, `grep` with
PCRE support (`-P`). Optional but recommended: `sysstat` (provides the
historical `sar` curves) and `python3` (parses pm2's JSON output).

`netstat` (net-tools) and `bc` are no longer required. Neither is installed by
default on Ubuntu 18.04+, and earlier versions of these scripts silently
recorded zeros when they were missing.

**Local side**: `bash` and `curl`. Both ship with macOS.

---

## 8. Verification status

- All three scripts pass `bash -n`.
- Core logic verified locally against constructed inputs: CIDR containment
  (including `/13` and `/14` boundaries), `/proc/net/netstat` parsing (including
  older kernels missing those fields), nginx config parsing (inheritance,
  compact single-line style, `access_log off`, custom paths), keepalive time
  unit conversion (`15m` → 900s), both pm2 execution modes, probe functions
  distinguishing a refused connection from a fast response, and CSV column
  alignment.
- `probe-52x.sh` single-shot probing, proxy detection and failure snapshots
  were tested for real on the local machine.
- **None of the three has been run end-to-end on a real Linux server.** The
  development machine is macOS, with no nginx, pm2 or `/proc`. On first use,
  run in the foreground once and confirm that the "Discovered sites" section of
  `diag` picked up the right sites before backgrounding anything.

## 9. Notes

- `-n` means different things in two of the scripts: in `diag-52x.sh` it caps
  the number of sites, in `watch-52x.sh` it sets the `Host` header.
- All three scripts are read-only. They never modify configuration and never
  restart a service.
