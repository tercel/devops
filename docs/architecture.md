# whatbroke — architecture (v1)

A single-binary diagnostic CLI for servers. It inspects resources, kernel and
network limits, reverse-proxy configuration, process supervision, TLS, and
CDN-origin behaviour, then **reaches a conclusion** rather than printing
numbers.

v1 ships one thing: the CLI. The architecture below exists so that the surfaces
that come later — a Netdata plugin, an MCP tool, third-party checks — attach
without reopening the core.

---

## 1. Scope

### 1.1 In scope for v1

- A `whatbroke` binary that runs a catalogue of read-only checks and prints a verdict.
- A stable, versioned JSON report (`--json`).
- Extension seams for checks, correlation rules, evidence sources, and output
  surfaces (§3).

### 1.2 Explicitly out of scope for v1

| Not building | Why |
|---|---|
| Client/server, push protocol, central aggregator | Where fleet reach is needed, a Netdata Parent already provides it. Building a second one is duplicated transport with none of the maturity. |
| A metrics agent | Netdata, CloudWatch, and `sar` already record. This reads what they recorded. |
| A dashboard or web UI | A general observability tool must show everything because it cannot know what you are looking for. A diagnostic tool knows the question, so its output is a verdict. |
| Remediation | Every check is read-only. Findings carry remediation *text*, never actions. |

These are scope decisions, not permanent bans — but each one currently exists in
a better form elsewhere, and taking them on is how this turns into a worse
Netdata.

### 1.3 Why a CLI first

The unique value is diagnosis, and diagnosis is inherently on-demand: you run it
during or after an incident, once, and you want an answer. That shape is a CLI.

The distribution consequence matters as much as the technical one. `curl | sh`
and run has no standing cost — no install to maintain, no agent to supervise, no
resource footprint on a host whose resource exhaustion may be the thing under
investigation.

---

## 2. Concepts

### 2.1 Check

The unit of diagnosis: self-contained, read-only, independently runnable.

Checks never call each other. Cross-check reasoning lives in §2.4, so that a
check stays a pure function from *evidence* to *verdict* and can be tested in
isolation.

### 2.2 Verdict: five states, not three

This is the decision that separates a diagnostic tool from a monitoring
threshold. Monitoring has `ok / warn / critical`. Diagnosis needs two more:

| Status | Meaning | Why it must exist |
|---|---|---|
| `pass` | Checked, healthy | |
| `warn` | Checked, risky | |
| `fail` | Checked, broken | |
| `skip` | Not applicable — no nginx on this host | Without it, "no findings" silently masquerades as "healthy" |
| `unknown` | Applicable, but undeterminable — needs root, log already rotated | The honesty state. A tool that cannot say "I could not tell" will eventually say something false |

`unknown` is load-bearing, not a fallback. Absence-of-evidence and
evidence-of-absence are different results, and a diagnostic tool that cannot
distinguish them will confidently mislead. Concretely: an empty nginx error log
during a 522 is *positive evidence* — it proves the requests never reached
nginx, which is what 522 means. The same empty log during a 520 is a *gap*,
because 520 evidence is supposed to be in that file. Same observation, opposite
meaning; the schema must be able to carry both.

Every `skip` and `unknown` carries a machine-readable reason, so a caller can
tell "this host has no nginx" from "I could not read the config".

### 2.3 Evidence

Every verdict carries what produced it: the command executed, the file and line
read, the raw excerpt, the parsed value.

Mandatory, not decorative, for two reasons:

1. A verdict without evidence is unactionable — the operator cannot confirm it.
2. When the consumer is an AI agent, evidence lets it reason past a wrong
   verdict instead of inheriting the mistake.

### 2.4 Facts and correlations

Checks are independent; failures are not.

A check may publish **facts** — small typed key/values — into a shared fact set:
`process.pm2.mode = fork`, `edge.codes_seen = [520, 522]`,
`system.memory.under_pressure = true`.

**Correlation rules** then match over facts and check statuses to emit
higher-order findings:

```
edge.codes_seen ⊇ {520, 522}
  AND process.pm2.mode = fork
  AND system.memory.under_pressure
  → "upstream is restarting under memory pressure"

edge.codes_seen ∋ 522  AND  kernel.net.listen_overflow > 0
  → "listen queue overflow, not a network fault"

edge.codes_seen ∋ 520  AND  nginx.error_log.clean
  → 520-at-nginx ruled out; evidence points upstream
```

This is the layer no monitoring product has, and where the accumulated knowledge
in the current shell scripts actually lives. Correlations read *facts*, never
raw evidence strings, so a rule cannot break when a check changes how it phrases
its output.

### 2.5 Report

One versioned document is the single source of truth. Every output format is a
projection of it (§3.5). Nothing downstream may compute a verdict that is not
already in the report.

---

## 3. Extension model

Five axes, each designed so that extending along it requires no change to the
core.

| Axis | Extend by | Requires recompiling? |
|---|---|---|
| A. New check | Implement `Check`, register it | Yes (built-in) / No (external, §3.3) |
| B. New correlation | Add a rule | No — rules are data |
| C. New output surface | Implement `Renderer` | Yes, in the surface crate only |
| D. New evidence source | Implement `Source` | Yes, in `whatbroke-core` |
| E. New execution context | Supply a different `RunContext` | No |

### 3.1 The `Check` trait

```rust
pub trait Check: Send + Sync {
    fn meta(&self) -> &CheckMeta;

    /// Decide whether this host is even a candidate. Returning
    /// `NotApplicable` yields a `skip` carrying the reason.
    fn applicability(&self, env: &Env) -> Applicability;

    /// Gather evidence and evaluate. Must be read-only and must poll
    /// `ctx.cancelled()` around anything slow.
    fn run(&self, ctx: &RunContext) -> CheckOutcome;
}

pub struct CheckMeta {
    pub id: CheckId,          // "nginx.keepalive_below_cf_window"
    pub title: &'static str,
    pub domain: Domain,       // system | kernel.net | nginx | process | tls | edge.cloudflare
    pub severity: Severity,   // severity IF it fires
    pub refs: &'static [&'static str],
    pub explain: &'static str, // what it inspects, why it matters, how to fix
}

pub enum Applicability {
    Applicable,
    NotApplicable { reason: String },
}

pub struct CheckOutcome {
    pub status: Status,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub facts: Vec<Fact>,          // published for correlations (§2.4)
    pub remediation: Option<String>,
}
```

`explain` lives on the check, not in prose, because the reference tables in the
current README are the most reused part of this project and prose drifts away
from the code it describes. `whatbroke explain <id>` reads this field.

### 3.2 The environment probe

`Env` is built once per run, before any check executes: OS and distro, whether
running as root, which of nginx / pm2 / systemd / sysstat are present, nginx
prefix and config paths, discovered sites and upstream ports.

Building it once matters for correctness, not just speed: forty checks each
independently shelling out to `nginx -T` would produce forty possibly-different
views of the config within one run.

### 3.3 Registry and external checks

Built-in checks are registered explicitly in one `catalogue()` function —
deterministic order, no macro magic, greppable.

For extension **without recompiling**, the registry also accepts **external
checks**: an executable in a drop-in directory that prints a `CheckOutcome` as
JSON on stdout.

```
$XDG_CONFIG_HOME/whatbroke/checks.d/*      →  executed, stdout parsed as CheckOutcome
```

The contract is deliberately the same shape as the internal trait, so an
external check is a first-class citizen: it appears in `whatbroke list`, it can
publish facts that built-in correlation rules match on, and it is subject to the
same timeout and cancellation. This is the extension path for site-specific
knowledge that will never belong upstream.

### 3.4 Correlation rules as data

```rust
pub struct CorrelationRule {
    pub id: RuleId,
    pub title: String,
    pub severity: Severity,
    pub when: Vec<Predicate>,      // all must hold
    pub explanation: String,       // may interpolate matched facts
}

pub enum Predicate {
    Status  { check: CheckIdPattern, is: Vec<Status> },
    FactSet { key: FactKey, contains: FactValue },
    FactCmp { key: FactKey, op: CmpOp, value: FactValue },
    Not(Box<Predicate>),
}
```

Because rules are data rather than conditionals, they can be loaded from file,
listed, unit-tested against synthetic fact sets, and reviewed by someone who is
not a Rust programmer. Adding institutional knowledge should not require a
compiler.

### 3.5 Renderers

```rust
pub trait Renderer {
    fn render(&self, report: &Report, out: &mut dyn Write) -> io::Result<()>;
}
```

v1 ships `TerminalRenderer` and `JsonRenderer`. Later surfaces — a Netdata
function table, an MCP tool result, SARIF — are additional implementations in
their own crates. **No check logic may live in a renderer**; a renderer that
computes a verdict is a bug, because it means two surfaces can disagree.

### 3.6 Evidence sources and the `System` seam

All filesystem and process access goes through one trait:

```rust
pub trait System: Send + Sync {
    fn read_file(&self, path: &Path) -> io::Result<String>;
    fn glob(&self, pattern: &str) -> io::Result<Vec<PathBuf>>;
    fn exec(&self, cmd: &Cmd) -> io::Result<Output>;
    fn now(&self) -> DateTime<Utc>;
}
```

`RealSystem` in production; `FixtureSystem` in tests, backed by recorded
`/proc` contents, `nginx -T` dumps, and log excerpts.

This seam is not academic. The predecessor shell scripts carry an explicit
caveat that they were never run end-to-end on a real Linux server, because the
development machine is macOS with no nginx, pm2, or `/proc`. A fixture-backed
`System` is what turns that permanent caveat into a test suite that runs
anywhere.

Remote evidence sources (the Cloudflare GraphQL Analytics API, a Netdata query
endpoint) implement a parallel `Source` abstraction with the same testability
property, and are always optional: a check whose remote source is unconfigured
returns `skip`, never `fail`.

### 3.7 `RunContext` — designing for execution models v1 does not have

```rust
pub struct RunContext<'a> {
    pub env: &'a Env,
    pub sys: &'a dyn System,
    pub window: TimeWindow,        // for log/history analysis
    pub cancel: &'a CancelToken,
    pub progress: &'a dyn ProgressSink,
}
```

The CLI never cancels anything and reports progress to `/dev/null`. Both are in
the signature from day one anyway, because the surfaces on the roadmap need
them: a Netdata function can be cancelled mid-run when the user navigates away,
and must report progress to keep its timeout alive.

Retrofitting cooperative cancellation into a catalogue of forty checks later is
not an extension, it is a rewrite of all forty. The seam costs almost nothing
now and cannot be added cheaply later.

---

## 4. Report schema (v1.0)

```json
{
  "schema_version": "1.0",
  "tool": { "name": "whatbroke", "version": "0.1.0" },
  "run": {
    "host": "web1",
    "started_at": "2026-08-21T09:14:03Z",
    "duration_ms": 2140,
    "window": { "from": "2026-08-21T03:00:00Z", "to": "2026-08-21T09:00:00Z" },
    "privileged": true
  },
  "summary": {
    "verdict": "fail",
    "counts": { "pass": 31, "warn": 4, "fail": 2, "skip": 9, "unknown": 3 }
  },
  "checks": [
    {
      "id": "nginx.keepalive_below_cf_window",
      "domain": "nginx",
      "title": "keepalive_timeout is shorter than Cloudflare's reuse window",
      "status": "fail",
      "severity": "high",
      "summary": "keepalive_timeout 65s < 900s; idle edge connections are closed mid-reuse",
      "evidence": [
        {
          "kind": "config",
          "source": "/etc/nginx/nginx.conf:34",
          "excerpt": "keepalive_timeout 65;",
          "parsed": { "seconds": 65 }
        }
      ],
      "remediation": "Raise keepalive_timeout above 900s on server blocks behind Cloudflare.",
      "refs": ["https://developers.cloudflare.com/support/troubleshooting/http-status-codes/"]
    },
    {
      "id": "nginx.error_log_readable",
      "domain": "nginx",
      "status": "unknown",
      "reason": "permission_denied",
      "summary": "error log not readable; re-run as root",
      "evidence": [
        { "kind": "error", "source": "/var/log/nginx/error.log", "excerpt": "Permission denied" }
      ]
    },
    {
      "id": "process.pm2.fork_mode",
      "domain": "process",
      "status": "skip",
      "reason": "not_applicable",
      "summary": "pm2 is not installed on this host"
    }
  ],
  "facts": {
    "process.pm2.mode": "fork",
    "edge.codes_seen": [520, 522],
    "system.memory.under_pressure": true
  },
  "correlations": [
    {
      "id": "upstream.restarting_under_memory_pressure",
      "title": "Upstream is restarting under memory pressure",
      "severity": "critical",
      "derived_from": ["edge.codes_seen", "process.pm2.mode", "system.memory.under_pressure"],
      "explanation": "While the process is down the edge cannot connect (522); when it dies mid-request the edge receives a truncated response (520)."
    }
  ]
}
```

Schema rules:

- `schema_version` is mandatory and changes only on breaking edits.
- Consumers must ignore unknown fields, so additive changes stay compatible.
- `summary.verdict` is the rollup: worst of `fail > warn > pass`. **`unknown`
  never rolls up into `fail`**, but is always reported separately in `counts` so
  it cannot be mistaken for `pass`.

---

## 5. Crate layout

```
whatbroke-core     checks, facts, correlations, report model, System/Source seams
whatbroke-cli      the v1 binary: argument parsing, terminal + JSON renderers
```

Planned, not built in v1, and deliberately additive:

```
whatbroke-netdata  Netdata external plugin: protocol codec, evloop, stdout mutex
whatbroke-mcp      MCP tool surface
```

Future surfaces link `whatbroke-core` rather than shelling out to `whatbroke-cli`,
because cancellation, progress, and timeouts have to reach *inside* a run and a
subprocess boundary hides them.

### 5.1 Dependency posture

Deliberately thin. Every dependency is something that can fail to build on an
old box, which is exactly where this tool gets used.

| Need | Choice |
|---|---|
| Serialisation | `serde`, `serde_json` |
| CLI parsing | `clap` |
| System facts | `sysinfo`, plus direct `/proc` reads where being exact is cheaper |
| Process execution | `std::process` |

No async runtime in v1. If the Netdata surface later needs concurrency it is
three long-lived threads and a mutex, not a reactor.

### 5.2 Build target

Static linking against musl (`x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`) so one artifact runs across distros with no glibc
floor. macOS builds exist for development and for running the probe-style
checks from a laptop.

---

## 6. CLI surface

```bash
whatbroke run                       # all applicable checks, human output
whatbroke run --domain nginx,tls    # restrict by domain
whatbroke run --check 'nginx.*'     # restrict by id glob
whatbroke run --json                # the schema in §4
whatbroke run --window 6h           # log/history analysis window
whatbroke run --fail-on warn        # tighten the exit-code threshold

whatbroke list                      # every known check, with applicability on this host
whatbroke explain <check-id>        # what it inspects, why it matters, how to fix
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No `fail`; `warn` / `unknown` may be present |
| `1` | At least one `fail` |
| `2` | Tool error — could not run at all |

`unknown` never fails the run on its own. It is reported, not enforced —
otherwise running unprivileged would look like a broken server.

---

## 7. Initial check catalogue

Organised by domain so the tool is extensible to general server diagnosis rather
than locked to one incident class.

| Domain | Covers |
|---|---|
| `system` | Load, memory, swap, disk space, inodes, file descriptors |
| `kernel.net` | Listen-queue overflow, conntrack saturation, TCP tunables |
| `nginx` | Worker capacity, keepalive vs CDN reuse window, per-vhost proxy timeouts, log analysis, listening ports |
| `process` | Supervisor mode and instance count (pm2, systemd), restart history, Node heap OOM |
| `tls` | Certificate validity and chain |
| `edge.cloudflare` | Status-code family analysis, origin IP exposure, colo distribution |

Adding a domain must never require touching the registry, the schema, or the
renderers.

---

## 8. Future surfaces (informative — not v1)

Recorded here because they constrain v1's seams, not because they ship with it.

### 8.1 Netdata external plugin

Protocol details below were verified against Netdata source at
`v2.11.0-75-g96f5c79df`; file references are to that tree.

> **The metrics path is unidirectional; the function path is not.** Netdata's
> documentation describes plugin communication as "unidirectional, plugin to
> Netdata". That holds for metrics only. Functions are delivered *to the plugin
> on its stdin* (`functions_evloop.c:245-299`), so a plugin registering a
> function must run a stdin reader alongside its collection loop. This is the
> execution model §3.7 reserves room for.

**Discovery and launch.** The filename must end in `.plugin`, `_plugin`, or
`-plugin` (`plugins_d.c:247-272`); the stripped stem becomes the plugin name and
the config section. The binary would ship as `whatbroke.plugin`:

```ini
[plugins]
    whatbroke = yes

[plugin:whatbroke]
    update every = 60
    command options = --domain nginx,system
```

It is spawned as `exec <fullpath> <update_every> <command options>`
(`plugins_d.c:425-427`), so `argv[1]` is the interval in seconds.

**Function registration** is positional (`pluginsd_functions.c:319-335`):

```
FUNCTION GLOBAL "whatbroke" 60 "Run server diagnostics and return a verdict" "top" "member" 100 1
```

A local plugin may **not** register a function named `config` or `config <id>` —
dyncfg owns those and the registration is silently dropped
(`pluginsd_functions.c:382-395`).

**Response envelope** — note the quoting and the leading newline before the
terminator (`functions_evloop.h:122-142`):

```
FUNCTION_RESULT_BEGIN "<transaction>" 200 "application/json" <expires_unixtime>
{ ...report... }
FUNCTION_RESULT_END
```

**Verdict → row severity.** Netdata table rows accept exactly
`normal | notice | warning | error` (`FUNCTION_UI_REFERENCE.md:358-365`), which
the five states map onto without loss:

| Verdict | `rowOptions.severity` |
|---|---|
| `pass` | `normal` |
| `skip` | *row omitted by default* |
| `unknown` | `notice` |
| `warn` | `warning` |
| `fail` | `error` |

`unknown → notice` is the mapping that matters. Collapsing it into `normal`
would restore exactly the false-healthy reading §2.2 exists to prevent.

**Alerting for free.** Emitting one chart per interval lets Netdata's own health
engine alert on `fail > 0` through an ordinary `health.d/*.conf` entity —
alerting becomes configuration rather than code. Chart and dimension argument
order verified at `pluginsd_parser.c:447-458` and `:564-569`:

```
CHART whatbroke.checks '' 'Diagnostic check results' checks whatbroke whatbroke.checks line 1000 60
DIMENSION pass    '' absolute 1 1
DIMENSION warn    '' absolute 1 1
DIMENSION fail    '' absolute 1 1
DIMENSION unknown '' absolute 1 1
```

Emitting a *count* rather than per-check dimensions is intentional: the chart is
a trigger meaning "something is wrong, go run whatbroke", not a second-rate copy of
the report.

### 8.2 MCP

Two paths, and the cheap one comes first: because Netdata's built-in MCP server
exposes *function execution*, shipping 8.1 already makes `whatbroke` callable by an
AI agent across every node attached to a Netdata Parent — with no MCP server of
our own. A native `whatbroke-mcp` surface is only warranted for deployments with no
Netdata at all.

---

## 9. Open questions

- **Cloudflare edge truth.** The GraphQL Analytics API is available on all plans
  (retention varies) and would let `edge.cloudflare.*` checks read what the edge
  actually returned, after the fact, with no probe running. Requires an API
  token — decide whether that is an optional capability or a core one.
- **External check protocol stability.** §3.3 makes the external-check JSON a
  public contract the moment it ships. It should probably be versioned
  separately from the report schema.
- **Netdata version floor.** §8.1 is verified against v2.11. The function
  protocol is older, but the minimum supported version is not established.
- **SARIF export.** Attractive for CI consumers, but the runtime diagnostic
  model does not map cleanly onto its code-analysis shape. Deferred.

---

## Appendix: relationship to the shell scripts

| Today | Becomes |
|---|---|
| `diag-52x.sh` | The check catalogue plus the correlation rules — the core of the product |
| `watch-52x.sh` | Retired. Netdata and `sar` already record; §8.1 covers the continuous signal |
| `probe-52x.sh` | Stays a laptop-side tool for now; its edge/colo logic becomes `edge.cloudflare.*` checks |
| `client/`, `server/` | Removed. Push, ingest, and aggregation are redundant once a Netdata Parent exists (§1.2) |

The scripts remain the specification of record until the equivalent checks exist
and are tested against fixtures. They are not deleted on the promise of a
rewrite.
