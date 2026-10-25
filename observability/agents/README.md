# F17 engineering observability — offline projections

This package consumes a **trusted, already-sanitized snapshot** and produces bounded JSON and Prometheus text before an observability stack is deployed. It never opens the controller database, acquires/releases a lease, dispatches work, contacts a provider or starts a service. The original author left tests to root. This remediation runs the current synthetic suite normally and with -O; independent acceptance remains with the root supervisor.

When independently configured, existing Prometheus/Grafana/Loki components can consume these outputs. This change installs no exporter daemon, collector, dashboard, scheduler, or storage service. A file is useful before those components exist; a generated file is not proof that monitoring is deployed.

## Accepted interfaces and input custody

`telemetry.py` loads accepted `contracts/core/validate.py` for UTC/datetime and exact decimal money validation. It loads `docs/orchestration/capacity/check_dispatch_inputs.py` for F08 structural dispatch holds and reads the accepted dispatch-input field set. It does not edit either dependency or infer missing production inputs from a development measurement. F08's Windows and WSL memory observations overlap and must never be added. The snapshot resource rows must instead represent a single chosen, non-overlapping pool whose capacity is already net of trusted headroom reservations.

The input schema is enforced by strict Python shape checks rather than permissive dictionaries. Top-level fields are schema_version, monotonically increasing sequence, observed_at, emergency_stop, dispatch_inputs, tasks, resources, accounting and model_usage. Unknown fields are rejected. Input is at most 512 KiB; task count is at most 128; numeric counters are bounded nonnegative integers and booleans are rejected as numbers. JSON duplicate keys, NaN/infinity, malformed dates, future observation times and invalid money are rejected. The file reader reads only the bound plus one byte. Errors from the CLI report INVALID_SNAPSHOT and false admission/dispatch signals without echoing raw input, exception text or paths.

A trusted caller exports sanitized state; passing a path to this CLI is not permission to read private controller files. No raw event errors, prompts, model text, credentials, contact data, task packet, lease token, API key or private provider payload belongs in the snapshot. This validator is not a secret classifier. It rejects unknown fields and accepts only pseudonymous identifier formats, but the source owner must enforce data classification before export.

## Metrics and safe task detail

State gauges cover BACKLOG, READY, RUNNING, REVIEW, BLOCKED, ORPHANED, ACCEPTED and FAILED. Queue age is oldest BACKLOG/READY age; merge wait is oldest REVIEW age. RUNNING leases with a future deadline count as active; expired RUNNING leases are separately counted. ORPHANED tasks remain orphaned and force a hold; the exporter never releases their reservations. Evidence freshness is the oldest supplied evidence timestamp with a missing-evidence count. No evidence means an unknown age, not a fresh zero-age result.

Resource rows use the fixed keys cpu, memory_mib, disk_gib, gpu_vram_mib, gpu, slots and integration, each with capacity and allocated. Pressure is allocated/capacity for that same pool. Unknown values produce null in JSON, no value sample in Prometheus, and an explicit known=0 gauge. Zero capacity with zero allocation is valid only for an unused optional pool such as GPU. CPU, memory_mib and execution slots require positive capacity. Requested subscription tasks must also fit capacity minus allocated execution slots; satisfying subscription quota alone is insufficient. A nonzero allocation against zero capacity is held. Allocation must include orphaned reservations until the trusted controller reconciles them. Source data must not double count allocations across pools.

Model usage consists of numeric calls, input_tokens and output_tokens for the fixed roles implementation and review. Token **counts** are distinct from token credentials or prompt text. Roles map to the accepted F08 selection: Codex implementation with GPT-6.1-Sol/low and GitHub Copilot review; no observed token quota, provider spend or entitlement is invented. Missing model usage stays null with known=0.

Prometheus label keys/values are generated exclusively from the fixed state, resource, role and measure tuples. There are no task IDs, agent names, input/result hashes, model identifiers, paths, provider error strings or user-supplied label values. All samples are bounded numeric gauges, not inferred monotonic billing counters. Per-task JSON detail separately binds `task:...` and pseudonymous `agent:...` references to `sha256:<64 hex>` input, `git:<40 hex>` base and optional `artifact:<64 hex>` result. These are nonsecret references, never raw file paths or bearer credentials. They are outside metric labels.

## Subscription and API accounting

`api_spent_usd` and `api_reserved_usd` are separate exact decimal strings for known API-dollar amounts; missing amounts stay null. Reservations are never reported as actual spend, and usage is never multiplied by a guessed price. The F08 zero API-dollar ceiling means no API-dollar use is authorized. It is not the subscription fee and does not grant unlimited subscription usage.

`subscription_task_limit`, `subscription_tasks_used` and `subscription_tasks_reserved` are separate quota counts, with an explicit requested_subscription_tasks count for evaluating the next demand. They have no USD conversion. An unknown subscription limit/usage/reservation holds the signal; exhausted or insufficient remaining quota also holds it. No credits are purchased and no missing quota is guessed. The synthetic fixture numbers are invented test data only, not a report of the user's actual subscription.

The admission signal is false when trusted inputs show emergency STOP, F08 holds, stale snapshot (>120 seconds), unreconciled orphan/expired RUNNING work, unknown or exhausted resource margins, unknown API accounting, API spent+reserved above the approved ceiling, or insufficient subscription quota. Even a true signal means **only** that these observation checks passed for the requested count. `dispatch_authorized` is always false and next_step always requires trusted admission. The controller still authenticates evidence and enforces capacity, provider limits, task eligibility, locks, cost reservation, per-task caps and G02 atomically before any claim. F08 structural booleans are not authenticated authority.

## Replay and output

The returned cursor binds sequence, canonical snapshot SHA-256 and observed_at. A trusted consumer passes its previous cursor back to reject lower sequences, decreasing observation times, or conflicting content at the same sequence. Identical snapshot replay is idempotent. The cursor is only a consistency mechanism; the caller must protect cursor storage against rollback. This code does not maintain a second controller ledger. A newer observation can become stale at render time and hold admission even when its content previously passed.

`task_ref` is an immutable attempt reference, not a reusable logical task ID. The cursor now retains an `attempt_bindings` map from each observed task_ref to its exact input_ref/base_ref, including attempts absent from later snapshots. A higher sequence cannot replace those bindings. Retries with different input or base require a new attempt reference. History is bounded to 512 attempts and is never silently pruned: reaching the bound with an additional attempt fails closed. The trusted owner must archive and explicitly establish a fresh monitoring scope/cursor with nonreused attempt references; deleting history or accepting an old three-field cursor is not an automatic migration or safe reset. Cursor storage remains a trusted caller responsibility.

CLI commands for the trusted isolated runner, from the exported workspace:

```
python -B observability/agents/test_telemetry.py
python -B observability/agents/export_snapshot.py observability/agents/fixtures/synthetic-snapshot.json --now 2026-10-25T12:01:00Z
```

`--prometheus` prints numeric text instead of JSON. `--previous-cursor` accepts a separately saved safe cursor file. `--output-dir` requires an existing nonsymlink output directory and writes fixed `agents.json`/`agents.prom` names via exclusive temporary files and replacement. Supply a disposable authorized output directory; this mode is not an installer. The two files are replaced separately, so consumers needing a coherent pair must use the JSON cursor/version as their consistency boundary. No external file paths are taken from snapshot contents.

The supplied positive fixture sets F08 flags to synthetic true values only to exercise the transform's positive branch. The tests separately use the accepted F08 held inputs and require a false signal. Tests cover exhaustion, reservations versus spend, unknown data, orphan/expiry holds, bounded labels, hostile fields, wrong hashes, duplicate and malformed JSON, API amount syntax, replay conflict, detached output, file writing and redacted CLI failures. These are authored tests, not execution evidence.

Unverified items remain held: actual snapshot exporter/authentication, current capacity and subscription entitlements, provider counters, cost reconciliation, atomic admission enforcement, actual retention/storage, metrics ingestion/alerts and all runtime/production isolation. No F17 artifact claims those qualifications.


## Independent review remediation

READY, RUNNING and REVIEW rows now require nonmissing prerequisite evidence no older than the same 120-second freshness bound used for snapshots. Exactly 120 seconds is accepted; older evidence holds the admission signal. Completed historical tasks remain visible in evidence-age metrics but cannot block unrelated new work solely because their evidence is old or absent. The positive synthetic fixture now supplies fresh READY evidence and includes one completed historical row with missing evidence; the original two-missing-evidence metric assertion remains intact.

Eight additional regression methods cover zero required pools, free-slot demand, critical-evidence absence/expiry and boundary, historical evidence, attempt identity changes, explicit retry references, disappeared/reappearing attempts, cursor compatibility and bounded-history overflow. All original test methods are retained unchanged. These changes still provide observations only: dispatch_authorized remains false, metric labels remain fixed and subscription counts are not converted to API dollars. Python execution and independent reruns belong to root.

## Export invalidation and consumer freshness

Every successful JSON export includes export_available=true, rendered_at and valid_until. Prometheus exposes agent_export_available, agent_export_timestamp_seconds, agent_export_valid_until_timestamp_seconds and agent_snapshot_observed_timestamp_seconds. Consumers must check availability and their own current clock against valid_until on every read; use report_is_current for JSON, or require time() < agent_export_valid_until_timestamp_seconds together with agent_export_available == 1 for metrics. Snapshot/evidence age gauges are samples and do not advance while a file sits on disk. A once-positive admission sample never authorizes dispatch.

The expiry is the earliest of snapshot freshness, critical prerequisite-evidence freshness, active lease expiry and one export freshness interval. At the expiry instant consumers fail closed. On invalid/unreadable snapshot or cursor, the CLI replaces both fixed output files with an INVALID_SNAPSHOT/unavailable report and zero admission/dispatch/availability metrics. Failure reports omit old state counts, cursor and ages. A partially failed write invalidates both files; inaccessible storage can prevent both replacement and deletion, so consumer-side expiry and missing-file rejection remain mandatory. Output pairs are not one atomic filesystem object; consumers requiring a coherent pair must still use the trusted version/cursor boundary. The last valid replay cursor should be held separately and never replaced with an unavailable report.

The API budget check uses exact integer ratios for spent + reserved versus cap. It does not add Decimals in the ambient precision context, so an arbitrarily small accepted reservation above an exact cap is not rounded away. The existing bounded decimal syntax and nonnegative amount limits remain unchanged.

Six new tests cover successful publication followed by malformed/missing input or missing cursor, consumer-side expiry, exact-budget behavior at low/default/high Decimal precision, and partial-write cleanup. All original 30 methods remain. No exporter service, live telemetry or controller admission operation was run.