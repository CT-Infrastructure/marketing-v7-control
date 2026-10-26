# F07 isolated synthetic harness

This is test-only scaffolding around the supplied F04 contracts. Production remains disabled. G02/F12 and F07 as a whole remain unqualified. This candidate provides local unit evidence only; independent validation, review and acceptance belong to the trusted controller.

`synthetic.py` reuses `contracts/core/validate.py` for action keys, approval checks, receipt validation and transitions. Fake providers are direct in-process calls selected by exact fake:// endpoint allowlists; there are no real provider SDKs, listeners or network fallbacks. The disposable SQLite fixture is not evidence for PostgreSQL durability or concurrency. Fake approval authority does not replace OpenProject. Public synthetic callback HMAC material is not a production credential. Deterministic model fixtures are untrusted data and never executable instructions.

All 40 pre-existing test methods in test_synthetic.py and test_probe_network.py are retained unchanged. Their complete execution requires the accepted jsonschema dependency, unavailable in this authoring interpreter. No dependency installation or real network probe was authorized. Mocked socket tests exercise only application semantics, not OS egress enforcement. probe_network.py requires a separately authorized trusted isolated runner; do not use it as a general connectivity probe.

## Local export retention

`export_retention.Exports(root, owner, clock)` accepts an absolute, canonical, existing disposable root supplied by the controller and a controller-assigned 32-character lowercase hex ownership ID. The controller must exclusively own the root and serialize all readers/writers/mutations while an operation runs. This path-based helper is not hardened against a concurrent malicious filesystem writer. Do not use it on shared or production directories. Symlink/junction roots, root replacement, owned symlinks/reparse points, directories, special files and multi-link files reject. Operations inspect only direct children matching the exact synthetic ownership namespace; they never recurse. Unrelated files and other ownership namespaces are preserved. Ownership names are a convention inside this trusted disposable root, not an authentication boundary.

The helper reads tests/fixtures/shared/retention.json without modifying it, enforces exactly seven days and 1,048,576 bytes per artifact, and rejects unsafe/invalid policy values. The fixture's historical enforcement note describes the separately owned CI obligation; this candidate adds local enforcement only. Clock is a callable returning canonical UTC timestamps with six fractional digits, e.g. 2026-10-01T00:00:00.000000Z. Missing timezone, alternate/ambiguous encodings, invalid dates, duplicate fields and future artifact timestamps fail closed. Age exactly seven days expires; timestamps come from the injected clock and artifact envelope, never filesystem mtime.

`export(case, repeats=0)` permits only four hard-coded synthetic case IDs and generated synthetic padding. It accepts no arbitrary payload, path, model output or receipt text. This closed vocabulary is not a filter that detects arbitrary secrets. Size is checked before creating a partial file. A bounded partial is exclusively created, flushed and fsynced, then renamed to the final JSON name after a collision check. No success receipt returns on write, sync, rename or cleanup failure. Caught interruptions remove the owned partial; a hard process kill or cleanup denial can leave a partial. Sweep validates owned partials and final files and removes only those at or beyond seven days. Malformed/truncated partials fail closed and require disposal of the isolated scratch root by its controller; the helper never guesses their age or recursively deletes them. Rename and process-level success are not power-loss durability evidence.

`sweep()` validates the complete owned candidate set before deleting expired entries. Fresh files remain. Repeated successful sweeps are idempotent. A deletion failure raises rather than returning a success list; earlier completed deletions may have occurred, and a later explicit sweep reconciles them. There is no automatic background deletion. Sibling and parent paths are never deletion targets.

## Runbook and evidence limits

Use only a controller-supplied disposable artifact root. Run synthetic unit tests with the existing interpreter and dependencies, using absolute paths:

```
python -B -m unittest discover -s <absolute-workspace>/tests/harness -p test_*.py
```

The added test_export_retention.py covers size boundaries, just-before/at/after expiry, mixed ages, repeat sweeps, siblings, policy/timestamp rejection, publication collision, partial writes, cleanup/delete failures, traversal, special-file rejection and symlinks. Actual symlink creation may skip when the sandbox denies that capability; root must validate on its intended Linux filesystem. No actual provider, upload, store or network namespace probe is run here. runtime_cases_run remains zero.

Local retention enforcement is separate from actual CI/upload/store enforcement. A separately owned CI packet must configure and validate upload size gates, remote-store expiry, permissions, cleanup after killed jobs and independent execution on the target filesystem. This candidate changes neither .github nor shared CI policy. Passing these unit tests cannot establish F07 acceptance or qualify G02/F12.
