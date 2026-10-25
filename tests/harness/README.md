# F07 isolated synthetic harness

This is test-only scaffolding around the accepted F04 core contracts. No Python, database fixture, socket probe, provider, service or test has been executed by the authoring worker. All execution and runtime qualification remain **NOT_RUN** until the trusted isolated runner supplies evidence. No production endpoint, credential, contact, account, payment or provider SDK is present.

## Modules and boundaries

`synthetic.py` loads `contracts/core/validate.py` from the supplied snapshot and reuses its canonical action key, approval checks, receipt validation and allowed transitions. It does not fork those schemas or replace Activepieces, OpenProject or PostgreSQL. `test_synthetic.py` authors 26 positive and adversarial test methods. Shared JSON under `tests/fixtures/shared/` is synthetic input, not an acceptance receipt.

`FakeProvider` uses an exact registry of `fake://` endpoints for WordPress, Postiz, Mautic, voice, payments and ads. Calls are direct Python method calls that only mutate an in-memory dictionary. There are no listeners, HTTP clients, DNS lookups, SMTP transports, carrier connections, SDK fallbacks or child services. Real schemes, unrecognized endpoints, user-info, query strings and fragments are denied before state is reserved. The fake provider's ACCEPT result only simulates provider acceptance; it is not delivery, publication, charging, dialing or spend.

`FakeClock` starts at an explicit synthetic UTC instant and can only advance by nonnegative integer seconds. `FakeAuthority` stores detached copies of an F04-validated synthetic approval and can simulate unavailable, revoked and expired authority. Every new submission checks its client, exact revision, destination, asset hash set and action scope using the accepted core. Replaying a previously reserved action retrieves its existing receipt without a new external operation; this retrieval does not renew its authority.

`FakeModel` returns detached deterministic fixtures selected by a closed case identifier. Its malformed JSON and instruction-injection cases are untrusted test data; the harness does not execute model text. Missing measurement data stays null/UNKNOWN. There is no model endpoint or token.

## Receipts, callbacks and replay

A caller provides an existing disposable temporary parent. The harness creates its own randomly named child directory and fixed `synthetic.sqlite` file; it never opens a caller-specified existing database or the controller ledger. SQLite enforces a unique action key and stores receipt history and callback deduplication. Context exit closes the database and removes only that generated child directory. Tests verify sibling preservation and fresh-instance isolation. An interrupted runner may leave files; the trusted runner must destroy its disposable scratch filesystem after preserving sanitized test evidence.

The simulated flow is HELD -> SUBMITTED -> ACCEPTED/REJECTED/UNKNOWN. A null initial approval reference binds at SUBMITTED as accepted F04 permits. UNKNOWN remains HOLD with its reservation and cannot resubmit. A separate fake readback resolves OCCURRED or NOT_OCCURRED; neither result triggers an automatic retry. Established provider IDs remain immutable through the accepted core transition check. A released fake reservation retains its historical row, so repeated submission still cannot send again.

Callbacks are canonical JSON bytes with an HMAC using explicitly public synthetic test material embedded in the fixture module. That value is not a real secret and must never be used by a live service. Signature, exact fields, duplicate JSON keys, 300-second freshness, action/client/provider/destination/object identity and replay IDs are checked before a receipt transition. The callback handler additionally obtains independent fake readback; it does not trust callback text as external truth. The static signed-callback.json fixture was constructed with local .NET SHA-256/HMAC primitives without executing Python; an authored test compares its exact bytes and signature to the fake signer. These are synthetic contract semantics, not proof of any vendor signing scheme or production key custody.

This SQLite fixture is intentionally single-process and temporary. It is not evidence for production PostgreSQL concurrency, crash consistency, backups, migrations, distributed coordination, callback delivery guarantees or trusted authorization. Those require separately scoped native integration tests.

## Default network denial and root-run probe

The normal unit suite does not make socket connections. It verifies the fake endpoint allowlist and patches socket creation to fail if used. This tests the application seam, not OS enforcement; arbitrary Python could bypass an in-process guard. Root must run the suite inside the actual network-denied sandbox, with no credentials or host/controller sockets mounted.

Commands for the **trusted runner only**, from the exported workspace:

```
python -B tests/harness/test_synthetic.py
```

`probe_network.py` is deliberately separate from normal tests. Root may run it only inside the approved, isolated network namespace, with `F07_NETWORK_NAMESPACE_EXPECTED=1` and the explicit switch:

```
python -B tests/harness/probe_network.py --probe-test-net
```

The environment marker is intent, not attestation. The probe connects only to literal TEST-NET `192.0.2.1:9`, never resolves a hostname, sends no application payload, and has a two-second timeout. Network-unreachable/host-unreachable/permission-denied errors produce exit 0 with a scoped DENY_OBSERVED result. A successful connection produces exit 1. Timeout/refusal/other errors are inconclusive and exit 2; absent opt-in also exits 2 with NOT_RUN. A single-address observation does not prove IPv6, DNS, proxy, VPN, metadata or complete production egress denial. Root records the actual wrapper/namespace, command, result and limitations; the worker has not run this probe.

## Retention and evidence

`tests/fixtures/shared/retention.json` requires immediate context cleanup of disposable databases and a maximum seven-day retention / 1 MiB size for exported test artifacts. The database cleanup is implemented and has an authored test. Exported-artifact expiry and size must be enforced by the trusted CI/scratch-store configuration; this repository change does not configure CI storage. They remain NOT_RUN. Export only test IDs, commands, versions, exit codes, hashes, scoped failure reasons and synthetic receipt references. Never export raw model/provider payloads, private source inputs, production identities, credentials or task lease packets. Only the private agent result carries required lease metadata.

All future PASS/FAIL evidence must identify the tested source digest and actual isolated execution. Test authoring and schema-shaped output cannot establish acceptance. Keep native provider behavior, production network isolation, real approval revocation, production retention and G gates explicitly held. No actual services or production facts are required to review this harness candidate.




## Late callback acknowledgment

A valid callback may arrive after explicit authoritative fake readback has already reconciled OCCURRED, or a new event ID may describe the same object after an earlier callback. After signature, shape, freshness, client/provider/destination/action and current readback checks, the harness records an unseen event and returns the existing OCCURRED receipt. It does not attempt a second F04 transition, create another receipt or resubmit. A duplicate event returns that same receipt without another callback row. The event-to-action binding still rejects cross-action replay.

Idempotent acknowledgment never bypasses signature or identity validation. A stored NOT_OCCURRED outcome or changed established provider object rejects the callback and preserves the existing receipt. Four additional regression methods cover explicit-readback-first, new-event-after-callback, duplicate acknowledgments, bad signatures and contradictory outcome/object readback. The original22 tests remain unchanged; all26 are authored for root-only execution.
