# Core runtime contracts — version 1.0

These contracts implement F04 design boundaries; they do not enable outbound actions or establish runtime acceptance. All supplied examples are synthetic. The contract version `1.0` preserves the existing `schemas/event-envelope.example.json` version; it is not a vendor version. The versioned schemas are under `schemas/runtime/`, identified by offline URNs. Consumers must validate with Draft 2020-12, resolve references locally, and enable datetime format assertions. `validate.py` supplies an offline reference validator, including calendar validation without optional format packages.

## Source contract and ownership

Normative source: `reference/architecture/Consolidated_Self_Hosted_Technology_Stack_v7_Integrated.md`, sections 3.4/4/6 (ownership, exact-revision approval, native APIs, unknown-result reconciliation); `reference/workflows/M17.json` (run_contract and acceptance tests); `reference/workflow_catalog.json`; `schemas/event-envelope.example.json`; `schemas/evidence.schema.json`; `docs/decisions/ADR-003-EVIDENCE-LEVELS.md` and the execution protocol. The envelope workflow identifiers are the 190 source workflow file IDs, not a newly invented namespace.

| State | Authoritative application / interface |
| --- | --- |
| Editorial, business, campaign, budget and publication approval | OpenProject supported work-package API; exact immutable approval snapshot reference |
| Contact permission, suppression, journeys and email | Mautic native API and permission state |
| Website publication | WordPress native REST API and webhooks |
| Social schedules and provider publication IDs | Postiz native API; its Temporal is internal |
| Approved assets and rights | ResourceSpace signed API and metadata |
| Website analytics | Matomo native reporting API |
| Rank history | SerpBear native API |
| Cross-app execution | Activepieces native orchestration; no second orchestrator |
| Immutable operational actions, attempts, audit and idempotency | Separate PostgreSQL operational ledgers |
| Engineering review, source and merge receipts | GitHub; engineering merge is not business publication approval |

Exact application versions, API base URLs, credentials, project mappings, currencies in use, timezone choices, expiry policies, provider test accounts and site facts remain site-owned inputs. None are inferred here. F05 adapters must map these logical references to the selected supported APIs and preserve opaque native IDs. Adapter availability never confers authorization. Consumers must independently fetch/revalidate permission and revocation at the final action boundary, fail closed on inaccessible authorities, and validate destination ownership within the same client.

## Envelope, identifiers and evolution

The event envelope retains all seed fields. `source` identifies the source system and `event_id` its stable event identifier; adapters map these to the action tuple's `source_system` and `source_event_id` without regeneration. IDs are nonempty opaque, case-sensitive strings, not globally unique native numeric IDs. Scope native references with source, client and destination; never compare an unscoped ID across clients. References contain no credentials or raw PII. `payload_ref` points to access-controlled, tenant-scoped storage; validators must not dereference it over the network. `authority_ref` is provenance, never a bearer token. `approval_ref` and `channel_eligibility_ref` are nullable only for intake; null is not permission to dispatch. Every event starts in HOLD. Unknown extra fields are rejected to catch spelling errors and accidental sensitive fields.

Version changes are reviewed centrally by F04 ownership. Downstream agents must not edit these files. Prefer optional additive fields in a new reviewed schema version; existing readers reject unknown fields, so deploy dual readers before new producers. Never silently reinterpret an existing field or loosen a gate. Preserve old schemas/fixtures for replay. Unknown versions are quarantined in HOLD, never coerced to current. The envelope idempotency string remains compatible with the seed, and is opaque; action uniqueness uses the separate algorithm below.

## Canonical action identity and retries

The unique tuple is exactly `(client_id, source_system, source_event_id, action_scope, approved_revision)`. `action_scope` must include destination/account/channel where actions can fan out. Approved revision must identify immutable content plus the approved asset/destination snapshot. Produce the UTF-8 encoding of the five strings as a compact JSON array in that order (`ensure_ascii=False`, separators comma/colon), without Unicode normalization, then prefix its lowercase SHA-256 hex digest with `sha256:`. Do not concatenate with a delimiter; embedded colons would collide. `action_key()` is the executable reference. Changed tuple components represent different actions, and require fresh authority checks; they are not a mechanism to bypass an existing UNKNOWN reservation.

A trusted consumer atomically reserves this key in PostgreSQL under a unique constraint before any external call. A duplicate reservation returns the existing outcome and never sends again. Append immutable receipt IDs for attempts and preserve correlation, event, approval and destination. The pure validator does not implement a database, lock, authorization engine, provider, or retry loop. Real concurrency, crash durability and provider semantics require later integration qualification.

An ambiguous timeout/lost reply is UNKNOWN even when no provider ID is available. UNKNOWN always means HOLD, reservation retained, no retry. Neither lease expiry, receipt age, missing callback nor new worker proves non-occurrence. Reconcile via authoritative destination readback and retain the evidence reference. A RECONCILED receipt explicitly records OCCURRED (provider ID, CONFIRMED, reservation retained) or NOT_OCCURRED (HOLD, reservation may be released). Schema validity cannot prove that readback occurred. Trusted independent reconciliation must substantiate it. Even a conclusive rejection or NOT_OCCURRED is not automatic retry authority: recheck consent, suppression, rights, exact approval, quotas, limits and a bounded retry policy before any fresh attempt. The reference transition checker models one attempt, ending at REJECTED or RECONCILED; it deliberately offers no automatic retry path. ACCEPTED means provider acceptance, not delivery, publication visibility, a sale, or business success.

## Approval, datetime, currency and missing data

Approval snapshots bind OpenProject approval ID/object, client, exact revision, asset SHA-256 set, destination and action scope, with approved-by reference, approved time, expiry and revocation status. `check_approval()` requires explicit current time and expected bindings, rejects stale/future/revoked/mismatched snapshots, and uses an exclusive expiry boundary. Snapshot validation alone cannot detect subsequent revocation. Query the authority again before dispatch; unreachable means HOLD.

All instants are UTC RFC3339 `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, at most six fractional digits. Reject naive local time, calendar-invalid dates and offsets; normalize known source offsets before submission. Do not invent a timezone for ambiguous source timestamps. Preserve source timezone and reporting-period information in the domain payload when applicable. Received time must not precede occurrence; clock-skew cases are quarantined for investigation, not silently rewritten.

Money is `{amount: decimal-string, currency: uppercase ISO-4217-code}`; binary floats, exponent notation, NaN and fabricated zero for missing feeds are forbidden. The schema checks syntax; consumers additionally validate the code against their approved ISO reference data and enforce currency-specific scale and rounding for the operation. Never silently convert currencies, combine incomparable periods or infer absent rates. Decimal arithmetic and an explicit rate/source/instant are required for conversions. Unknown values are null or an explicit domain UNKNOWN state, never zero or an empty successful result.

## Evidence and operation

The runtime evidence manifest preserves the existing evidence schema's fields and evidence levels, adding schema version, producer, timestamp and explicit nullable production authorization reference. Its fixture is an illustrative document, not a real qualification assertion. PASS, FAIL, NOT_RUN and NOT_APPLICABLE remain distinct. Only an independently attributable receipt establishes an evidence level; a producer-supplied level or authorization reference is not proof. A production claim must include a reference, then the trusted controller verifies the named human, exact revision/digests, destination, limits, expiry and staging/recovery evidence. The validator cannot award acceptance.

Run `python -B contracts/core/test_contracts.py` from the snapshot root using the already available `jsonschema` and `referencing` dependencies. No packages are installed and no network/provider calls occur. This covers schemas, seed compatibility, calendar/chronology checks, tenant/revision/asset/destination binding, collision-safe action keys, tampering, UNKNOWN transitions, release rules, evidence path traversal and money syntax. Runtime providers, database concurrency, source authorization readback, delivery and production remain NOT_RUN.

## Review remediation invariants

Receipt event_id must equal action_identity.source_event_id. External attempt states (SUBMITTED, ACCEPTED, REJECTED, UNKNOWN, RECONCILED) require a non-null approval reference; HELD may retain null pending authorization. This linkage is necessary, never sufficient authorization. REJECTED is always HOLD. Once a provider object is known, ordinary receipt transitions cannot replace or clear it; UNKNOWN may discover a previously null object through evidenced reconciliation. NOT_OCCURRED requires a null provider object and cannot negate an established object through an ordinary transition. Corrections need a separately reviewed protocol. SHA-256 values are exactly 64 lowercase hexadecimal characters, and prefixed action keys exactly 71 characters, with no trailing newline.
