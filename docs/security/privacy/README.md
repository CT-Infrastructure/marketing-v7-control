# Privacy and channel eligibility contract 1.0

This package is an offline decision model, not a contact store, legal opinion, provider integration or permission to act. `eligibility.py` consumes typed, caller-authenticated snapshots and returns DENY, HOLD, or ELIGIBLE_OFFLINE. Every result retains outbound_state=HOLD. No function reads contacts, sends messages, modifies permissions, deletes data or calls a provider. The fixture is synthetic, including its jurisdiction and reviewer references; it is not consent evidence.

## Independent channels and authorities

| Channel | Source of permission and review | Explicit exclusions |
|---|---|---|
| email | Mautic permission and current native/provider suppression; purpose/account/jurisdiction-specific evidence | Import, address validity, CRM membership or engagement never grants consent. E11/E12 final transport and quota guards remain separate. |
| phone | Telephone-specific consent/suppression/Do-Not-Call state in the existing PostgreSQL operational records; verified applicable calling/recording rules | Email opt-in and SMS permission do not authorize calls, AI speech or recording. Asterisk/carrier capability is not permission. |
| sms | Independent Mautic SMS permission and STOP/suppression state; selected provider/registration review | SIP service does not imply SMS capability. Phone consent does not imply SMS permission. |
| tracking | Actual site/tracker consent authority selected by the site; approved purpose, tracker/account and jurisdiction review | A cookie banner alone is not evidence of compliant tracker behavior. No tracker or banner product is assumed. |
| audience_export | Explicit audience-export permission and platform/privacy review for destination account and purpose | Contact possession, email permission and marketing engagement do not authorize uploading an audience. |

Authority strings in the module identify these contract roles, not new databases/services or a claim that endpoints exist. Mautic remains the contact authority; telephone-specific records retain their source-defined ownership. Review responsibility is assigned to the `privacy_reviewer` and `provider_compliance_reviewer` roles, not a fabricated person. A verified human process must resolve the applicable jurisdiction, provider rules, recording/disclosure, retention, data location, rights and permission requirements. Missing or stale review yields HOLD, with the responsible role. No legal/provider rules, consent or engagement are inferred by a model.

## Typed bindings and final-boundary evaluation

A Request binds client, opaque subject reference, independent channel, purpose, account, jurisdiction and provider. Permission must match all of them plus the channel authority and have explicit True grant, False revoked, True available, valid evidence reference and current timestamps. Missing, false, malformed, stale, future or revoked permission returns DENY. Truthy strings and Boolean-as-integer freshness or generation values reject. The caller supplies the freshness interval from a reviewed policy; the fixture's interval is only a test choice, not a legal limit.

Both jurisdiction and provider reviews must match the entire request binding, be explicitly APPROVED and unrevoked, and carry fresh, unexpired review evidence from the responsible role. A role label or reference string is not proof that a real reviewer approved anything. The trusted caller must authenticate the source and reviewer authority before creating these snapshots. No status from engineering, CI or this model substitutes for that process.

Lifecycle state must be available and current for the same client/subject. Deleted or suppressed records cannot qualify. Expired retention denies; unknown retention holds for privacy review. Requested assets require exact one-to-one rights evidence bound to client, account and purpose, with current observation and exclusive expiry. Missing, duplicate, expired or revoked rights deny. This does not establish copyright ownership or a legal basis; ResourceSpace remains the native rights/asset authority.

Use UTC strings matching F04's YYYY-MM-DDTHH:MM:SS[.fraction]Z convention, with real calendar validation and exclusive expiry. A future observation is not fresh. A validity snapshot cannot detect later withdrawal: fetch current permission/suppression/rights just before each effect, including after delays/retries. Never extend expiry or overwrite revocation based on a successful past check.

## Restore, deletion and revocation propagation

Keep all restored consumers and queues in HOLD. Reapply suppression, deletion/tombstone, retention-expiry and rights-revocation records produced after the backup cutoff before considering any effect. `authority_generation` comes from a current authoritative read; `applied_generation` must match it exactly. A restore also needs a unique restore epoch, explicit replay_complete=True and replay evidence. Neither a backup's old consent row nor its old replay marker proves the latest generation was applied. Re-query the authoritative generation at the effect boundary; concurrent new revocation invalidates the decision.

Operational propagation contract:

1. Record a source-issued immutable change ID, subject/client or asset scope, effective time, reason category and monotonically advancing authoritative generation. Do not place raw identifiers in generic logs. Native owners retain their state; operational ledgers keep reference/audit linkage only.
2. Fan out through existing adapters to queued Mautic email/SMS, telephone suppression and pending calls, active tracker configuration, pending audience uploads, destination copies and asset-derived publications as relevant. Cancel or quarantine pending work. An uncertain external action remains UNKNOWN under F04 and requires destination reconciliation; deletion does not prove it never occurred.
3. Collect per-destination acknowledgments for the same generation and retain a minimal approved tombstone so restored data cannot silently resurrect eligibility. Retry only idempotent propagation using the immutable change ID; missing destination coverage remains HOLD. Provider deletion/withdrawal capability and legally required retention exceptions need human review; do not claim remote erasure from a local flag.
4. Restore native databases/files coherently in isolation. Reconcile authoritative changes after the backup cutoff through the current generation, then record replay evidence and re-fetch all current eligibility/rights. Restore does not renew permissions or extend retention. Unknown legal holds or conflicting retention/deletion obligations go to the privacy reviewer, with outbound work held.
5. Keep minimal audit evidence under an explicitly reviewed audit retention policy, separately access-controlled. Restore media expiry, deletion from backups and downstream copies require an approved lifecycle plan and receipts; no destructive operation is implemented here.

The model tests the receipt conditions, not actual cross-system propagation, durable generation ordering, deletion or recovery. Consumers must implement race-safe final checks together with their F04 action reservation and F05 native adapters. No globally atomic cross-provider deletion is claimed.

## F04 integration and evidence boundary

Keep the original F04 event_id/correlation_id/client_id and action identity. Store this decision's immutable evidence reference in the existing `channel_eligibility_ref`, and bind it to the exact request/action revision in the trusted evidence store. Do not add privacy fields to shared F04 schemas in this task. `approval_ref` remains a separately verified OpenProject action approval. ELIGIBLE_OFFLINE is neither that approval nor a SUBMITTED/ACCEPTED action receipt. Generic failure after submission stays UNKNOWN until authoritative reconciliation.

Source: integrated V7 architecture sections covering independent channel permission (telephone and V5 contact authority, privacy rules and source data), component/native ownership, `contracts/core/README.md`, F16 brief, AGENTS, SECURITY and execution protocol. No live legal/provider sources or contacts were used.

## Tests and open qualification

Root-only commands: `python -B contracts/privacy/test_eligibility.py` and `python -B -O contracts/privacy/test_eligibility.py`. They are authored NOT_RUN here. Tests use only the included synthetic fixture and cover all five channels, cross-channel inference, request/evidence mismatch, type confusion, stale/expired/revoked permission, missing reviews, suppression/deletion, post-restore replay, generation mismatch, retention and asset-right expiry. No real approval or engagement is fabricated.

Before live use: the trusted owner must identify actual reviewers/authorities, approve jurisdiction/provider requirements and freshness/retention policies, qualify source authentication and final-boundary race handling, prove propagation and post-backup replay on isolated systems, and obtain independent review plus required human gates. These are unresolved inputs, not permission to bypass DENY/HOLD.
