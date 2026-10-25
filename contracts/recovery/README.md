# F18 recovery contract v1.0

The initial and returned state is **HOLD**. `evaluate_recovery` is a pure offline eligibility check for later human review; it performs no restore, credential access, provider call, release, queue replay or retry. Its synthetic unit tests are not evidence that a backup can be restored.

A recovery record binds current commit, dependency locks, environment, restore ID and immutable backup generation/manifest. Backup creation and restore timestamps are bound by the independently verified restore-execution receipt. Merely matching a backup checksum is not restoration. Preserve source generations, keys under authorized custody, rollback options and immutable audit records; do not overwrite or prune them during recovery.

Before any separate unhold decision, the trusted verifier must establish all of the following:

1. The complete restore ran in an isolated destination with all sends, calls, publishing and spend held throughout. The restore execution and HOLD proofs bind this restore and its exact environment; they are not copied from another drill.
2. The authoritative suppression/deletion/withdrawal stream after the backup was replayed through the trusted current cutoff, at least through restore time. The checkpoint receipt must be issued after the replay watermark. F15's owners specify retention and site RPO/RTO; none are invented here.
3. Every effect ID in the independently determined reconciliation set has authoritative destination readback after restore, proving OCCURRED or NOT_OCCURRED. UNKNOWN, missing, cache-only or contradictory evidence keeps HOLD. OCCURRED does not authorize another send. NOT_OCCURRED is not automatic retry authority. Preserve F04 action identity/reservations and recheck native consent, approval and quota at any later dispatch.
4. Every required credential has a nonsecret credential reference, broker reference and scope reference plus an independently verified successful access test in the restored environment, issued after restore. A reference or decrypted file alone is not proof of usability. Do not store key material, passwords, tokens, certificate private keys, credential URLs or full provider responses. The trusted broker performs the actual authorized test and retains sanitized proof outside this code.
5. An independent human/operator reviews the exact result with current channel/site authority. Production approval remains a separate F18 evidence-level decision and native final guard; this recovery API never clears HOLD.

The expected restore ID, generation, current suppression cutoff, complete effect IDs and required credential references come from the trusted recovery plan and live authoritative inventories. The record author must not define that set to omit unresolved actions or unusable credentials. Empty effect inventory is acceptable only when that trusted inventory establishes there were none; an empty credential requirement is rejected. All claim and receipt fields are strict, unknown fields fail closed and references are nonsecret opaque IDs.

`trusted_receipts` is already-authenticated independent evidence supplied by the caller, not a worker-owned dictionary. Its validation establishes shape/bindings/time and cannot authenticate a signer or prove a remote observation. `restore_execution`, `restore_hold`, `suppression_replay`, `authoritative_remote_readback` and `credential_access_test` are evidence categories, not new runtime services. Approved existing backup tools, native APIs and the scoped credential broker retain execution ownership.

Run `python -B -m unittest discover -s contracts/recovery -p test_*.py -v` only in the authorized test environment. Record actual output and immutable source identity. Real restore, credential usability, remote reconciliation, measured RPO/RTO, carrier/provider behavior and native suppression remain NOT_RUN for this task.

## Independent-review remediation

Recovery expected context also requires the independently attributed author_ref and rejects mismatched or absent attribution. Restore-execution proof issuance must be at or after the claimed completed restored_at, in addition to the existing backup/restore chronology, identity, expiry and independently verified subject checks. Exact-time completion proof remains valid; earlier proof cannot establish a completed restore. All successful evaluations still return HOLD.


## Conflicting current remote observations

Selecting a readback_ref cannot hide another current authoritative readback for the same effect ID and exact commit/lock/environment identity. The validator examines all matching receipts in the caller-authenticated registry. A receipt is current for this check when issued at or after this restore, no later than the trusted current time, and not expired. Same-time or newer opposite OCCURRED/NOT_OCCURRED observations fail closed regardless of which reference the claimant selected; this implementation also conservatively holds older contradictory observations that are still current. Current UNKNOWN outcomes hold as unresolved.

A trusted controller must reconcile contradictions and supply a consistent current observation set before another eligibility check; the claimant cannot drop inconvenient receipts. Expired, pre-restore, future-dated, other-effect, other-identity and nonauthoritative cache records do not qualify as current matching readbacks. Malformed matching-scope metadata holds because it cannot safely establish whether that observation is current. Consistent duplicate observations are allowed, but every successful result still returns HOLD, no automatic retry and no production authorization.

Five added synthetic regressions cover same-time and newer opposing observations under either selected reference, stale/nonmatching scope controls, consistent duplicate readbacks and current UNKNOWN. Existing evidence-level and recovery tests remain intact. This remains offline contract logic; the trusted registry's authentication, completeness and actual provider reconciliation require separate execution evidence.
