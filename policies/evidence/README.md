# F18 evidence policy v1.0

This is an offline policy candidate, not a qualification receipt. The validator checks eligibility for an independent decision and never awards a level, clears a hold or authorizes production. Checksum success, rendered diagrams, an author's statement and schema validity are insufficient evidence of application readiness.

## Levels and current identity

Every claim and every independently verified receipt binds the exact current commit, dependency-lock SHA256 and environment-manifest SHA256. The trusted caller supplies this expected identity, current UTC time, exact qualification plan and complete required case set. Changing any binding invalidates old evidence. A checksum binds bytes; separate provenance, measured environment and independent execution records establish what those bytes represent.

| Requested level | Required independent evidence in addition to exact case execution |
|---|---|
| CODE_MERGED | Verified immutable merge receipt, independent code review, dependency-lock provenance and captured environment |
| SANDBOX_QUALIFIED | All common evidence plus observed sandbox boundary execution at that exact identity; mock-only scope must be explicit in the trusted plan |
| STAGING_QUALIFIED | All common evidence plus observed selected-stack staging boundaries, permitted test accounts and relevant acceptance cases |
| PRODUCTION_APPROVED | All common evidence plus staging qualification, independently verified recovery qualification, and a current authorized human approval binding the exact target, channel, limits, plan and identity |

There is no automatic promotion. `evaluate_evidence` returns `level_awarded: null` and `production_action_authorized: false` even on success. The trusted integration controller must authenticate receipts, verify issuer/account/role and any required human quorum, then make a separate decision. Receipt IDs, actor IDs and booleans are not authentication. `trusted_receipts` is an input populated only after that external verification; untrusted claim data must never populate it. Fixtures deliberately supply a synthetic trust registry for tests and are not real approvals.

Required-case sets are controlled by the independent qualification plan, never chosen by an author to omit failures. All required cases must be PASS with independent execution and verified artifacts. NOT_RUN, FAIL and NOT_APPLICABLE block this version's decision. A legitimate non-applicability disposition requires a separately reviewed plan with an authenticated human rationale; it is not a string substitution. Time bounds use UTC and exclusive expiry. Each tested case, supporting receipt and production approval must remain current.

## Original acceptance coverage

`acceptance-register.json` preserves all 576 IDs from `reference/acceptance/Original_Acceptance_Matrix.csv`, including the exact source test text and source workflow. It maps each ID to its existing verification issue from `backlog/acceptance_traceability.csv` and an independent executor role. Named individuals and evidence references remain null. Roles are responsibilities to assign, not claims that someone accepted an assignment.

The original source labels 564 rows NOT_RUN and 12 rows OPEN_SOURCE_BLOCKER. The register preserves those labels as `source_annotation`; independently, all **576 runtime_status values are NOT_RUN**. The twelve blockers are not twelve executed tests, extra cases, or exemptions. No runtime acceptance case was executed by producing this policy or by running its unit tests. `validate_register` rejects missing/extra/duplicate IDs, changed mappings/annotations, invented people and any runtime promotion.

CODE_MERGED for this policy is not a pass for these 576 runtime cases. Each downstream verification issue must provide its actual evidence at the required environment level. F15's unset production inputs, owner assignments, RPO/RTO, versions, identities and channel approvals remain unset until their authorized owners resolve them. No site values or approved providers are inferred from this register.

## Artifacts and trusted boundaries

`evidence_policy.py` is a pure stdlib validator. `synthetic_fixtures.py` constructs nonsecret fake receipts and identities in memory. `test_evidence.py` checks current identity, required evidence, independent execution, expiration, coverage, malformed fields and forbidden promotion. `contracts/recovery/` supplies the complementary restore-in-HOLD contract. Neither modifies accepted F04 schemas nor substitutes its engineering receipt structure for F04 business action receipts.

References are opaque nonsecret identifiers, not URLs or bearer credentials. Actual evidence is held in authorized private stores; trusted consumers resolve references and verify artifact digests, signer/issuer and content. References and hashes alone cannot prove authority or runtime success. Only summarized, redacted metadata belongs in shared evidence. Never copy task packets, controller lease credentials, secret values, contact payloads or private inventory into this directory.

## Verification runbook

Root's isolated executor may run, from the complete source snapshot:

```
python -B -m unittest discover -s policies/evidence -p test_*.py -v
python -B -m unittest discover -s contracts/recovery -p test_*.py -v
```

Both suites are synthetic policy tests. Preserve exact source/environment/lock identities and actual exit codes; tests are NOT_RUN until that executor records them. Independently verify all original ID mappings and compare the register against immutable source/traceability inputs. Test malformed, stale, self-authored and missing evidence before integrating the API. Changes to identity, plan or constraints require renewed evidence. This task includes no live application test, credential use, provider readback, restore, release of HOLD or production approval.
