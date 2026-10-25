# ADR-003 — Separate code from operational readiness

CODE_MERGED: independently reviewed implementation/test artifacts merged at an immutable revision.
SANDBOX_QUALIFIED: isolated fixtures/native test services demonstrate the stated boundaries at that revision. Mock-only results disclose the limitation.
STAGING_QUALIFIED: actual chosen stack, topology and permitted provider test accounts pass relevant acceptance cases with attributable evidence.
PRODUCTION_APPROVED: named authorized human approves the precise revision/digests, target, channel, limits and expiry after staging/recovery evidence.

Original acceptance IDs remain in the traceability table. Some source cases require real carrier/DNS/device/site access; mark NOT_RUN until actually exercised. A verification issue can accept an explicit sandbox evidence level while carrying those operational cases to its human gate. No lower evidence level is represented as a higher one. Gate non-applicability requires a human recorded disposition, not a skipped test.
