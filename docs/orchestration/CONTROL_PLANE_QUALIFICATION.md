# Trusted-control-plane qualification and remaining adapters

## Trust boundary
`Scheduler.accept` is an internal trusted-control-plane API, not an endpoint for agents. Its caller must independently verify evidence. The reference launcher never calls it. Workers cannot access the ledger or controller files. A flag inside agent output is not approval.

`tools/verify_merge.py` performs read-only GitHub queries and validates the explicit repository/base/head, task/input binding, complete file scopes, approved exact-head reviews, successful named checks from trusted numeric App IDs, and merge ancestry. It returns CODE_MERGED only. It neither merges nor marks work accepted, and it rejects verification, integration, conditional-selection and manual-gate tasks as unsuitable for PR-only qualification.

F13 must implement/qualify the trusted file-to-PR integrator, candidate-to-issue binding, exact reviewed revision, merge serialization and verified receipt ingestion. F18 must qualify the independent executor evidence path. G02 must be an authenticated human approval, not a self-approved model decision. No interface treats a user-edited issue comment or generic uploaded JSON as an authenticated receipt.

## Supervised bootstrap
Before G02, trusted operators perform individually authorized foundation work in isolated scopes. Record source revisions, commands, independent reviewers and proof outside worker mounts. Import supervised results through an operator-reviewed ledger transition only after prerequisites are accepted; never directly modify SQLite while workers are active. F11 owns the audited bootstrap/import transition. This is explicitly assigned engineering work, not an unimplemented step disguised as an enabled feature.

## GitHub importer recovery
The importer persists pending mutation intent. A crash, timeout or GraphQL error blocks further writes. On restart, successful read-back of a stable marker/relationship adopts it. When an update/private-project/field mutation cannot be automatically reconciled, a trusted operator inspects its exact remote result and preserves a private read-back file. `reconcile_import.py` requires exact target, operation key, evidence hash and operator identity before releasing that intent. It is an explicit human trust operation, not an automated verifier. Never use it just to suppress an error. The next import rediscovers objects; it does not assume issue numbers or copy stale state from another destination.

## Distributed and provider-specific agents
The included real launcher manages local CPU-only Podman jobs with a trusted file protocol. No provider binary is assumed. A custom/native agent adapter must enforce provider RPM/TPM, budget ceiling, cancellation, process/outcome IDs, denied network paths, disk quotas and context/secret isolation. A remote provider timeout may leave a remote job alive; quarantine until explicit reconciliation. GPU tasks require a different qualified launch adapter. A single-host SQLite coordinator is not distributed consensus or high availability.

## Operational projections
F17 projects verified controller states to GitHub Project fields using a metadata-only broker. The importer only seeds initial values and deliberately avoids overwriting live status. Poll/read-back independently; the controller remains authoritative. A merged issue can remain open until its evidence requirement is accepted. The product's runtime OpenProject approvals are separate from engineering issue state.

The integrator also refreshes the trusted source checkout after acceptance. The launcher checks that each accepted prerequisite revision is an ancestor of its selected immutable base; it does not claim that a local stale HEAD is current main. Missing commits hold dependent dispatch until the trusted source is reconciled.
