# F01 source custody

The canonical incoming package is Marketing V7 GitHub Agent Package, revision
1, dated 2026-10-25. Its complete original file manifest is preserved in
PACKAGE_MANIFEST.json. This directory records source custody and disclosure;
it does not assert deployment or runtime qualification.

source-register.json contains all 190 workflow IDs, 147 component IDs, 576
acceptance IDs and 329 opaque legacy references. Those legacy references
represent 156 service-disposition rows, 104 recovery rows and 69 route rows.
Their source hashes are retained. Raw inventories and the original source ZIP
are not present in this repository, and their contents were not independently
verified. Missing access is not evidence that a source system is absent.

file-classification.json binds each of the 1,290 original imported paths to its
SHA-256 and disclosure category. Additional implementation and policy files
are separate changes in Git. The owner explicitly selected public repositories
and MIT licensing; third-party notices remain applicable. Raw source archives,
private inventories, credentials, controller state and local configuration
remain outside public Git.

Precedence is the owner's explicit current instructions, the integrated V7
clarifications, retained V7 selections and safeguards, then older references.
GitHub owns engineering; OpenProject retains business and publication approval.
Activepieces and Postiz's internal Temporal retain runtime orchestration.

Run `python3 docs/provenance/verify_intake.py`. It compares immutable Git blobs
against the incoming manifest, checks identity coverage and confirms that all
source acceptance cases still start as NOT_RUN. Its PASS means source custody
only. It does not grant a human gate, accept a foundation task, or authorize a
production effect.

Git normalized CRLF line endings in four CSV inputs. git-normalization.json
records their committed hashes. Verification reverses that exact newline-only
transformation and checks the original byte lengths and SHA-256 values; the
other 1,286 original blobs must match byte for byte. No original source hash is
silently replaced with the committed representation's hash.

## Verification boundaries and regression checks

The trusted integrator runs the Git-backed command above at the candidate
revision. The original 1,290 manifest entries must exist exactly once; unsafe
or duplicate paths are rejected before constructing Git batch requests.
Classification hashes and byte counts, reversible-normalization metadata,
source identity uniqueness, each legacy category count, complete NOT_RUN trace
coverage and the copied provenance record are checked against source bytes.
The incoming manifest remains a custody baseline, not an independent signature
or proof of the absent archive's contents. Disclosure categories record the
intake decision; automated byte checks do not perform semantic secret review.

Run `python -B -m unittest discover -s docs/provenance -p 'test_*.py' -v`
for 25 synthetic fixture and mocked-wrapper tests. They exercise malformed, duplicated, missing,
modified and falsely promoted inputs without Git, network access, historical
scripts or runtime execution. They test verifier behavior, not acceptance of
this implementation by an independent reviewer. The exported snapshot can be
checked through `validate_custody` and `validate_register`; this does not prove
Git revision identity and must be labeled EXPORTED_SNAPSHOT_CUSTODY_ONLY.

Default custody metadata (classification, normalization and source register) is
loaded from the same captured immutable Git revision as the manifest and source
blobs. The result includes each metadata path, commit, SHA-256 and byte count;
dirty or stale working files cannot change that result. `--classification PATH`
is an explicit external test input: its resolved path, byte count and SHA-256
are reported without a commit attribution, and the result scope becomes
MIXED_INPUT_SOURCE_CUSTODY_ONLY. Its bytes still undergo custody validation.
The tested_commit then identifies only the Git inputs, not the external file.
Mocked wrapper tests exercise these boundaries without invoking Git; the trusted
integrator must still exercise actual Git transport at the committed candidate.

Before deriving the inventory, the verifier checks the raw PACKAGE_MANIFEST.json
bytes against fixed SHA-256
`c7b6564a2e4113abb25ae3bfad15f9f7a862879e8da62f5b31f2bef4c8c859a7`,
supplied by the trusted controller intake source manifest. The candidate revision
cannot redefine that baseline by changing both inventory and classification.
Even semantically equivalent reserialization requires a separately reviewed
baseline update; the verifier provides no candidate-controlled digest override.
