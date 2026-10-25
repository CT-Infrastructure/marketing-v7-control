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
