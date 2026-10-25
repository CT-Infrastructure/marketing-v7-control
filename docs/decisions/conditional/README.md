# F19 conditional technology decisions

This is a decision policy and offline register, not installation or deployment evidence. All 40 source selection tasks CP099–CP138 remain DEFERRED, disabled, unselected and uninstalled. No graph, shared contract or source file is changed. Baseline alternatives are planning references, not verified installed site facts.

`register.json` preserves task identities, source classifications, functions, workflow associations, exact Section 2 table rows, adoption triggers and baseline alternatives. Candidate types distinguish services, native services, architectural alternatives, test CLI, desktop application, libraries, plugins, adapters, model artifacts, capacity and external providers. Compound candidates remain compound; no alternative member is selected. Source deployment mode remains conditional-no-install regardless of the interpreted candidate type.

`source_license_claim` retains the source deployment/license text verbatim where present. For example, source labels GPL-2.0, MIT and Apache-2.0 are historical source claims, not an upstream license verification. Every actual license, edition, version, dependency and model/provider rights field is UNKNOWN. The project MIT license does not relicense any third-party application, dependency, asset, model weight, dataset, font or media. An OSS-core label provides no paid feature entitlement. No current versions, digests or licenses are guessed.

`policy.json` defines adoption and rollback requirements. Unknown rights block adoption, not core baseline progress. No approval, legal review, named owner, demonstrated site gap or next review date was supplied. The register identifies accountable and unblock roles without inventing people. `recorded_on` is the record creation date; `reviewed_on`, `next_review_on` and approval references are null. The mandatory review trigger is before any selection and on material changes; a named human must set review dates and expiry when reviewing.

## Offline root execution

The original native author could not execute Python. The authorized remediation subsequently ran the validator and mutation tests with Python on Windows; current results are recorded in evidence.json. Independent acceptance remains the root controller's responsibility. Use Python 3.10 or newer with its standard library; no dependencies, installation, network, provider access or application jobs are needed. The scripts read repository source files and print results; use `-B` to avoid bytecode writes. Run against the complete exported candidate snapshot, not the output-only copy.

From the repository root, the trusted executor may run:

```text
python -B docs/decisions/conditional/validate.py
python -B -m unittest discover -s docs/decisions/conditional -p test_validate.py -v
```

The validator returns 0 only for exact 40-task source coverage, matching canonical source-blob hashes/issue bodies, faithful baseline/trigger/license claims, safe types, unknown rights and no invented approvals. Missing or malformed input fails closed. Tests include missing/duplicate/extra tasks, every candidate's attempted selection, effect flags, source tampering, baseline/trigger changes, invented license/approval and library/CLI/provider promotion to a service. These author-written tests are not independent verification. Root must record actual exit codes and evidence at the exact integrated candidate revision; a rebase requires fresh checks.

A limited PowerShell data inspection was run in the child: JSON parsing, count, row identity, deferred flags and issue-file hashes. It is not a substitute for Python validator/tests, dependency qualification or reviewer acceptance. See `evidence.json`.

## Review and reversible adoption

1. The human selection owner supplies a measured unmet need and baseline comparison, assigns an accountable person and review date, and identifies exact version/edition/artifacts. The current baseline remains usable with optional code absent or unavailable. Where a baseline cannot deliver an optional channel, leave that channel disabled/HOLD; do not claim feature equivalence.
2. Legal/security and component maintainers review authoritative rights evidence and the full dependency graph, including model/node artifacts, paid feature boundaries, DB/cache versions and native workers. Record applicable obligations and justified N/A values only in a reviewed successor record. UNKNOWN blocks selection. Source license labels cannot satisfy this step.
3. Follow the adoption list in policy.json: budget, threat model, synthetic qualification and rollback evidence, named human approval, independent review, then separately scoped controller-owned graph changes. This F19 snapshot intentionally rejects any promotion; a future selection needs a versioned reviewed successor with a qualified validator and independently tested gates.
4. Keep Activepieces as business orchestrator, Postiz Temporal internal, Mautic permission state, WordPress publication, Postiz social scheduling and native APIs authoritative. No new CRM, publisher or workflow platform. General-purpose Temporal is a separate deferred decision. Architectural voice alternatives require architecture review. No SOPS/age decryption is granted.
5. Rehearse feature-off fallback and isolated restore before scoped adoption. Hold new effects during rollback and reconcile UNKNOWN provider outcomes before any retry. Preserve receipts, audit and reservations. Snapshot rollback does not undo calls, mail, publication or spend. Host/firmware/OS services remain native where appropriate; rootless application packaging needs version-specific qualification.
6. Engineering selection and merge do not authorize production. OpenProject retains business, budget and publication approvals; applicable channel gates and trusted controller acceptance remain separate. No candidate is selected or installed by these files.

## Handoff limits

The supplied lease/fence and base/input bindings are recorded in evidence.json; the agent cannot inspect the controller ledger or Git metadata. Branch and prerequisite acceptance are trusted-launcher responsibilities, not independently verified here. No child agents, Git, network, credentials, installs or host changes were used. No shared file was edited. The result is ready for review only; Independent review/acceptance remains the root controller's responsibility.

## Exact text materialization policy

Declared source files and issue bodies are UTF-8 text whose recorded SHA256 values bind their LF source-blob bytes. A Windows checkout may materialize those same bytes with uniform CRLF endings. `canonical_text_bytes` accepts uniform LF or uniform CRLF and converts only complete CRLF pairs to LF before hashing. The conversion is reversible for uniform CRLF and does not alter any other byte. Mixed LF/CRLF, lone CR, NUL and invalid UTF-8 fail closed. Spaces, tabs, BOM, final-newline presence and content changes remain hash-significant. No arbitrary whitespace normalization, source rewrite or hash refresh is permitted.

This rule applies only inside the F19 validator to its declared textual source/evidence paths, not to arbitrary binary artifacts or the controller's original source-manifest. The original manifest remains an exact-byte snapshot receipt. Six additional regressions cover both complete LF and CRLF source fixtures, malformed endings, and hash-significant content/whitespace; the original ten tests remain. `inspect.ps1` is retained as historical limited exact-byte inspection only and intentionally does not implement checkout normalization; use the Python validator for checkout-aware validation.
