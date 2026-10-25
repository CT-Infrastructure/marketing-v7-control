# Supply-chain locks and adoption policy — 1.0

F09 supplies an offline contract and held inventory, not a production bill of materials or a deployment approval. `locks/supply-chain.lock.json` preserves all 147 entries from `reference/components/component_registry.json`, including exact names, classification and placement. Each component remains UNSET or DEFERRED. A COMPONENT entry is a planning placeholder, not a pinned artifact. Child artifacts must be added for the exact chosen OS packages, applications, OCI platforms, models and custom nodes; dependency IDs link those artifacts. Missing transitive dependencies must be resolved before release review. No conditional, external or legacy component is silently promoted.

Two additional entries record observations supplied by the trusted F09 packet: actions/checkout at `3d3c42e5aac5ba805825da76410c181273ba90b1`, and Codex Windows 0.164.0 binary SHA-256 `6f267830b029ee25d9339864aa867cd45de9f8fd4c5ea007d2e63c13a0c66d36`. These are engineering observations. This worker did not download or independently measure those artifacts, infer their architecture/license, generate their SBOM, or assess their current vulnerabilities. Their adoption diagnostics remain held. No pending Podman or other new pin is included.

## Authority and source fidelity

This policy implements `backlog/issues/F09.md`, `docs/security/THREAT_MODEL.md`, `docs/security/CONTAINER_AND_HOST_BASELINE.md`, `docs/security/CREDENTIALS_AND_CI.md`, and the execution protocol. Source placement is retained: firmware/host services stay native; CLI tools, libraries, model weights and custom nodes do not become permanent services; application workers are container candidates only where supported. Mautic native queues and Postiz Temporal remain application-owned. Component selection is not a supported-version or vulnerability statement.

Only the central lock owner/integrator may prepare and merge a lock update with independent human code-owner review. Component workers propose scoped artifact evidence without editing shared locks. No bot may bulk-refresh pins, follow floating tags or overwrite another worker's proposal. GitHub engineering approval is separate from OpenProject business/production authorization. This module has no network, installation, execution, credential or deployment authority.

## Typed artifacts and provenance

The manifest schema rejects unknown fields. `validate_manifest()` additionally verifies the source registry hash, complete inventory, exact source metadata, unique artifact IDs, dependency existence/acyclicity, conditional holds, scan-kind coverage and strict digest/type consistency. All unknown facts use the literal `UNSET`; omission, invented placeholders or a mutable tag cannot stand in for a pin. `latest`, moving branches and version ranges are forbidden. State CANDIDATE is a proposed review state, never proof of readiness.

| Artifact type | Required evidence before adoption review |
| --- | --- |
| OCI | Exact registry/repository, release, per-platform SHA-256 digest and architecture; index-to-platform mapping if multi-arch; build provenance and image SBOM for that digest |
| OS_PACKAGE | OS/distribution/repository snapshot, package name/version/revision/architecture, downloaded package SHA-256, signed repository/package verification and dependency closure |
| APPLICATION / TOOL | Immutable release artifact SHA-256, origin/edition/platform, upstream verification and all runtime/transitive dependency locks |
| ACTION | Owner/repository/path plus verified full 40-hex commit, matching git-sha1 digest, reviewed action code and transitive dependency closure |
| COMFY_NODE | Exact repository/40-hex commit and matching git-sha1, transitive package locks, isolated import test, license review and runtime installation disabled |
| MODEL | Exact checkpoint/tokenizer/config/auxiliary files and SHA-256s, source identity, model/weight license and use/redistribution rights reviewed for the actual workload |
| COMPONENT | UNSET planning record only; cannot establish artifact adoption |

For every fetched artifact, the trusted acquisition lane records upstream URL/object identity, exact bytes and digest, verification command/tool version, signer/certificate/issuer and expected identity, timestamp, verification output and verifier identity. Verify that signature/attestation subject equals the locked digest and issuer/workflow identity is approved; a signature alone is insufficient. Reject mismatched, missing or unverifiable provenance. Store redacted evidence references; never embed tokens or private topology. No artifact is fetched by this module.

License fields are unresolved unless an actual source/edition/license text and relevant dependencies were reviewed. `LicenseRef-Synthetic-Test` appears only in a labeled test fixture and is not an upstream license conclusion. Model rights require explicit review; ordinary applications also require an evidenced rights disposition. UNKNOWN license/model rights/provenance block adoption and cannot be exceptioned away. Runtime node downloads/manager auto-install, unpinned checkpoint replacement and mutable tag pulls are prohibited.

## Scanning and SBOM workflow

1. The trusted build/acquisition lane produces the exact immutable subject in a disposable, restricted environment. Generate SPDX or CycloneDX SBOM from those bytes and dependency locks, including native workers, libraries, OS packages, model files and custom nodes. Record SBOM SHA-256 and subject digest; a component list is not an SBOM.
2. Scan that same subject using the approved pinned Trivy binary/config and offline vulnerability database snapshot. Record tool release/hash, database digest and timestamp, scope, command, exit status, output hash and every finding. Run the approved secret scanner over source, generated files and release artifacts with full redaction. Never let a scanner fetch/update databases during an offline run. A missing database or unsupported scanner is NOT_RUN, not PASS.
3. Categorize findings with exact artifact digest, package/file/rule/CVE, severity, affected/fixed version where verified, and redacted evidence. Unknown severity/fix remains unknown. Exposure/credential findings stop publication and go to the configured private owner; revoke/rotate at the authority, review access, rebuild and rescan. Removing a string does not undo exposure. Synthetic test-data findings stay visible and labeled, never suppressed globally.
4. Resolve findings by a centrally reviewed patch/rebuild/new lock proposal and rerun regression tests plus both scans on the new digest. If a vulnerability cannot yet be fixed, use the exact expiring exception process below. A PASS with findings is contradictory; scans with unknown metadata, mismatched subject, future time or age greater than 24 hours remain held.
5. Independent reviewer checks the evidence chain and tests at the exact candidate revision, verifies the original scan reports and identities, then the integrator promotes the same reviewed bytes. Rebuilding later requires new evidence. Rollback pins and state/reconciliation procedure are reviewed before adoption; old pins are retained until rollback retention requirements are met.

The 24-hour scan freshness ceiling and 30-day maximum exception duration are proposed version-1 local policy choices, not vendor promises. Changing either requires central review. Actual vulnerability reports remain necessary even when a dependency has an upstream signature.

`adoption_blockers(entry, now, exceptions)` performs structural diagnostics with explicit UTC time and revalidates exception fields. An empty list means only that the supplied claims are internally complete. It does not verify reports, signatures, human identity, runtime compatibility, dependency completeness, license truth or production authorization. The trusted integration boundary must independently verify those facts and verify every dependent artifact before adopting anything. Do not wire an empty list directly to deployment. All shipped inventory records have blockers.

## Expiring vulnerability exceptions

`locks/exceptions.json` begins empty. An exception proposal binds one entry ID, exact digest, vulnerability scanner kind and observed finding ID. It includes accountable owner, different independent reviewer, reason, compensating controls, approval/evidence references, issue and expiry timestamps. Only an authenticated authorized owner/reviewer can approve the proposal outside this schema; string references alone never prove approval. The validator rejects mismatched scope, unobserved findings, missing evidence, same owner/reviewer, future/expired exceptions and durations over 30 days. Expiry is exclusive. Revoked/proposed records never waive a finding. Active exceptions must be revalidated at release time and on every new digest; never carry them forward by package name.

No exceptions waive secrets, unknown pins, license/model rights, missing provenance, missing scans/SBOM, or conditional selection. One vulnerability waiver cannot clear another finding or a secret finding. Expired records are retained in the reviewed evidence history, removed from the active exception document through central review, and block release until fixed or newly reviewed. No active exception is created here.

## Actions and workflow lockfile preview

Full SHA pinning is mandatory independently of any workflow lockfile feature. Verify action commit provenance, nested actions, downloaded scripts/binaries and dependency locks; disable credential persistence and preserve least-privilege permissions. The existing workflow comment is not security evidence. Optional Actions dependency-lockfile preview/platform support is `UNVERIFIED_HOLD`: availability, exact semantics, supported runner/repository plan and enforcement must be verified in a separate authorized task. Do not generate a guessed lockfile, enable preview, loosen SHA pins, or treat absence as permission to float dependencies.

## Local validation and actual evidence scope

Run `python -B policies/supply-chain/validate.py` and `python -B policies/supply-chain/test_supply_chain.py`. The supplied negative mutations exercise moving versions, malformed digests, missing license/provenance/SBOM, stale scans and missing rights. Tests also cover registry drift, incomplete/duplicate inventories, conditional promotion, mismatched scan subjects, full Action/node commits, dependency cycles, exact exception binding and expiry. Synthetic scanner records are explicitly fixtures, not scanner results.

For this task only, locally available Gitleaks 8.30.1 was run offline with bundled default rules, full redaction, no allowlist and `--ignore-gitleaks-allow`, separately over `policies/supply-chain/` and `locks/`. Both exited 0 with zero findings. The exact executable SHA-256, commands, targets, config hash, report hashes and logs are in the F09 output evidence. This result covers only those source directories, not dependencies or production artifacts. Scanner binaries are observed local tools, not new adopted runtime pins.

Full-repository scanning, Trivy vulnerability analysis, runtime artifact scanning, SBOM generation, provenance signature verification and model/license verification are NOT_RUN. A local Trivy executable was discovered, but no approved artifact/database snapshot was supplied or used. No network, installs, host changes, production operations, Git changes or scan-based production approval occurred.

## Registry checkout bytes

`source_registry_sha256` remains the SHA-256 of the immutable LF source registry bytes. Only the declared `reference/components/component_registry.json` receives checkout handling: the validator reads its bytes once and accepts LF bytes or a uniform CRLF materialization that reversibly converts to exactly those LF bytes. It hashes the recovered bytes before parsing the same bytes. It does not hash reserialized JSON or normalize whitespace, encoding, BOM, lone CR, or mixed line endings. Content changes and every other transformation still fail the unchanged source digest. This local checkout handling does not replace F01 raw Git-blob custody verification and does not alter registry files or the lock digest.

## Exact package versions and shared exception diagnostics

OS_PACKAGE release values accept native exact versions beginning with a digit, including Debian epoch, revision, and tilde pre-release syntax (for example `2:1.2.3~rc1-1`). Range operators, whitespace, wildcard versions, and moving release names remain rejected; other artifact kinds retain their existing stricter release rules. Artifact digests remain required for adoption.

Call `validate_exceptions` with the complete manifest at the integration boundary before per-entry diagnostics. `adoption_blockers` checks the shared document structure, filters exceptions by the current entry ID, then revalidates all matching digest, finding, reviewer and time bindings. Other entries' valid exceptions cannot waive current-entry findings. The CLI performs full-manifest exception validation and captures current UTC once for both expiry and freshness checks. Fixed timestamps are confined to tests. Qualified scanner `latest` references remain unpinned.

The follow-up exact-release check examines the terminal version/tag of qualified non-OS artifact and scanner references. It rejects wildcard components (`1.x`), unions (`1.2||2.0`), range operators and moving terminal tags such as `registry/repo:stable` or `registry/repo:main`. Concrete prerelease identifiers and full SHA references remain accepted. Both vulnerability and secret scanner versions are checked at the manifest boundary and remain explicit adoption blockers in per-entry diagnostics. Native OS_PACKAGE exact-version handling, including Debian tilde revisions, is unchanged.
