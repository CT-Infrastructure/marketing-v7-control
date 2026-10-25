# GitHub capability and governance evidence

This is a bounded evidence record for F02, not approved configuration or production authority. [capabilities.json](capabilities.json) preserves the historical commit bounds, object timestamps, source hashes, repository controls, bootstrap receipts and six verified issue mappings. Later readbacks below refresh only their named fields. They do not make the historical main, CI, bootstrap, ruleset or project-import evidence globally current.

The user selected CT-Infrastructure and eight **public MIT repositories** with one **private project**. This supersedes the private-monorepo design in PROJECT_SETUP.md for this destination; public visibility was explicitly chosen, not used as a protection workaround. The sanitized authenticated access readback reports CompleteDotTech, organization type Organization, enterprise plan, active admin membership and repository admin access on all eight public repositories. That payload has no capture timestamp; none is inferred from filesystem time. The observed plan/access does not prove private-repository protection behavior in an untested private destination. Existing human CODEOWNERS remain unchanged.

## Scope and dates of the supplied readbacks

| Source | Time supplied by source | Verified scope and limits |
| --- | --- | --- |
| Historical snapshot and bootstrap sources | Original object dates retained; capture times absent where originally absent | Recorded main SHAs, package checks, bootstrap and repository controls; no new global refresh |
| Environment identity readback | 2026-10-25T21:56:13.901676+00:00 | Reviewer numeric identity, self-review, branch restrictions and administrator bypass only |
| governance-access-live.json | Not supplied | Authenticated CompleteDotTech identity, enterprise organization plan, active admin membership, and eight public repository admin-access readbacks |
| project-grouping-results.json | 2026-10-25T22:11:22.421592+00:00 | By workstream view 9 grouped by Workstream; Roadmap view 10 grouped by Phase; original views 6 and 8 preserved. API readback verified; browser rendering unverified |
| private-vulnerability-reporting.json | 2026-10-25T22:23:02.008775+00:00 | Private vulnerability reporting enabled on all eight repositories, report URLs and security owner read back; zero advisories created |

Source SHA-256s and exact view/repository records are retained in capabilities.json. Earlier disabled private-reporting values in the access payload were superseded by the later reporting-specific readback. The historical `saved_views.grouping` value remains explicitly labeled as historical; current grouping API results are in `saved_views.grouping_readback`. This worker incorporated supplied sanitized evidence without making network requests.

All eight historical main readbacks are protected and have successful GitHub Actions `package-validation` checks at their recorded main SHAs (app 15368). Recorded rules require one approval, CODEOWNER review, last-push approval, stale-review dismissal, thread resolution and strict required checks; deletion and force updates are blocked. Default workflow tokens are read-only and cannot approve PRs. The allowlist pins checkout to a full SHA. These historical package checks are not deployed-system validation. Recorded staging and production settings require CompleteDotTech and prevent self-review but permit administrator bypass. Production credentials remain absent per the trusted task; no credential inventory was performed here.

Bootstrap PRs used an explicit user waiver and the review rule was restored at that time. The user subsequently selected **Copilot review and waived human code review for engineering**; the waiver is therefore no longer described as bootstrap-only. Request Copilot review for engineering candidates, retain the review/check receipts and resolve findings. This policy statement does not itself prove a completed review or authorize acceptance. It does not waive G01–G12, grant production authorization, or replace separately applicable native-owner approvals. The trusted integrator reconciles the applicable authorized review policy with actual repository controls; this documentation makes no ruleset changes.

## Private security reporting

Private vulnerability reporting is enabled on all eight named repositories. Each repository's private report URL and CompleteDotTech security-owner reference are in `private_vulnerability_reporting_readback.repositories`. Use the corresponding repository's `/security/advisories/new` route for private reports; do not place vulnerability details, credentials or personal data in public issues. Enabling/report-URL verification created no advisories and does not establish response-time guarantees, completed triage or upstream software security.

## Ownership and F02 scope

GitHub owns engineering issues, reviews and merge evidence. OpenProject owns business/editorial/campaign/budget/publication approval; Mautic contact permissions; WordPress web publication; Postiz social scheduling; ResourceSpace approved assets; Matomo website analytics; SerpBear rankings. PostgreSQL keeps separate operational ledgers. Activepieces owns cross-application runtime orchestration and Temporal remains Postiz-internal. Forgejo can only be a one-way mirror. Neither the engineering project nor this snapshot supersedes those owners.

F02 concerns governance capabilities and their evidence. The **785-issue import remains separate unfinished program work**, operating under the recorded 300 writes/hour budget; it is not a prerequisite for this bounded governance candidate and is not claimed complete. Only the six supplied original issue mappings are positively recorded here. Full hierarchy, labels, milestones, fields and dependency completeness require that separate reconciliation. Grouping for the two replacement views is now API-verified as scoped above; browser rendering remains unverified. The supplied historical project workflow list excludes auto-close and PR-merged workflows; other workflow names alone do not prove their actions or acceptance semantics. Project status and closed issues never replace acceptance receipts.

Preserve every G01–G12 gate in the snapshot; none is approved by this document. Completion still needs the authorized candidate review, exact-revision checks, trusted integration and verified receipt. Production stays disabled until its separately authorized gates and native-owner approvals exist.

## Remaining verification

- Re-read all eight main SHAs, trusted check app IDs, rulesets, token policies, action pins, CODEOWNERS and environment settings when judging a new candidate; the newer scoped readbacks do not refresh them.
- Retain subsequent engineering Copilot reviews and check/merge receipts under the user's engineering review policy. This candidate cannot accept itself.
- Verify browser rendering if visual grouping acceptance is needed; the two group-by configurations already have API evidence.
- Continue full import/hierarchy/dependency reconciliation separately without holding this governance candidate to unrequested program completion.
- Verify remaining workflow actions cannot imply controller acceptance; retain the recorded removal of auto-close/PR-merged workflows.
- Keep credentials absent and obtain applicable G gates and native application approvals before production operations.

Run `python -B docs/github/runtime-capabilities/verify_snapshot.py` for historical-snapshot consistency and `python -B docs/github/runtime-capabilities/test_verify_snapshot.py` for adversarial regressions. These perform no network access or acceptance transition. The verifier checks exact main-SHA shape before equality and requires exactly two distinct expected environment records; it does not authenticate the newly supplied readbacks or make live claims.
