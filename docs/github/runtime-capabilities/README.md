# GitHub capability and governance snapshot

This is a bounded evidence record for F02, not approved configuration or production authority. `capabilities.json` retains the supplied commit bounds, object timestamps, source hashes, repository controls, bootstrap receipts and six verified issue mappings. Capture timestamps were not supplied. It describes the 2026-10-25 evidence only.

The user selected CT-Infrastructure and eight **public MIT repositories** with one **private project**. This supersedes the private-monorepo design in PROJECT_SETUP.md for this destination; public visibility was an explicit deployment decision, not a protection workaround. Private-repository plan capability and separate authenticated membership payloads are not established here. Existing human CODEOWNERS remain unchanged.

All eight supplied main readbacks are protected and have successful GitHub Actions `package-validation` checks at their recorded main SHAs (app 15368). Rules require one approval, CODEOWNER review, last-push approval, stale-review dismissal, thread resolution and strict required checks; deletion and force updates are blocked. Default workflow tokens are read-only and cannot approve PRs. The allowlist pins checkout to a full SHA. These are package checks, not deployed-system validation. Staging and production require CompleteDotTech and prevent self-review, but permit administrator bypass. Production credentials remain absent per the trusted task.

Bootstrap PRs used an explicit user waiver, and the review rule was restored. That waiver is bounded to bootstrap. Request Copilot review for subsequent PRs and retain its receipt; the packet does not prove Copilot enablement or a completed review. Copilot review does not satisfy required human security/production approvals. The trusted integrator must reconcile reviewer eligibility and rules before merging; never weaken controls to force a merge.

GitHub owns engineering issues, reviews and merge evidence. OpenProject owns business/editorial/campaign/budget/publication approval; Mautic contact permissions; WordPress web publication; Postiz social scheduling; ResourceSpace approved assets; Matomo website analytics; SerpBear rankings. PostgreSQL keeps separate operational ledgers. Activepieces owns cross-application runtime orchestration and Temporal remains Postiz-internal. Forgejo can only be a one-way mirror. Neither the engineering project nor this snapshot supersedes those owners.

The 785-issue import is ongoing under 300 writes/hour. Only the six supplied mappings are positively recorded here. Saved view names, filters and layouts exist per the trusted task; grouping is unverified. The supplied project workflow list excludes auto-close and PR-merged workflows; remaining workflow names alone do not prove their actions or acceptance semantics. Fields, labels, milestones, complete hierarchy and dependency readbacks require reconciliation before claiming completeness. Project status and closed issues are never acceptance receipts.

Preserve every G01–G12 gate listed in the snapshot; none is approved by this document. Completion remains candidate → independent review → exact-revision checks → trusted integration → verified receipt. Production stays disabled until separately authorized gates and native-owner approvals exist.

## Verification checklist

- [ ] Trusted owner refreshes organization access and private-plan capability if a private destination is proposed.
- [ ] Re-read all eight main SHAs, trusted check app IDs, rulesets, token policies, action pins, CODEOWNERS and environment reviewer/bypass settings at candidate review time.
- [ ] Request subsequent-PR Copilot review; retain outcome and resolve findings without substituting it for required approvals.
- [ ] Reconcile all 785 keys to unique remote IDs/numbers, labels, milestones, project fields, native hierarchy and blocked-by relations within the write budget.
- [ ] Read back saved view names/filters/layout and verify grouping in supported UI/API.
- [ ] Verify remaining workflow actions cannot imply controller acceptance; retain removed auto-close/PR-merged disposition.
- [ ] Obtain independent F02 review and exact-candidate check/merge receipts from the trusted controller.
- [ ] Keep credentials absent and obtain applicable G gate and native application approvals before any production operation.

Run `python docs/github/runtime-capabilities/verify_snapshot.py` for local consistency only. It performs no network, writes or acceptance transition.
