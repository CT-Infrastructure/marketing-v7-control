# GitHub repository and Projects setup

## Desired objects
One private monorepo (`marketing-v7-platform` is an editable example) and one private Projects v2 project. The package has 26 aggregation epics, 20 foundations, 147 component/provider/selection/preservation records, 570 workflow BUILD/TEST/VERIFY issues, 10 integrated scenarios and 12 human gates: 785 issues total. Use immutable package keys; remote issue numbers are assigned at import and stored separately.

Create labels, P0–P6 milestones, fields and views from `config/project.json`. Built-in GitHub Status can remain default; the custom Execution field carries the richer lifecycle. Issue/project metadata is a projection, not a scheduler lock. Native sub-issues model parentage, native blocked-by links model build prerequisites where supported. Runtime arrows remain in reference Mermaid/JSON and are not blindly imported as blocked-by relationships.

Use `tools/seed_github.py` in plan mode first. It does not push source or configure production access. Apply requires an explicit destination confirmation, reviewed source/privacy flags and a bounded mutation budget. Repo/project creation are opt-in. A subsequent bootstrap agent imports the reviewed repository seed through a PR, configures code owners and verifies account-specific protections. Do not upload the old raw ZIP or source recovery material.

## Import phases and idempotency
1. Verify authentication, owner/account and existing repository visibility; create private only when approved.
2. Create/read-back milestones and labels; inventory all remote issues with pagination.
3. Reconcile immutable markers, create missing issues and preserve human notes. Abort on duplicate markers or uncertain creation; never blindly repeat a mutation.
4. Add native parent/sub-issue and blocked-by relations using remote issue **IDs** where required, not issue numbers.
5. Create/reuse Projects v2, make private, link repository, create/reconcile fields, attach issues and populate values. Verify read-back. Issue and project operations are separately persisted; no all-or-nothing transaction is assumed.
6. Verify counts, relationships, metadata and capabilities. Configure saved views and built-in automation through supported API/UI; never claim unsupported view setup succeeded.

Create/read-back one object at a time with rate-limit pacing. Stop at the configured mutation budget and resume from the reconciliation journal. Comments/human notes survive updates. Native relationship failure is visible and normally stops apply; an explicit fallback uses local DAG plus cross-links, never pretending GitHub enforced it. Discovery of a different unrelated project with a matching title is ambiguous; require an explicit project number.

## Repository controls — explicit bootstrap deliverables
Protected default branch; disallow force-push/deletion; independent review and code-owner review for protected paths; stale approval dismissal; trusted required checks; restricted action allowlist; read-only default token; secret/vulnerability scanning as available; actual human security contact; private access audit. Verify plan support. Production environments stay without credentials until relevant G gates are approved.

The seed includes a working package-validation workflow with a verified full action SHA, issue/PR templates, Dependabot Actions configuration, and a CODEOWNERS template. Additional service-native checks are backlog work, not falsely represented as already implemented. `ruleset.template.json` is a reviewable payload, not automatically enforced.
