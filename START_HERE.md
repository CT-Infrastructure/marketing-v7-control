# Start here — Marketing V7 GitHub Agent Package

**Release:** 2026-10-25 · prompt/engineering seed revision 1  
**Scope:** Create a private GitHub repository and Projects v2 workspace, seed an agent-ready backlog, then coordinate parallel engineering under explicit trust boundaries.  
**Current state:** Package and local control logic tested. No remote GitHub project, production deployment or real AI worker has been created by preparing this package.

## Give this to the coordinating agent
Attach/extract this entire package, not just the prompt. Then send:

> Read `prompts/00_MASTER_ORCHESTRATOR.md` and carry out that assignment using this package as the source of truth. Create the approved private GitHub repository and project, reconcile all 785 issue records, and coordinate the maximum useful number of parallel agents permitted by the dependency graph, isolated work scopes, measured hardware and provider/cost budgets. Preserve V7 application ownership. Do not invent GitHub ownership, credentials, provider capabilities, hardware facts or approval evidence. Begin with a local validation and GitHub plan; obtain only genuinely missing destination/access authorizations. Keep production effects disabled. Do not stop after creating issue titles: preserve each complete brief, referenced source pack, acceptance IDs, dependencies and security/container requirements. Bootstrap trusted controls under supervision, qualify the chosen worker adapter, and obtain G02 before unattended execution. Report actual results and blockers, never simulated activity as real work.

The coordinating agent must have a supported GitHub tool/CLI and an actual agent-launch capability. This package does not grant those permissions or select an unapproved external provider. Missing credentials are provided through an approved broker, never pasted into an issue or prompt.

## 1. Inspect locally — no network or live agents
From the extracted directory, using Python 3.10 or later on Linux/macOS for the tools that use POSIX file locking:

```sh
python tools/validate_package.py
python -m unittest discover -s tests/package -v
python tools/demo_parallel.py --workers 12
python tools/seed_github.py --plan
python tools/coordinator.py plan
```

The demo executes 24 synthetic jobs and labels them synthetic. The actual launcher additionally requires rootless Podman, cgroup v2, a qualified digest-pinned agent image, explicit authorization and independently enforced network/quota/provider limits. Native host/firmware components use their own exception paths; do not run them in privileged agent containers.

Open `ISSUE_BROWSER.html` for offline search across all complete issue briefs. Open `README.md` for the inventory and `diagrams/PNG/O01.png` for the orchestration overview.

## 2. Create GitHub resources through an authorized bootstrap
Follow `prompts/01_GITHUB_BOOTSTRAP.md` and `docs/github/PROJECT_SETUP.md`. Copy `config/github.example.json` to untracked `config/github.local.json`. Supply the real owner, repository name, owner type, optional existing project number, disclosure review and explicit create flags. A private destination is mandatory in this package. Retain the source archive privately; do not upload it wholesale.

```sh
python tools/seed_github.py --config config/github.local.json --plan
python tools/seed_github.py --config config/github.local.json --apply --confirm OWNER/REPOSITORY
```

Replace `OWNER/REPOSITORY` with the approved exact value. Authenticate `gh` separately with the least permissions needed; never put a token on the command line. The importer is incremental and deliberately pauses at the write budget. Rerun after the budget permits, retaining the same private journal. It checks existing markers and IDs before creating objects. An uncertain write pauses for read-back; use `tools/reconcile_import.py --help` only after a trusted operator has verified remote state. A pause is not completion.

The importer creates/reconciles repository metadata, labels, milestones, issue bodies, native sub-issues/dependencies, a private project and its fields/items. It **does not** push source, activate rulesets, install code owners, create saved views, authorize production, merge PRs or start agents. Those are explicit bootstrap tasks with read-back evidence and capability checks. Seven saved-view specifications and the policy templates are included.

## 3. Start real parallel work only after qualification
F01–F20 establish interfaces, security, test fixtures, capacity, agent adapter, merge controls and evidence policy. Bootstrap them through individually authorized supervised work. G02 authorizes unattended dispatch only after those controls are qualified. This breaks the bootstrap loop without allowing an agent to approve itself.

Copy `config/orchestration.example.json` to an untracked local config and fill measured, approved values. Defaults intentionally reject live execution. The reference launcher is single-host and CPU-only; GPU tests and remote workers require the separately qualified adapter described in F12. `max_workers: 12` is an example ceiling, not a hardware recommendation or guaranteed concurrency. Cost, resource and dependency limits may admit fewer jobs. Never set qualification flags merely to bypass checks.

```sh
python tools/run_agents.py --policy config/orchestration.local.json --source /approved/repository --control /private/controller-state --watch
```

The source must be a trusted committed checkout. Policy/state/broker credentials must remain inaccessible to workers. The controller starts isolated containers, validates their returned files, and moves candidates to REVIEW; it does not auto-merge or auto-accept. A qualified F13 integrator verifies independent review/CI/merge evidence and calls the trusted acceptance boundary. `tools/verify_merge.py` supplies a read-only GitHub CODE_MERGED receipt; it cannot establish native/runtime/production qualification. F18 supplies independent execution receipts. Status updates to GitHub are a trusted projection of the ledger, never the scheduler authority.

Place `STOP` in the private control directory to prevent new starts and invoke the launcher's cancellation/quarantine path. Expired/uncertain jobs retain locks until termination and external-outcome reconciliation are proven. Do not delete the ledger, reset leases or clear a STOP to skip recovery.

## 4. Treat completion correctly
A workflow BUILD and its independent TEST task can run concurrently after contracts are ready. VERIFY waits for both and required component evidence. Integration slices test combined behavior. Human G gates separately authorize specific site/channel/artifact effects. Deferred components are not installed; NOT_RUN source tests are not passing tests.

No API calls, sends, calls, ads, public content, migrations, firewall changes or destructive storage work are authorized solely by this package. All 576 inherited runtime acceptance cases begin NOT_RUN. Keep the 156 disposition, 104 recovery and 69 routing evidence records traceable through their private source hashes.
