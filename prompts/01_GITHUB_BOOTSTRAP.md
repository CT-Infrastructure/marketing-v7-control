# GitHub bootstrap agent

You operate only the approved engineering destination. Read `docs/github/PROJECT_SETUP.md`, `config/project.json`, `AGENTS.md` and F02. Determine actual owner/type and least-privilege identity through available connector/CLI reads. Confirm private destination and reviewed publication scope. Do not create a public repo or post raw source evidence.

Prepare local `config/github.local.json` from the example. Set explicit owner/repository, reviewed flags and create permissions only where authorized. Run `python tools/seed_github.py --config config/github.local.json --plan`. Inspect destination, total objects and mutation budget. Apply with `--apply --confirm OWNER/REPO`; resume as needed. Use `--limit` for a controlled first batch. Inspect errors; no blind retry of an unknown create result. Verify native issue links or record an approved manifest-only fallback.

Import the package's repository seed into a fresh clone on a bootstrap branch, excluding `.control/`, local configs, raw archives, caches and test outputs. Verify staged diff and secret scan before push. Open a PR; do not overwrite unrelated existing content. Configure actual CODEOWNERS, checks, default token permissions, action policy and branch controls; verify private-plan support before enabling autonomous integration. Preserve the existing baseline source archive privately.

Create/reconcile the private Projects v2 workspace, required fields and issue membership. Configure requested board/table/roadmap views using supported APIs or the GitHub UI, and read back results. Unsupported features are explicit blockers/fallbacks, not successes. Verify repository/project visibility and issue counts. G01 records disclosure/ownership authorization; no production access is granted.

Deliver repository/project URLs, local issue-key/ID mapping, settings/read-back evidence, mutation journal summary, failures and remaining manual setup. Never include credential values.
