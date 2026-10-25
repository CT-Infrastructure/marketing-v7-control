# Dispatch and GitHub projection

Do not assign the entire backlog to all agents. A single trusted coordinator selects ready task keys, atomically reserves resources and scope, resolves remote issue URLs and creates one immutable packet per attempt. Use each runtime's actual supported agent-launch facility or the configured adapter; the package does not assume a vendor-specific SDK.

An issue assignment, `ready` label or project field is not an atomic lease. Confirm source graph hash and predecessor acceptance receipts immediately before launch. Graph changes invalidate affected unstarted packets; running tasks are held/reconciled before changing authority. Use one task per agent context and one result per attempt; no hidden spawn of additional agents outside the coordinator's budget.

The provider-neutral launcher starts rootless Podman containers with a trusted digest/argv. Local/offline agents can run with network none. Hosted model agents need a separately qualified adapter/network and narrow inference credential. F12 must prove actual invocation, cancellation, job-ID lookup and unknown-submission reconciliation. Provider-native async jobs require an idempotency key and receipt; a timeout cannot cause a second create request without lookup.

Update GitHub after ledger changes; retries of metadata projection must not duplicate actual work. The built-in seeder creates the initial project; ongoing projection is a coordinator/bootstrap obligation. Store remote IDs in the local administrative map, not as user-facing credentials. UI saved views are convenience, not security boundaries.

No actual GitHub repository/project or live AI workers were created when this package was generated. The initial source state is DESIGN_SPECIFIED_NOT_DEPLOYED. Package unit tests and mock concurrency demos are not evidence of runtime marketing acceptance.
