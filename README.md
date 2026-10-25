# Marketing V7 — GitHub and Parallel-Agent Delivery Package

**Start with [START_HERE.md](START_HERE.md) and the [master prompt](prompts/00_MASTER_ORCHESTRATOR.md).** This is a self-contained engineering handoff, not evidence that V7 applications are installed or that any live agent has been launched.

## Deliverables

| Area | Included |
|---|---|
| GitHub backlog | 785 complete issue briefs; stable keys; hierarchy; dependency graph; labels; milestones; Projects v2 fields and view specifications |
| Workflows | 190 BUILD + 190 independent TEST + 190 VERIFY issues, each linked to source behavior and Mermaid |
| Components | 147 records: 89 component packages, 40 conditional selection tasks, 9 preservation tasks, 9 external-provider tasks |
| Delivery controls | 20 foundation tasks, 10 integration slices, 12 non-agent human gates and 26 aggregation epics |
| Source coverage | All 190 original workflows, 147 component records, 576 acceptance IDs, 329 private-evidence row references and 215 original Mermaid diagrams |
| Agent roles | Coordinator, bootstrapper, implementer, test author, verifier, security reviewer, integrator, operator, incident repair, component builder and conditional selector |
| Parallelism | Acyclic build graph; critical-path priority; atomic leases; fencing; prefix-aware path locks; resource/spend admission; isolated snapshots; crash quarantine |
| Repository seed | AGENTS, SECURITY, contribution/PR/issue templates, protected-owner template, read-only pinned CI, dependence updates and schema templates |
| Container security | Rootless Podman/Quadlet guidance; native exceptions; digest pins; UID/volume/secret/health/resource/backup contracts; bounded agent launcher |
| Inspection | Offline searchable issue browser, three new Mermaid/PNG/SVG orchestration diagrams and package test evidence |

**785 records do not mean 785 parallel agents.** Epics aggregate; human gates never dispatch; optional tasks stay deferred. The scheduler fills the ready frontier up to measured resource, provider, path and cost limits. It does not promise globally optimal packing or unlimited parallelism.

## Directory map

```text
prompts/                 role prompts and master orchestration assignment
backlog/issues/          785 importable, self-contained issue briefs
backlog/                 issue catalog and source/acceptance traceability
orchestration/           reviewed engineering build DAG
reference/               V7 source specifications, component registry, 215 Mermaid sources
config/                  explicit non-secret, disabled-by-default example policies
schemas/                 task result, evidence and event contracts
templates/               Quadlet and Containerfile starting points, not deployed services
tools/                   importer, scheduler, launcher, merge verifier, local tests/rendering
.github/                 repository policy and safe validation scaffold
docs/                    architecture decisions, threat model and operating instructions
diagrams/                three new orchestration maps in Mermaid, PNG and SVG
evidence/package/        actual local package test and synthetic-run reports
third_party/             licensed local Mermaid renderer and notices
```

## Read the artifacts at the right level

`backlog/issues.json` includes issue content hashes and complete metadata. `orchestration/task_graph.json` contains 759 non-epic records, including manual/deferred records; it is the scheduling authority after review. Runtime loops in `reference/workflow_catalog.json` are not build blockers. GitHub hierarchy is a reporting view, not the scheduler.

Source crosswalk rows are represented by opaque IDs and hashes. Raw private inventories, historical disk/recovery dumps and the original archive are deliberately excluded. Issue agents have all design context; site-specific evidence still requires authorized intake, not invention.

## What is executable now versus assigned work

The bundled Python tooling supports offline validation, a synthetic concurrent scheduler exercise, guarded GitHub metadata import, local scheduling, a disabled-by-default provider-neutral Podman launcher and read-only GitHub merge verification. Local tests cover these control boundaries. It does not include an already-qualified agent vendor image, distributed scheduler, full trusted Git integrator, production rollout, or completed implementations of the 190 business workflows. Those are explicit tasks and qualification gates rather than hidden assumptions.

GitHub account features, API permissions and agent-provider capabilities must be verified for the actual destination. Private repository protections must not be bypassed by making the repository public. See [sources](docs/SOURCES.md) and [validation](evidence/package/VALIDATION.md).

## Authority

GitHub owns engineering for this repository. OpenProject retains business/editorial/campaign approval. Activepieces retains cross-application runtime orchestration; Postiz's Temporal remains internal. Mautic remains contact/consent authority with its supported native database. No new mandatory business platform or wholesale replacement of the V7 stack is introduced.
