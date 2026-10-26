# F20 source and dependency reconciliation

This is an offline audit of the frozen source at `30f56e90e1fc103eaf0491838b53ba07f9ab732c`, including the supplied F04/F05 material. Local source coverage is complete; runtime qualification and remote import are separate. The coordinator reports only 210 managed remote issues, against 785 local source issues. This tool makes no API request and cannot refresh that count or claim the remote import complete.

Run from the repository root:

```text
python -B docs/traceability/audit.py
python -B docs/traceability/test_audit.py
```

The first command emits deterministic JSON. `coverage-report.json` is its checked source snapshot, not an execution receipt. The test suite is supplied for the independent executor; author-side test execution is not claimed. Only the standard library is used. Inputs are read-only, and neither command touches a graph, a lease, a controller, a remote service, or credentials. Source files are verified against `source-hashes.json`, and all 785 issue bodies against their catalog digests. The frozen manifest also enumerates all 190 individual workflow JSON files and all 215 individual/shared Mermaid files (405 artifacts); missing, mutated or omitted artifacts fail source loading. Duplicate acceptance-review IDs are rejected before any route lookup. Only reversible uniform CRLF checkout conversion is accepted; source hashes never mean reserialized JSON.

The validator checks all 190 BUILD/TEST/VERIFY triples, 147 component records, all 576 original acceptance IDs, 785 issues and their repository routes, and the complete 759-task DAG. It rejects duplicate/orphan IDs, wrong-stage acceptance routes, issue/task drift, missing VERIFY prerequisites, cycles, epic prerequisites and human-gate prerequisites for ordinary engineering. Test authoring cannot be blocked by workflow implementation. The 1,847 runtime edges are checked independently for valid endpoints/types; feedback remains valid runtime structure and never becomes a build prerequisite.

## Evidence distinctions

Original annotations remain **564 NOT_RUN plus 12 OPEN_SOURCE_BLOCKER**. All **576 runtime checks remain unexecuted**. The generated traceability file's 576 NOT_RUN values do not erase those 12 source blockers or prove qualification.

The source includes 88 acceptance rows whose original selector is a baseline or range rather than a single workflow. `acceptance-routing-review.json` preserves each exact original selector and existing destination. These are routed locally, so there are no orphan IDs, but the destination semantics require review. They are not silently represented as original exact workflow matches. The audit rejects a changed route until the versioned review mapping is updated through review.

## Component ownership and unresolved consumer contracts

`component-contracts.json` is one compact mapping for all 147 components. Its engineering owner is the exact existing CP issue, not an invented person or operational account. A small set of native application boundaries cites the normative authorities table in `reference/architecture/Integration_Contracts.md`. Other component contracts explicitly await their component issue owner. All source `supports_workflows` lists remain **source-declared, not consumer-confirmed**: old substring matches cannot establish an interface, a hard prerequisite, or deployment evidence.

Every component has an explicit reviewer issue and pending consumer list in `coverage-report.json`. Reviewers must determine the actual producer/consumer operation, native API or artifact boundary, schema/version, authentication scope, idempotency/replay behavior, failure/UNKNOWN reconciliation, acceptance evidence, and whether dependency completion is truly required for BUILD, TEST, or VERIFY. Components with no declared workflows still require review; an empty substring result is not proof of no consumer. Native parent and conditional classification are preserved exactly. Conditional selection is not installation.

The twenty independently assigned workflow-review groups remain separate dossiers. This package does not duplicate or assume their conclusions. Their source-bound receipts can inform a later reviewed mapping revision; pending rows are deliberately not upgraded by heuristic name matching.

## Proposed follow-up, not active graph changes

No graph amendment is justified solely by substring association. Review the 88 baseline/range acceptance routes and the 147 component consumer contracts first. For any substantiated hard-prerequisite change, record exact before/after edge, source/contract evidence, rationale, affected task closure and validation results; submit it to the trusted controller for review. The controller must invalidate/reconcile affected active leases before applying a changed graph or input hash. This audit neither invalidates leases nor edits the active graph. Human production authorization remains outside ordinary test writing.

## Curated source evidence

The [portable curation package](curation-public/README.md) provides explicit dispositions for all 147 components, with exact source-named workflow relations and separately identified engineering, native, deferred, legacy and external roles. Its source citations validate against the public checkout; source naming does not establish deployed ownership or runtime qualification.

This supplements the initial unresolved component table. All 28 independent source-audit findings and the proposed domain-citation/email-ordering corrections remain pending root disposition. The original registry, workflow diagrams and build graph are unchanged. Run the portable validator and tests in addition to the package audit.
