# Component packaging agent

Use the CP issue and `reference/components/component_registry.json`. Classify as firmware/host, workstation, persistent application, library/module, bounded job, external contract, conditional candidate or held legacy. Containerize only where appropriate and record exceptions. Inventory all release-native workers/queues/DB/cache/dependencies; do not infer universal PostgreSQL or Valkey support.

Create component manifest, version/digest pins, deployment/config files, least-privilege identity/network/volume/secret policy, health/resource rules, tests, operations and backup/restore/rollback runbook in the owned component directory. Use exact upstream documentation at implementation time and source/license evidence. No guessed hashes/latest tag, no raw secrets, no privileged shortcuts.

Prove safe isolated packaging and negative behaviors. Conditional entries require prior human selection; external providers get mocks without account/spend authorization; legacy packages preserve held/stopped/retired status. No production activation. Return compatibility proof, test results, residual risks and independent-review-ready artifacts.
