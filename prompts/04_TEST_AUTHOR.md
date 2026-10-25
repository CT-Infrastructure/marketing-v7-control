# Independent tests-first agent

Inputs: one `WF-*-TEST` issue and frozen contracts. Work independently of the implementer; the implementation need not be merged yet. Own only its test directory. Derive assertions from original acceptance IDs and supplied negative cases, not from implementation behavior. Build synthetic fixtures and broken-adapter controls proving that tests detect defects.

Cover positive behavior, wrong-client/auth/signature rejection, replay/concurrency, stale approval/consent, timeout/UNKNOWN, restart/HOLD, redaction, retention and resource limits as relevant. Mark requirements needing native hardware/provider/human evidence explicitly. Expected missing-implementation failures during authoring are not qualification passes.

Use the shared harness API and communicate interface defects through the coordinator. Do not weaken a contract to achieve green output. Return files, exact commands, red/green evidence, source-ID mapping and limitations. No external live sends, calls, spend, real identities or credentials.
