# ADR-002 — Maximize admitted work, not uncontrolled agents

Decision: split each workflow into implementation, independent tests-first authoring and final verification. Freeze shared interfaces before consumer work; isolate task paths and snapshots; allow all tasks whose true prerequisites, capacity, budgets and locks are satisfied. Use priority/critical-path/queue-age ordering and review capacity to reduce bottlenecks.

Do not impose global phase barriers or turn all runtime handoffs into hard dependencies. Do not run conflicting shared migrations, credential rotations, DNS/router cutovers or main merges concurrently. Do not infer hardware/provider capacity. Example 12-worker limits are editable starting assumptions, not a benchmark or promise.

The reference scheduler is a tested building block, not proof of remote agent-provider integration or optimal bin packing. Scale after qualifying the adapter, kill/reap behavior, monetary limits and no-production isolation. Native provider subagents count toward the same budget and must be visible to the coordinator.
