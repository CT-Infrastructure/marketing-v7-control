# F08 measured capacity and dispatch hold

measurements.json is a timestamped, sanitized observation of the development
host and its shared WSL guest. It is not a production inventory. Windows and
WSL memory describe overlapping allocations and must never be added together.
Availability is a point-in-time observation, not an approved reservation.

The installed Codex CLI is an available command, not an attestation of an
isolated worker adapter. The inspected WSL guest does not have Podman. The
native collaboration interface exposes four slots, but provider RPM, TPM,
account concurrency, enforced spending ceilings and a scoped credential broker
have not been qualified for this workload.

dispatch-inputs.json deliberately leaves unapproved limits unset. Before a
worker claim, reserve explicit Windows/WSL CPU and memory headroom for the OS,
voice, data, backups and recovery, then require the provider's enforced limits,
disk quota, per-task timeout and cancellation evidence. GPU work additionally
needs device and VRAM isolation; a reported GPU capacity does not prove it.

Run `python3 docs/orchestration/capacity/check_dispatch_inputs.py` to inspect
the missing inputs. It exits nonzero while live dispatch is held. This input
check supplements the existing scheduler; it is not a second scheduler or a
replacement for F06/F10/F11/F12/F13 qualifications.

The metadata importer is separate from AI worker dispatch. Its existing
100-write invocation and 300-write hourly budgets do not grant model spend or
production access. G02 must bind a qualified runner, source revision, approved
capacity, cost limits, scope and expiry before unattended agent execution.
