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

## Selected provider and present evidence

The user selected Codex on the ChatGPT subscription for implementation, with
GPT-6.1-Sol at low reasoning effort for every writing subagent, and GitHub
Copilot for reviews. Login status was observed as `Logged in using ChatGPT`.
This proves observed authentication, not numeric quotas or entitlement for any
particular dispatch. Provider RPM, TPM and concurrency remain explicitly unknown.

The zero total/per-task USD ceilings mean no API-dollar spend is authorized;
they do not describe the subscription price or grant unlimited subscription use.
No extra credits may be purchased. Subscription entitlement and quota enforcement
still require trusted qualification. An OPENAI_API_KEY exists in the host
environment: the trusted launcher must remove it from every worker environment
and verify subscription identity without exposing its value.

CLI 0.164.0 supports MXC and its command smoke passed. The legacy elevated
sandbox rejected root-deny. A later MXC probe failed before any model session
because the sanitized shell environment lacked SYSTEMROOT. This is not adapter
qualification: preserve SYSTEMROOT and necessary nonsecret platform variables
while excluding API credentials, then independently qualify the adapter. No
worker launch or further probe is authorized by this document.

All G02, egress, disk quota, cancellation, identity, source and provider-limit
holds remain. A passing checker reports only structurally present inputs, never
acceptance or permission to claim. The checker rejects non-object inputs,
nonfinite/negative numbers, booleans posing as numeric budgets, malformed
headroom and inconsistent memory measurements. It reads the measured snapshot
without summing Windows and WSL memory. It does not verify measurement freshness,
provider receipts, runtime enforcement or the authenticity of approval references.
Trusted admission must refresh observations and verify those proofs before claim.

Run the regression suite with:
`python -m unittest discover -s docs/orchestration/capacity -p 'test_*.py'`.
Unknown capacity reservations must remain unset until approved; actual worker
slots remain zero. Global emergency STOP prevents new claims; the trusted
controller cancels/reaps and reconciles active work before releasing reservations.
