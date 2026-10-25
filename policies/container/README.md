# F06 rootless container baseline v1.0

Status: offline review candidate, 2026-10-25. Baseline revision `11f7a5f0aab4b41966e9d6134215b1a3823a8e95` includes F03 code acceptance; it does not establish native or production isolation. This package is policy and inert examples, not a deployment. No host changes, installations, container starts or network probes are performed. A separately authorized confined dry run of the extracted Quadlet 4.9.3 generator is recorded below.

## Design and scope

Use supported Debian guests with rootless Podman, the user systemd manager and compatible Quadlet for application and bounded worker jobs. The runtime user must itself be unprivileged; a `[Service] User=` line does not make a rootful system service rootless. Keep native scheduling in its native owner (including Postiz Temporal and Mautic queues). No replacement orchestrator or omnibus privileged container is introduced.

This conservative profile starts with network `none`, no external effects and no host mounts. Applications requiring private networking, additional write locations or capabilities need a separate scoped review and exact-target qualification; changing an input string or declaring an exception does not authorize them. Rootless network plumbing alone never proves deny rules for management, VPN, DNS, IPv6 or metadata. The profile supports only a bounded, non-network baseline; it is not a claim that every vendor image works under it.

Sources read from the pinned snapshot: `AGENTS.md`, F06 brief, `docs/orchestration/EXECUTION_PROTOCOL.md`, `docs/security/CONTAINER_AND_HOST_BASELINE.md`, `docs/security/threat-model/README.md`, `templates/quadlet/app.container.in`, `templates/containers/Containerfile.in`, and `reference/workflows/I12.json`. Native placement follows those source decisions. Existing upstream examples remain untouched; the new examples are intentionally narrower and non-installable.

## Normative controls

| Control | Candidate requirement | Evidence still required |
|---|---|---|
| Image and supply chain | Registry/repository with exact lowercase SHA256 digest; controlled prefetch, exact upstream version/license/SBOM and scan at that digest | Provenance/signature policy, supported architecture, digest content and vulnerability review. A syntactically valid digest is not approved content. |
| Rootless identity | Unprivileged user manager and container UID/GID > 0; no root mapping assertion from numeric values | `uid_map`/`gid_map`, subordinate ranges, rootless inspect and in-container identity on selected host; volume effective ownership |
| Privilege | `DropCapability=all`, no-new-privileges, no privileged mode/devices, private PID/IPC, runtime-default seccomp, enforcing host LSM | Exact generated flags and actual confinement profile; host support and escape-denial tests |
| Filesystems | Read-only root and ReadOnlyTmpfs=false to disable implicit writable /run and /var/tmp; named private data volumes only; no host paths/sockets; approved write targets; 0700 ownership; bounded noexec/nosuid/nodev tmpfs | Mount inspection, attempted prohibited writes, named-volume backing-store isolation, measured disk quota, correct application write requirements |
| Secrets | References only, scoped mounted secrets through separately reviewed runtime configuration; no raw values in environment/build/image/logs | Actual mounted secret identity/permissions, rotation, log redaction. The stateless Quadlet example has no secrets or state volumes. |
| Resource bounds | Typed positive CPU, memory, PIDs, disk and runtime budgets; tmpfs within memory budget | cgroup v2 delegation and actual memory/CPU/PID enforcement; underlying volume/output disk quota. A manifest field does not enforce disk quota. |
| Health and lifecycle | JSON exec-form fixed direct health executable, finite timeouts/retries, bounded start rate and Restart=no for the one-shot job; readiness, drain and rollback references | Health command exists in image; startup/dependency outage, SIGTERM/drain, readiness failure, memory/PID exhaustion, restart limits and held resume observed |
| Egress | No network and external effects disabled; no ports/proxy environment or native production credentials | Exact network namespace and host-path denial from approved disposable environment. Later private networking needs separately reviewed firewall/broker evidence. |
| Integration | Strict allowlisted manifest/Quadlet syntax subset; no shell, arbitrary PodmanArgs, ExecStart or `[Install]`; no automatic launch | Extracted Quadlet 4.9.3 emitted service and unknown-key negative test observed; target-installed version compatibility and independent review still required |

`validate.py` rejects missing/extra fields and wrong scalar types, zero/negative/unbounded resources, mutable image references, unsafe namespaces, bind mounts, sockets, unconfined profiles, shell health commands and raw environment additions. `--quadlet` validates only this repository's deliberately small static subset. It is not the Podman parser, does not prove runtime support and never returns launch authorization. The subset uses one stateless, one-hour bounded job example with no automatic restart; persistent servers require a separately reviewed lifecycle rather than deleting their timeout. Readiness is distinct from liveness and dependency ordering. References identify documentation to review; they are not authenticated evidence or automatic approval.

## Files and offline use

- `policies/container/validate.py`: typed JSON and restricted Quadlet validators; success remains `launch_authorized: false` and qualification `NOT_RUN`.
- `policies/container/test_baseline.py`: constructed fixtures and failure cases; fictitious `.invalid` image and repeated-character digest exist only in memory, never to be pulled.
- `policies/container/native-exceptions.json`: native placement register, not an approval to deploy or relax container policy.
- `deploy/base/app.container.in`: unresolved stateless example, no `[Install]` target, no write to a systemd search path.
- `deploy/base/component.json.in`: deliberately unresolved input outline. All template fields must be reviewed and replaced; both templates must fail preflight as delivered.

From the workspace root, run:

```
python -B policies/container/test_baseline.py
python -B policies/container/test_observed_generator.py
python -B policies/container/validate.py deploy/base/component.json.in
python -B policies/container/validate.py --quadlet deploy/base/app.container.in
```

Both test commands must pass; the two unresolved templates must exit **2**. Exit 0 on a resolved candidate means offline policy validity only. The validator has no install, write, launch or qualification mode. A trusted integration path must bind the exact manifest/image/template to independently verified receipts; do not treat an agent-generated JSON boolean as a receipt.

## Native placement and exceptions

`native-exceptions.json` keeps firmware (OpenWrt/firewall4/DNS/DHCP/UI/SSH), Proxmox/QEMU, host operating-system/storage/time/UPS services, dedicated voice VM and offline KeePassXC in their supported native roles. Native does not mean exempt from access control, patching, least privilege, backup or incident handling. Asterisk ARI stays private and carrier/SIP/RTP access requires separate voice permission. No host-wide restart is part of this work. No raw recovery keys, private inventory, addresses or credentials are included.

A future container exception must record component, exact image/version, requested setting, reason, minimal scope, compensating controls, accountable owner, independent security reviewer, expiry, rollback and exact-target evidence. Exceptions cannot authorize privileged containers, host sockets, host networking or production access under this task. Read-only incompatibility remains blocked until separately reviewed; do not silently switch it off.

## Qualification blockers and safe runbook

Earlier inventory reported no available host Podman. This assignment neither installs it nor repeats host discovery. The exact target OS/kernel, installed Podman/Quadlet/systemd versions and installed generator path are not supplied. An extracted official Ubuntu package generator was exercised as described below, but target-installed-generator compatibility, rootless UID/GID mapping, cgroup enforcement, LSM/seccomp, application behavior, network denial and native service acceptance are still **NOT_RUN**. They block the corresponding F06 acceptance items; offline lint is not a substitute. Only the controller can accept independent review and determine an allowed lower evidence level.

The infrastructure owner and independent verifier should, in a separately authorized disposable engineering environment:

1. Record exact OS/kernel, package and generator versions, architecture and nonsecret target identity. Obtain supported generator invocation from that installed version's help/docs; do not assume a fixed generator path or flags. Preserve package/image provenance and source hashes.
2. Replace placeholders only with approved component facts. Validate the manifest and the exact resolved Quadlet offline. Review image digest, writable paths, secret references, health executable and dependency readiness/drain/rollback contracts. Keep all external effects held.
3. Run the installed generator in its supported dry-run mode against an isolated scratch unit directory, not live systemd search paths. Capture stderr, exit status and exact emitted unit. Demonstrate an unknown-key candidate is rejected by the trusted preflight, and record actual installed-generator behavior (some versions may warn/ignore). Never call a successful generation alone a runtime pass.
4. Inspect emitted image/UID/GID, read-only, caps, security, namespaces, tmpfs and cgroup flags. Only after independently reviewed generation, a separate approved runtime test may start the disposable fixture. Inspect actual UID maps, effective identity, mount permissions, seccomp/LSM and delegated cgroup controls. Test denied socket/coordinator/host reads with synthetic canaries, no real secrets.
5. Exercise memory/PID/CPU/disk/runtime limits, health timeout and readiness failure, bounded restart storms, signal/drain and held recovery. Verify network denial for IPv4/IPv6/DNS/proxy/VPN/metadata through a trusted harness; no production probes. Verify volume ownership and a synthetic coherent backup/restore without resuming external queues.
6. Preserve attributable command/output/exit-code/hash receipts, owner and independent verifier with exact configuration and image. Keep unresolved cases NOT_RUN. No automatic production authorization follows; production requires its separate human gate.

Residual risks: runtime/kernel defects, malicious approved images, model/build code abuse, trusted-controller compromise, incomplete mounted-volume quota support, unsupported LSM and vendor incompatibility. Fail closed rather than removing protections. Do not publish exploit details, secrets or private topology in evidence.

## Extracted-generator observation (v1.0 evidence update)

The controller supplied Ubuntu 24.04 package `podman 4.9.3+ds1-1ubuntu0.2`, reporting package SHA256 `e5c1c37e387ed14c352a744a75fbb79fb2f82573ca7bf36886e3b7333fc9ef1a`. The extracted generator executable was independently hash-checked before execution: SHA256 `9e95fafe06ef5b630dbb59cbf3630d38931c3fc27ba7c7f9cf472f064d9798b9`. This is a project-local extracted binary, not a host-installed Podman engine. No package install or container launch occurred.

An authorized WSL invocation ran only `-dryrun -user -no-kmsg-log` inside bubblewrap with `--unshare-all`, a cleared environment, read-only `/usr`, read-only generator and isolated fixture directory, a private `/tmp`, and `QUADLET_UNIT_DIRS=/fixtures`. No host systemd directory or ordinary Quadlet search path was exposed. Exact commands, exit codes and stdout/stderr are in the task output evidence. The valid synthetic pinned-image fixture returned exit 0 and emitted a service; adding `F06UnknownSecuritySetting=true` to `[Container]` returned exit 1 with an unsupported-key diagnostic and no emitted service.

`fixtures/quadlet-4.9.3.service.txt` preserves the observed synthetic stdout as non-installable text. Historical regression tests inspected its no-new-privileges, all-capabilities drop, read-only filesystem, nonroot user argument, no-network argument, bounded tmpfs, resource/lifecycle settings and health arguments. The emitted `Delegate=yes` and `--cgroups=split` are configuration observations only: no cgroup enforcement was tested. Generator user mode is not evidence that a process actually ran rootless or that UID maps are correct. Likewise, the synthetic image digest has not been pulled or authenticated. Runtime resource, disk, LSM/seccomp, health, volume, network, restore and production-isolation qualifications remain NOT_RUN.

## PR 102 review remediation � pending regenerated observation

At the initial handoff, the stored generator stdout predated these fixes, and the updated assertions awaited controller regeneration. That pending/expected-failure status is historical and is superseded by the controller observation below. The worker did not fabricate generated output, install an engine, start services or containers, or make network calls.

Five corrections are now normative: `ReadOnlyTmpfs=false` disables Podman's implicit writable mounts while the explicit hardened `/tmp` remains; HealthCmd is a JSON exec array rather than a shell string; `Restart=no` prevents RuntimeMaxSec timeout from creating an unlimited sequence of activations; registry host must contain a dot or an explicit valid port, except literal localhost; and the parser rejects control/Unicode line separators and bare CR before parsing physical LF/CRLF lines. CLI reads preserve raw line endings, preventing newline normalization from concealing malformed input. No cumulative restart guarantee is inferred from StartLimit settings.

`fixtures/synthetic.container` is resolved, policy-valid source for root's generator test with a fictitious `.invalid` image and digest. It is not observed output, a real image, an installable deployment, or runtime evidence. New regression tests cover both manifest and Quadlet paths, actual CLI reads of CR/VT/FF/Unicode separator cases, allowed CRLF/tab formatting, JSON-shell rejection and automatic-restart rejection. Existing test semantic changes are limited to adding required read_only_tmpfs=false to the positive fixture, changing its restart value to no, and updating the corresponding mutation/observed-output assertions. Runtime qualification remains NOT_RUN.


## Image-declared volumes and complete image-name bound

Pinned Podman/Quadlet 4.9.3 has no native ImageVolume Quadlet key. Using the official versioned Quadlet and podman-run documentation verified by root, this profile now requires the one fixed `PodmanArgs=--image-volume=ignore` literal. This suppresses image-declared VOLUME mounts, which otherwise create writable paths outside the explicit manifest. No arbitrary PodmanArgs are accepted: omission, another image-volume mode, appended flags and duplicate directives all fail preflight. The JSON filesystem contract requires image_volumes=ignore as well. Explicit reviewed mounts and the hardened /tmp remain independently checked.

References supplied and verified by root: https://docs.podman.io/en/v4.9.3/markdown/podman-systemd.unit.5.html and https://docs.podman.io/en/v4.9.3/markdown/podman-run.1.html (image-volume). This worker made no network requests. The controller has now regenerated the snapshot using the pinned real Quadlet 4.9.3 generator: exit code 0, input SHA-256 `89d48984a2c6c694b3c0cc46101c54e0e120bb030d7abe59033c2543c450e1ee`, and output SHA-256 `4303f168720aa304acf2ebbc214a0306a8c52789ebc2de7a637902fa8a97d815`. The generated ExecStart contains exactly one `--image-volume=ignore` argument. Root also reports all 36 policy/observed-fixture tests passed normally and with Python `-O`.

This is controller-supplied generation and test evidence, not a new worker execution or global runtime qualification. No container runtime was started. Target runtime UID mappings, cgroup enforcement, LSM/seccomp behavior and network isolation remain **NOT_RUN** and require their separately authorized tests. No observation timestamp was supplied for this receipt, so none is inferred here.

The complete registry[:port]/repository name before @ is limited to 255 characters in both manifest and Quadlet validators. Host and repository component checks remain in place; checking their individual lengths is insufficient. Boundary tests cover total lengths254,255,256 with and without registry ports. No stored generator stdout was edited by this follow-up.

