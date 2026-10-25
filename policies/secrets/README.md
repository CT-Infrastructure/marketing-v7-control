# Secrets and identities policy 1.0

This is an offline engineering contract, not a secret store, credential issuer, authenticated service or production authorization. All external effects remain HOLD. No actual credential is read, minted, decrypted, mounted or tested. `roles.v1.json` is a reviewed policy seed; a real broker must receive it from a trusted read-only deployment, never from the worker-writable snapshot.

## Role separation

| Identity | Bounded authority | Explicit separation |
|---|---|---|
| Bootstrap administrator | Initial repository/project setup and governance configuration | Time-boxed human session; remove elevated grants after setup. Never reuse for coding, reviews or normal integration. |
| Metadata coordinator | Approved issue/project reads and writes | No repository administration, source push, review approval or deployment. Project access is verified separately. |
| Coding worker | Read exported source and write its scoped artifacts | No GitHub write/admin credentials, private age keys, SMTP/SIP/payment credentials, deployment tokens, host sockets or production routes. |
| Reviewer | Read candidate source/artifacts, submit independent report | No editing the candidate or merging own review; no production authority. |
| Trusted integrator | Write topic branches/PRs and request governed merge | Distinct identity; exact reviewed tree and required checks; no approval bypass or deployment credential. |
| Production operator | Separately approved runtime secret references and deployment requests | Outside coding worker; fresh verified human gates, exact artifact/account/environment and scoped secret delivery. This prototype does not execute deployment. |

A role label is never authentication. A trusted identity verifier maps the authenticated principal to a preapproved task grant; caller JSON cannot select identity, role, scopes, task, fence, TTL or approval. The grant binds subject, role, task, current fence, exact resource, exact audience and explicit scopes. No wildcard expansion, inheritance or broad-token fallback. Runtime issuance and effective upstream scopes must be independently verified; this package only checks synthetic grants.

Use the existing ChatGPT subscription for the authorized native agent execution. API-key authentication is prohibited for that path. Do not copy subscription/session material into worker output or repurpose it as a broker token. A missing supported authentication path blocks launch; it does not authorize purchasing API access or injecting model keys.

## Lifetime, revocation and requests

The reference policy caps a grant at 300 seconds, always within the current task lease. This is a policy choice, not a vendor token TTL claim. An issuer must shorten upstream credentials where supported or keep them outside the worker and enforce the shorter grant at a trusted broker. Never call a long-lived upstream token short-lived merely because a JSON wrapper expires.

The trusted verifier supplies current identity/task/fence/audience and lease state on every operation. Exact integer timestamps use issued_at <= now < expires_at and now < lease_until. Unknown/unavailable identity, time, policy, lease or revocation authority fails closed; no cached allow during outage. Expiry, revocation, role/resource/scope mismatch, forged context, old fence, cross-task reuse or repeated nonce rejects without leaking inputs. Revocation must reach all broker instances and upstream credentials must be revoked/rotated as appropriate. The in-memory nonce set and revocation set only demonstrate single-process behavior; production needs atomic durable replay consumption and strongly current revocation before effects. Restarting this prototype loses those sets, so it must not protect a live endpoint.

The authenticated transport binds caller identity to the opaque grant reference; knowing that reference alone is insufficient. A grant reference is not a credential and must not resolve to raw secret bytes for a coding worker. A real production operator's approval is verified separately against OpenProject, not inferred from this role, a nonce, or an engineering PR.

## SOPS, age and native secret references

Preserve SOPS+age as baseline. Encrypt secret documents for reviewed public recipients; retain actual age private identities only under the named human/off-platform recovery custodians and separately authorized runtime decryptor. Workers do not decrypt SOPS, receive private identities, or browse entire Vaultwarden/KeePassXC stores. Use existing Vaultwarden for human credentials where selected and KeePassXC for independent offline recovery; no new mandatory vault service is introduced.

Use task/service-specific file references with Podman/systemd credentials or mounted secret files. `file-bindings.example.json` shows logical references only and is deliberately NOT deployable. Verify exact installed versions and supported secret options, user ownership, mode, mount namespace and permissions; expose only the one service's secret file, read-only, for its lifetime. Prefer service-private runtime credentials directories. Never put secret values in Git, CLI argv, image build args/layers, logs, or general environment variables. If a product requires environment credentials, document that exposure and use a reviewed dedicated runtime wrapper outside workers. Do not assume Podman secret objects automatically rotate already-running workloads or that filesystem unlink wipes memory.

Decrypt only in a bounded trusted operator/runtime job to private temporary storage, mount only the required value, prevent child-process/log exposure, remove temporary material on success/failure, and revoke on completion. Validate cleanup and rotation with synthetic secrets on a disposable runner before deployment. Actual upstream secret delivery, process-memory handling and systemd/Podman enforcement remain NOT_RUN.

## Off-platform recovery ownership and runbook

The human security owner appoints a primary recovery custodian and a separate alternate before enablement; actual names and private contact routes are absent and must be recorded outside this public package. Keep encrypted backups and recovery instructions on independently accessible offline media, with age identities/unlock material separated from encrypted data and production hosts. Neither GitHub, this coordinator, nor the running infrastructure is the sole recovery path. Define access under dual human approval, inventory/checksum dates, revocation history and alternate contact escalation in that private custody register.

1. Inventory only logical secret references, owner, allowed service, scopes, issuer, rotation/expiry and recovery record. Never export secret values into evidence.
2. Approve task/resource/audience/identity and verify effective provider permissions. Retire bootstrap elevation. Confirm worker mounts and logs contain no credentials.
3. On suspected exposure: hold new work, revoke broker and upstream grants, isolate the affected identity, rotate at source, inspect redacted receipts and keep unknown external actions unresolved pending reconciliation. Deleting a log is not rotation.
4. For recovery: two custodians authenticate out-of-band, restore a synthetic test first, verify encrypted backup integrity and documented recovery order, then obtain separate approval for real restore. Keep outbound queues/automation held throughout.
5. Record a redacted receipt with reference, incident/recovery ID, timestamps, actor roles and result; never the key, unlock material or raw payload. Run periodic offline synthetic restore and custodian handoff drills. Actual recovery success is not claimed here.

Sources: package `AGENTS.md`, `SECURITY.md`, `docs/security/CREDENTIALS_AND_CI.md`, `CONTAINER_AND_HOST_BASELINE.md`, `docs/orchestration/EXECUTION_PROTOCOL.md`, ADR-001 and component registry CP022-CP025. Human custody assignments, runtime versions, authentication transport, effective upstream TTL/revocation and durable multi-process enforcement are deployment blockers.
