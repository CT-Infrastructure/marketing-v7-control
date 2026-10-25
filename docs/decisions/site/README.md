# F15 human decision register

This register collects missing production decisions without inventing site facts. The machine-readable companion is `decision-register.json`; all sixteen rows remain UNSET with null values, evidence, approver and approval date. Owner roles are requested responsibilities, not claims that a person has accepted ownership. The controller must route each blocker to a human role assignee.

| ID | Input | Unblock owner role | Required decision/evidence in the authorized private system |
|---|---|---|---|
| SITE-01 | domains | DNS owner | Owned zones, service names, registrar/DNS control and TLS responsibility; no DNS mutation here |
| SITE-02 | cidrs | Network owner | Approved IPv4/IPv6 ranges, routing/firewall boundaries, overlap and management-access review |
| SITE-03 | hardware | Infrastructure owner | Production host/guest inventory, capacity, storage and failure domains; development hardware is not evidence |
| SITE-04 | accounts | Service owner | Production tenant/account identities, delegated roles and scope; references only, no credentials |
| SITE-05 | supported_versions | Platform owner | Exact supported application/OS/runtime/database/cache versions, compatibility, license and upgrade evidence |
| SITE-06 | native_workers | Platform owner | Complete app-specific workers, queues, schedulers, dependencies and restart/recovery requirements |
| SITE-07 | timezone | Business operations owner | IANA policy timezone per client/channel; daylight-saving and scheduling decisions; host timezone is not authority |
| SITE-08 | client_owners | Client governance owner | Role-to-client partition ownership, escalation and authorized decision authority; no raw personal data |
| SITE-09 | rpo_seconds | Business continuity owner | Approved recovery point objective in seconds, per service/dataset and backup coverage |
| SITE-10 | rto_seconds | Business continuity owner | Approved recovery time objective in seconds, restore ordering and exercise evidence |
| SITE-11 | provider_approvals | Provider governance owner | Selected providers, verified account/scopes/terms, limits and approval receipts; none are selected here |
| SITE-12 | secret_references | Security owner | Authorized secret reference format, custodians, rotation/revocation and access boundaries; never secret values |
| SITE-13 | backup_restore | Backup owner | Retention, isolated restore, key custody, integrity checks and restore-in-HOLD reconciliation |
| SITE-14 | data_residency | Privacy owner | Approved data locations, retention, deletion, processor and cross-border decisions |
| SITE-15 | channel_permissions | Channel compliance owner | Native eligibility/consent, suppression, windows and revocation per channel/client |
| SITE-16 | budget_limits | Budget owner | Approved provider/channel caps, enforcement outside workers and escalation |

These blockers prevent use of the corresponding production inputs. They do not prevent unrelated synthetic/mock implementation. Conditional services require a separately reviewed selection; absence does not turn them into baseline dependencies.

Confirmed engineering facts supplied in the trusted F15 packet: GitHub organization `CT-Infrastructure`; public MIT repositories; `GPT-6.1-Sol` with low reasoning under a ChatGPT subscription; Copilot review. These facts establish no production account, provider approval, API credential, paid API entitlement, spend authorization, or review receipt. Copilot review does not replace required independent review or human gates. The local Windows development host and its timezone are not production facts.

GitHub owns engineering issue/review/merge evidence. OpenProject retains business, editorial, campaign, budget and publication decisions. Mautic owns contact permission; WordPress publication; Postiz social scheduling; ResourceSpace approved assets; Matomo analytics; SerpBear rankings. Activepieces coordinates cross-application work; Temporal is Postiz-internal. PostgreSQL operational ledgers do not replace native ownership.

Human resolution happens in a separately authorized workflow: collect minimal nonsecret evidence, name the accountable role, bind the exact scope/revision/expiry, obtain the required human decision and independent verification, then submit a separately scoped change. Do not edit this example into a production inventory or clear its holds. Actual identities/topology and approvals belong in the authorized private system. Append superseding decisions there; preserve earlier receipts and revocations. No approval is recorded by this package.
