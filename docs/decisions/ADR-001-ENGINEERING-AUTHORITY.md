# ADR-001 — GitHub engineering control plane

Decision: GitHub owns issues, PRs, code review and delivery state for this implementation repository, as requested. Existing Forgejo remains part of the V7 stack where used; this repository may have an approved one-way mirror, not dual-write ownership. OpenProject continues to own business/editorial/launch/budget decisions. Activepieces and Postiz-internal Temporal retain runtime responsibilities.

The local engineering coordinator is a bounded Python tool using a local SQLite file and container/provider adapters, not another business workflow service. No mandatory RabbitMQ, Kubernetes, Argo, global Temporal, Redis queue or second CRM is introduced. Multi-host execution requires separately reviewed transport/credentials/fencing.

Consequences: engineering completion cannot authorize a campaign; runtime topology is not an engineering DAG; account-specific GitHub access and private-repository protection features must be verified. A private source evidence store remains separate from GitHub.
