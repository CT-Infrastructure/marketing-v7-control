# Source provenance and official verification

Prepared October 25, 2026. This package derives from **Marketing V7 integrated implementation, consolidation revision 1**, not solely the older 36-marketing-workflow document. See `reference/provenance.json` for source ZIP/catalog SHA-256 hashes, counts and the deliberate exclusion of raw private historical evidence. Original acceptance rows are retained verbatim in `reference/acceptance/Original_Acceptance_Matrix.csv`; the new traceability CSV assigns every row to actual task keys.

## Official technical references checked

| Topic | Primary reference | Applied conclusion |
|---|---|---|
| Projects v2 API | https://docs.github.com/en/issues/planning-and-tracking-with-projects/automating-your-project/using-the-api-to-manage-projects | Use GraphQL project IDs, explicit project permissions, field discovery and separate item insertion. Repository permissions do not automatically establish project rights. |
| Native sub-issues | https://docs.github.com/en/rest/issues/sub-issues | Native parent links use issue database IDs; read back before writes. |
| Sub-issue hierarchy limits | https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/adding-sub-issues | Keep each parent within 100 children and hierarchy within eight levels; validated locally. |
| Native blocked-by relationships | https://docs.github.com/en/rest/issues/issue-dependencies | Use supported REST blocked_by relationships; stable package keys map to numeric IDs. |
| CLI project fields | https://cli.github.com/manual/gh_project_field-create | Discover existing field types/options; reconcile rather than assume hard-coded IDs. |
| Ruleset availability | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets | Private-repository feature availability depends on account plan. Verify before claiming enforcement. |
| Environment controls | https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments | Private environment and required-reviewer availability varies; a reviewer list is not automatically a two-person quorum. |
| Secure Actions | https://docs.github.com/en/actions/reference/security/secure-use | Minimize tokens, isolate untrusted code, avoid injection, pin reviewed actions; evaluate supported workflow dependency-lock features separately. |
| Runner exposure | https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization | Self-hosted runners require explicit trust isolation; a private repository does not make submitted code safe. |
| Quadlet | https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html | Rootless user units use rootless search paths. Setting systemd User= is not a substitute. Pin and validate the target generator/version. |
| Pinned checkout action | https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1 | Seed workflow uses this reviewed immutable reference; refresh through controlled review, not moving tags. |

These references justify implementation choices; they do not prove compatibility of the user's actual accounts, target operating systems, application editions or API scopes. Exact service versions and image/model digests are selected and validated by the corresponding component issues. Never invent a digest or treat a tag as immutable.
