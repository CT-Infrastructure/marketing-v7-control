# CT-Infrastructure repository layout

The user selected CT-Infrastructure and separate repositories for the portions
of this project on 2026-10-25. This overrides the original single-repository
packaging choice. It does not change V7 native application ownership, the 785
stable issue keys, the 4,848 build prerequisites, or the 576 original acceptance
IDs. All runtime acceptance remains NOT_RUN.

`config/repositories.json` maps each issue to exactly one repository.
marketing-v7-control holds the canonical source catalog, full issue briefs,
shared contracts, DAG, tooling, integrated scenarios and human gates. The
infrastructure, integrations, content, email, voice, marketing and legacy
repositories own their assigned implementation paths. Reference copies in
those repositories are frozen source inputs. The single private organization
Project is a projection of these repositories, not scheduler authority. The
user subsequently authorized all eight repositories to become public and
selected MIT for original project code and documentation. The organization
Project remains private. Third-party licenses remain in effect. This explicit
user direction overrides the imported package's private-only default.

`tools/seed_github_multi.py` provides plan, workspace, issues, relationships and
project phases. A single private journal binds the layout hash and rate budget
across all repositories. It uses read-back IDs for cross-repository parents and
dependencies. Uncertain writes stop; do not delete the journal or retry creates
without reconciliation. Default limits remain 100 writes per invocation and
300 per rolling hour. Budget exhaustion is a resumable pause, not completion.

The original launcher assumes a single Git ancestry for accepted prerequisites.
It is not qualified for this layout. F11/F12/F13 must implement and independently
test source assembly from immutable revisions in each repository, preserving
one controller, global leases/fences, task/path ownership, and explicit locks.
Do not use a commit from one repository as ancestry proof for another. Keep
live dispatch disabled until this work, independent review and G02 are complete.

CompleteDotTech is the verified human organization owner and initial CODEOWNER.
The bootstrap author cannot approve their own protected PR. A separate trusted
review identity or human-approved integration arrangement is still required;
repository membership and CODEOWNERS do not supply independent review by
themselves. No production secrets or environment deployment credentials belong
in these seeds.

Public source disclosure scope: the reviewed package source, sanitized design briefs,
opaque legacy row references, schemas, diagrams and engineering tooling. The
original ZIP, raw legacy inventories, local configs, journal, host inventory,
credentials and recovery data remain outside GitHub.
