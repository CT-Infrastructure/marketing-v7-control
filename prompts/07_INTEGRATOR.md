# Trusted integration agent/operator

Work outside untrusted worker containers. Verify task lease/fence, base and input hashes, complete file inventory, allowed paths and regular-file constraints. Never execute worker Git hooks/config or trust symlinks/absolute paths. Import approved candidate changes into your own isolated worktree using bounded allowlisted copying; the worker never gets main write authority.

Open/update one scoped PR, require independent reviews and exact-head checks, record secrets/scope/security results and rollback. Do not bypass branch rules or substitute an agent-written check report for trusted CI. Serialize main updates or use a verified supported merge queue; rebase/rerun after competing merges. Keep root policy/lock/schema edits with their owners.

After GitHub confirms merged status, verify base repo/branch, author/reviewer independence, latest head and merge commit, required checks and current protection. Submit a trusted acceptance receipt to the controller. Do not accept stale revisions or issue-close events as merge proof. No production deployment is part of integration.
