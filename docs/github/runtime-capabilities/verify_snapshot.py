"""Offline consistency check; not live verification or acceptance."""
import hashlib
import json
from pathlib import Path

def require(condition):
    """Keep validation active even when Python is run with optimization."""
    if not condition:
        raise ValueError("offline snapshot consistency check failed")


root = Path(__file__).resolve().parents[3]
doc = json.loads((Path(__file__).parent / "capabilities.json").read_text(encoding="utf-8"))
require(doc["kind"] == "evidence_snapshot_not_approved_configuration")
require(doc["authority"]["production_authorized"] is False)
require(hashlib.sha256((root / ".github/CODEOWNERS").read_bytes()).hexdigest() == doc["authority"]["codeowners_sha256"])
# This repository configuration is trusted input, independent of the snapshot.
configuration = json.loads((root / "config/repositories.json").read_text(encoding="utf-8"))
approved_repositories = {
    f"{configuration['owner']}/{repository['name']}"
    for repository in configuration["repositories"]
}
require(len(approved_repositories) == 8)
require(len(doc["repositories"]) == 8)
require({r["repository"] for r in doc["repositories"]} == approved_repositories)
require(len({r["repository"] for r in doc["repositories"]}) == 8)
for repo in doc["repositories"]:
    require(repo["visibility"] == "public" and repo["license"] == "MIT")
    require(repo["main_protected"] is True)
    require(repo["main_sha"] == repo["bootstrap"]["merge_sha"])
    require(repo["bootstrap"]["review_rule_restored"] is True)
    require(repo["token_policy"]["can_approve_pull_request_reviews"] is False)
    require(repo["token_policy"] == {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False})
    require(repo["action_allowlist"]["patterns_allowed"] == ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"])
    require(any(c["status"] == "completed" and c["head_sha"] == repo["main_sha"] and c["app_id"] == 15368 and c["conclusion"] == "success" and c["name"] == "package-validation" for c in repo["ci"]))
    require(repo["action_allowlist"]["github_owned_allowed"] is False)
    require(repo["action_allowlist"]["verified_allowed"] is False)
    require(len(repo["rulesets"]) > 0)
    for rule in repo["rulesets"]:
        require(rule["target"] == "branch" and rule["source"] == repo["repository"])
        require(rule["conditions"]["ref_name"] == {"include": ["~DEFAULT_BRANCH"], "exclude": []})
        require(rule["enforcement"] == "active" and rule["bypass_actors"] == [])
        rules = {r["type"]: r for r in rule["rules"]}
        require("deletion" in rules and "non_fast_forward" in rules)
        pr = rules["pull_request"]["parameters"]
        require(type(pr["required_approving_review_count"]) is int and pr["required_approving_review_count"] >= 1)
        require(all(pr[k] is True for k in ("require_code_owner_review", "require_last_push_approval", "dismiss_stale_reviews_on_push", "required_review_thread_resolution")))
        check = rules["required_status_checks"]["parameters"]
        require(check["strict_required_status_checks_policy"] is True)
        require({"context": "package-validation", "integration_id": 15368} in check["required_status_checks"])
    require({e["name"] for e in repo["environments"]} == {"staging", "production"})
    for env in repo["environments"]:
        require(env["can_admins_bypass"] is True)
        require(env["deployment_branch_policy"]["protected_branches"] is True)
        require(env["deployment_branch_policy"]["custom_branch_policies"] is False)
        require(len(env["required_reviewers"]) == 1)
        reviewer_rule = env["required_reviewers"][0]
        require(reviewer_rule["prevent_self_review"] is True)
        require(len(reviewer_rule["reviewers"]) == 1)
        reviewer = reviewer_rule["reviewers"][0]
        # Login-only historical evidence cannot establish the numeric identity.
        require(isinstance(reviewer, dict))
        require(reviewer.get("login") == "CompleteDotTech")
        require(type(reviewer.get("id")) is int and reviewer["id"] == 5861166)
        require(reviewer.get("type") == "User")
require(doc["project"]["visibility"] == "PRIVATE")
require(doc["project"]["automation_readback"]["public"] is False)
require(len(doc["project"]["verified_issue_mappings"]) == 6)
mappings = doc["project"]["verified_issue_mappings"]
for mapping in mappings:
    require(mapping["repository"] in approved_repositories)
    require(type(mapping["number"]) is int and mapping["number"] > 0)
require(len({m["key"] for m in mappings}) == len(mappings))
require(len({m["node_id"] for m in mappings}) == len(mappings))
require(len({(m["repository"], m["number"]) for m in mappings}) == len(mappings))
require(len(doc["human_gates"]) == 12)
require({g["key"] for g in doc["human_gates"]} == {f"G{i:02}" for i in range(1, 13)})
require(all(g["status"] == "not_assessed_no_approval_granted" for g in doc["human_gates"]))
print("PASS: offline snapshot consistency; no live verification or acceptance")
