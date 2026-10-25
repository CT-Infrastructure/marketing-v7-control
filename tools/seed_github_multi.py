#!/usr/bin/env python3
"""Journaled multi-repository projection of the unchanged V7 issue graph.

All phases default to a local plan. One journal enforces one mutation budget
across the organization; uncertain writes stop until read-back reconciliation.
"""
from __future__ import annotations

import argparse
import collections
import fcntl
import hashlib
import json
import re
from pathlib import Path

from seed_github import APIError, GitHub, Paused, ensure_project, preserve_human_notes, project_items, validate_destination

ROOT = Path(__file__).resolve().parents[1]
MARKER = re.compile(r"<!-- v7-agent-package:([A-Z0-9-]+) -->")


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_layout(path, issues):
    layout = json.loads(Path(path).read_text())
    names = [r["name"] for r in layout["repositories"]]
    if len(names) != len(set(names)) or layout["hub"] not in names:
        raise ValueError("Repository names must be unique and include the hub")
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", n) for n in names):
        raise ValueError("Invalid repository name")
    keys = {i["key"] for i in issues}
    if set(layout["issue_repositories"]) != keys:
        raise ValueError("Repository mapping must cover every issue exactly once")
    if not set(layout["issue_repositories"].values()).issubset(names):
        raise ValueError("Issue references an unknown repository")
    return layout


def plan(layout, issues):
    mapping = layout["issue_repositories"]
    cross_parents = sum(bool(x["parent_key"]) and mapping[x["key"]] != mapping[x["parent_key"]] for x in issues)
    cross_deps = sum(mapping[x["key"]] != mapping[d] for x in issues for d in x["depends_on"])
    return {"mode": "PLAN_ONLY_NO_NETWORK", "owner": layout["owner"], "visibility": layout["visibility"],
            "repositories": dict(collections.Counter(mapping.values())), "issues": len(issues),
            "parent_links": sum(bool(x["parent_key"]) for x in issues),
            "dependency_links": sum(len(x["depends_on"]) for x in issues),
            "cross_repository_parent_links": cross_parents, "cross_repository_dependency_links": cross_deps,
            "layout_sha256": canonical(layout), "production_actions": 0, "agents_launched": 0}


def bind_journal(gh, layout):
    fingerprint = canonical(layout)
    if gh.state.get("layout_sha256", fingerprint) != fingerprint:
        raise ValueError("Layout changed; explicit journal migration is required")
    gh.state["layout_sha256"] = fingerprint
    gh.state.setdefault("repositories", {})
    gh.save()


def repositories(gh, layout):
    owner = gh.api("/users/" + layout["owner"])
    membership = gh.api("/user/memberships/orgs/" + layout["owner"])
    if owner["type"] != "Organization" or membership.get("role") != "admin" or membership.get("state") != "active":
        raise ValueError("Verified active organization owner required for bootstrap")
    for spec in layout["repositories"]:
        name = spec["name"]
        target = layout["owner"] + "/" + name
        key = "repository:create:" + target
        try:
            repo = gh.api("/repos/" + target)
        except APIError as exc:
            if "HTTP 404" not in str(exc) or not gh.cfg.get("allow_repository_create"):
                raise
            gh.api("/orgs/" + layout["owner"] + "/repos", "POST",
                   {"name": name, "private": gh.cfg["visibility"] != "public", "auto_init": True, "has_issues": True,
                    "has_wiki": False, "description": spec["description"]}, key=key)
            repo = gh.api("/repos/" + target)
        if repo["private"] != (gh.cfg["visibility"] != "public") or not repo.get("permissions", {}).get("admin"):
            raise ValueError("Approved visibility and administrator access required: " + target)
        gh.adopt(key)
        gh.state["repositories"][name] = {k: repo[k] for k in ["id", "node_id", "full_name", "html_url", "private", "default_branch"]}
        gh.save()
    return owner


def workspace(gh, layout, model):
    owner = repositories(gh, layout)
    project, fields = ensure_project(gh, owner, model, gh.state["repositories"][layout["hub"]])
    q = "query($id:ID!){node(id:$id){... on ProjectV2{repositories(first:100){nodes{id}} views(first:100){nodes{id name number layout filter}}}}}"
    current = gh.graphql(q, {"id": project["id"]})["node"]
    linked = {r["id"] for r in current["repositories"]["nodes"]}
    for name, repo in gh.state["repositories"].items():
        key = "project:link:" + name
        if repo["node_id"] in linked:
            gh.adopt(key)
        else:
            gh.graphql("mutation($project:ID!,$repo:ID!){linkProjectV2ToRepository(input:{projectId:$project,repositoryId:$repo}){repository{id}}}",
                       {"project": project["id"], "repo": repo["node_id"]}, key=key)
    views = {v["name"]: v for v in current["views"]["nodes"]}
    for view in model["views"]:
        key = "project:view:" + view["name"]
        if view["name"] in views:
            gh.adopt(key)
            continue
        # Grouping remains a separately verified setting when requested. No
        # unsupported default is reported as configured.
        gh.api(f"/orgs/{layout['owner']}/projectsV2/{project['number']}/views", "POST",
               {"name": view["name"], "layout": view["layout"], "filter": view.get("filter", "")}, key=key)
        verified = gh.graphql(q, {"id": project["id"]})["node"]["views"]["nodes"]
        match = [v for v in verified if v["name"] == view["name"]]
        if len(match) != 1 or match[0]["filter"] != view.get("filter", ""):
            raise Paused("Saved view read-back differs: " + view["name"])
        views[view["name"]] = match[0]
    gh.state["views"] = views
    gh.state["view_grouping_status"] = "NOT_CONFIGURED_REQUIRES_READBACK"
    gh.save()
    return {"repositories": gh.state["repositories"], "project": project, "fields": list(fields), "views": views}


def metadata(gh, name, model):
    target = gh.cfg["owner"] + "/" + name
    labels = {x["name"] for x in gh.api(f"/repos/{target}/labels?per_page=100", paginate=True)}
    for label in model["labels"]:
        key = "label:" + target + ":" + label["name"]
        if label["name"] in labels:
            gh.adopt(key)
        else:
            gh.api(f"/repos/{target}/labels", "POST", label, key=key)
    milestones = {x["title"]: x for x in gh.api(f"/repos/{target}/milestones?state=all&per_page=100", paginate=True)}
    for milestone in model["milestones"]:
        key = "milestone:" + target + ":" + milestone["title"]
        if milestone["title"] in milestones:
            gh.adopt(key)
        else:
            milestones[milestone["title"]] = gh.api(f"/repos/{target}/milestones", "POST", milestone, key=key)
    return milestones


def inventory_issues(gh, layout):
    found = {}
    for spec in layout["repositories"]:
        target = layout["owner"] + "/" + spec["name"]
        for item in gh.api(f"/repos/{target}/issues?state=all&per_page=100", paginate=True):
            if "pull_request" in item:
                continue
            keys = MARKER.findall(item.get("body") or "")
            if len(keys) > 1:
                raise ValueError("Multiple stable markers in " + item["html_url"])
            if not keys:
                continue
            key = keys[0]
            if key in found or layout["issue_repositories"].get(key) != spec["name"]:
                raise ValueError("Duplicate or misplaced issue key: " + key)
            item["repository_full_name"] = target
            found[key] = item
    return found


def import_issues(gh, layout, issues, model, limit):
    found = inventory_issues(gh, layout)
    selected = issues[:limit] if limit else issues
    milestones = {}
    for issue in selected:
        key = issue["key"]
        name = layout["issue_repositories"][key]
        target = layout["owner"] + "/" + name
        if name not in milestones:
            milestones[name] = metadata(gh, name, model)
        body = (ROOT / issue["body_path"]).read_text()
        labels = ["type:" + issue["kind"], "risk:" + issue["risk"], "priority:" + issue["priority"]]
        if issue["manual"]:
            labels.append("manual-gate")
        if not issue["enabled_by_default"]:
            labels.append("deferred")
        op = "issue:create:" + key
        if key in found:
            gh.adopt(op)
            old = found[key]
            desired = preserve_human_notes(old["body"], body)
            merged_labels = sorted(set(labels) | {v["name"] for v in old.get("labels", [])})
            if desired != old["body"] or issue["title"] != old["title"] or set(merged_labels) != {v["name"] for v in old.get("labels", [])}:
                found[key] = gh.api(f"/repos/{target}/issues/{old['number']}", "PATCH", {"body": desired, "title": issue["title"], "labels": merged_labels}, key="issue:update:" + key)
        else:
            found[key] = gh.api(f"/repos/{target}/issues", "POST", {"title": issue["title"], "body": body, "labels": labels, "milestone": milestones[name][issue["phase"]]["number"]}, key=op)
        gh.state["issues"][key] = {k: found[key][k] for k in ["id", "node_id", "number", "html_url"]}
        gh.state["issues"][key]["repository_full_name"] = target
        gh.save()
    return {"managed_issues": len(found), "expected_issues": len(issues)}


def relationships(gh, layout, issues):
    found = inventory_issues(gh, layout)
    if set(found) != {i["key"] for i in issues}:
        raise Paused("Create/read back all 785 issues before linking cross-repository relationships")
    for issue in issues:
        key = issue["key"]
        child = found[key]
        parent_key = issue["parent_key"]
        if parent_key:
            parent = found[parent_key]
            path = f"/repos/{parent['repository_full_name']}/issues/{parent['number']}/sub_issues"
            children = gh.api(path + "?per_page=100", paginate=True)
            op = "parent:" + key
            if child["id"] in {v["id"] for v in children}:
                gh.adopt(op)
            else:
                gh.api(path, "POST", {"sub_issue_id": child["id"]}, key=op)
        if issue["depends_on"]:
            path = f"/repos/{child['repository_full_name']}/issues/{child['number']}/dependencies/blocked_by"
            present = {v["id"] for v in gh.api(path + "?per_page=100", paginate=True)}
            for dep in issue["depends_on"]:
                op = "dependency:" + key + ":" + dep
                if found[dep]["id"] in present:
                    gh.adopt(op)
                else:
                    gh.api(path, "POST", {"issue_id": found[dep]["id"]}, key=op)
    return {"relationships": "RECONCILED"}


def project_projection(gh, layout, issues, model):
    found = inventory_issues(gh, layout)
    if not gh.state.get("project"):
        raise Paused("Workspace phase required first")
    from seed_github import project_fields
    project = gh.state["project"]
    fields = project_fields(gh, project["id"])
    attached = project_items(gh, project["id"])
    for spec in issues:
        key = spec["key"]
        if key not in found:
            continue
        content = found[key]["node_id"]
        op = "project-item:" + key
        if content in attached:
            gh.adopt(op)
        else:
            data = gh.graphql("mutation($project:ID!,$content:ID!){addProjectV2ItemById(input:{projectId:$project,contentId:$content}){item{id}}}", {"project": project["id"], "content": content}, key=op)
            attached[content] = data["addProjectV2ItemById"]["item"]["id"]
        values = {"Package Key": key, "Execution": "Manual hold" if spec["manual"] else ("Backlog" if spec["enabled_by_default"] else "Deferred"),
                  "Priority": spec["priority"], "Phase": spec["phase"], "Risk": spec["risk"], "Workstream": spec["area"], "Workflow ID": spec.get("workflow_id") or "", "Evidence level": "Not run"}
        for name, value in values.items():
            cache = key + ":" + name
            if cache in gh.state["field_values"]:
                continue
            field = fields[name]
            if value == "" and field["dataType"] == "TEXT":
                # A newly attached item has no value. Do not issue an ambiguous
                # empty-value update or erase a later human-supplied value.
                gh.state["field_values"][cache] = ""
                gh.save()
                continue
            val = {"singleSelectOptionId": next(o["id"] for o in field["options"] if o["name"] == value)} if field["dataType"] == "SINGLE_SELECT" else {"text": value}
            gh.graphql("mutation($project:ID!,$item:ID!,$field:ID!,$value:ProjectV2FieldValue!){updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:$value}){projectV2Item{id}}}", {"project": project["id"], "item": attached[content], "field": field["id"], "value": val}, key="field-value:" + cache)
            gh.state["field_values"][cache] = value
            gh.save()
    return {"project_membership_readback": len(project_items(gh, project["id"]))}


def verify_projection(gh, layout, issues):
    found = inventory_issues(gh, layout)
    if set(found) != {x["key"] for x in issues}:
        raise ValueError("Remote issue-key coverage differs from the frozen catalog")
    parents = edges = 0
    for spec in issues:
        actual = found[spec["key"]]
        if actual["title"] != spec["title"]:
            raise ValueError("Issue title drift: " + spec["key"])
        source = (ROOT / spec["body_path"]).read_text()
        if preserve_human_notes(actual["body"], source) != actual["body"]:
            raise ValueError("Issue brief drift: " + spec["key"])
        prefix = f"/repos/{actual['repository_full_name']}/issues/{actual['number']}"
        if spec["parent_key"]:
            parent = gh.api(prefix + "/parent")
            if parent["id"] != found[spec["parent_key"]]["id"]:
                raise ValueError("Parent mismatch: " + spec["key"])
            parents += 1
        if spec["depends_on"]:
            deps = gh.api(prefix + "/dependencies/blocked_by?per_page=100", paginate=True)
            if {x["id"] for x in deps} != {found[x]["id"] for x in spec["depends_on"]}:
                raise ValueError("Dependency mismatch: " + spec["key"])
            edges += len(deps)
    project = gh.state["project"]
    q = "query($id:ID!,$after:String){node(id:$id){... on ProjectV2{public items(first:100,after:$after){nodes{id content{... on Issue{id}} fieldValues(first:100){nodes{... on ProjectV2ItemFieldTextValue{text field{... on ProjectV2Field{name}}} ... on ProjectV2ItemFieldSingleSelectValue{name field{... on ProjectV2SingleSelectField{name}}}}}} pageInfo{hasNextPage endCursor}}}}}"
    cursor = None
    records = {}
    while True:
        node = gh.graphql(q, {"id": project["id"], "after": cursor})["node"]
        if node["public"]:
            raise ValueError("Project must remain private")
        page = node["items"]
        for item in page["nodes"]:
            if not item.get("content", {}).get("id"):
                continue
            records[item["content"]["id"]] = {v["field"]["name"]: v.get("text", v.get("name")) for v in item["fieldValues"]["nodes"] if v.get("field")}
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]
    for spec in issues:
        values = records.get(found[spec["key"]]["node_id"], {})
        for name in ["Package Key", "Execution", "Priority", "Phase", "Risk", "Workstream", "Evidence level"]:
            if values.get(name) != gh.state["field_values"].get(spec["key"] + ":" + name):
                raise ValueError("Project field mismatch: " + spec["key"] + ":" + name)
    return {"status": "VERIFIED", "issues": len(found), "parent_links": parents,
            "dependency_links": edges, "project_items": len(records), "production_actions": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--layout", default=str(ROOT / "config/repositories.json"))
    parser.add_argument("--phase", choices=["workspace", "issues", "relationships", "project", "inventory", "verify"], default="workspace")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--journal", default=str(ROOT / ".control/github-multi-import.json"))
    args = parser.parse_args()
    issues = json.loads((ROOT / "backlog/issues.json").read_text())["issues"]
    layout = load_layout(args.layout, issues)
    cfg = json.loads(Path(args.config).read_text())
    if cfg["owner"] != layout["owner"] or cfg["repository"] != layout["hub"]:
        raise ValueError("Config destination and frozen layout disagree")
    if cfg["visibility"] != layout["visibility"]:
        raise ValueError("Config visibility and reviewed layout disagree")
    if cfg["visibility"] == "public":
        if not cfg.get("public_source_reviewed") or not cfg.get("public_publication_approval_ref"):
            raise ValueError("Public disclosure requires separate explicit user authorization and source review")
        # The original private-only importer remains unchanged. This adapter's
        # public mode is an explicit, separately recorded user policy override.
        validate_destination({**cfg, "visibility": "private"}, args.apply)
    else:
        validate_destination(cfg, args.apply)
    if not args.apply:
        print(json.dumps(plan(layout, issues), indent=2))
        return
    if args.confirm != layout["owner"] or args.plan or args.limit < 0:
        parser.error("Apply requires exact --confirm OWNER and nonnegative limit")
    path = Path(args.journal)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.with_suffix(".lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another importer owns this journal")
        gh = GitHub(cfg, path)
        bind_journal(gh, layout)
        model = json.loads((ROOT / "config/project.json").read_text())
        try:
            if args.phase == "workspace":
                report = workspace(gh, layout, model)
            elif args.phase == "issues":
                report = import_issues(gh, layout, issues, model, args.limit)
            elif args.phase == "relationships":
                report = relationships(gh, layout, issues)
            elif args.phase == "project":
                report = project_projection(gh, layout, issues, model)
            elif args.phase == "verify":
                report = verify_projection(gh, layout, issues)
            else:
                report = {"managed_issues": len(inventory_issues(gh, layout)), "project": gh.state.get("project")}
            gh.state["last_report"] = report
            gh.save()
            print(json.dumps({"phase": args.phase, "mutations": gh.count, "report": report}, indent=2))
        except (Paused, APIError) as exc:
            print(json.dumps({"status": "PAUSED_OR_BLOCKED", "reason": str(exc), "phase": args.phase,
                              "mutations": gh.count, "pending": gh.state.get("pending")}, indent=2))
            raise SystemExit(2)


if __name__ == "__main__":
    main()
