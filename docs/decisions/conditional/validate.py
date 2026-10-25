"""Offline F19 safety and source-fidelity checks; standard library only, no writes."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


# Fixed approved version; changes require a reviewed successor.
APPROVED_POLICY = json.loads(r'''{
  "schema_version": "1.0",
  "default_decision": "DEFERRED",
  "production_authorized": false,
  "project_license_scope": "MIT covers original project work only. It does not relicense third-party applications, dependencies, plugins, model weights, datasets, fonts or media.",
  "unknown_rights_action": "BLOCK_ADOPTION",
  "authority": "Named human selection approval permits scoped engineering only. Independent reviewer and trusted integration controller own acceptance. OpenProject retains business/budget/publication approval.",
  "adoption": [
    "Record a measured unmet need and compare the named baseline without disabling it. Assign a named owner and review date.",
    "Identify exact upstream repository, immutable version/digest, edition and feature boundaries; collect authoritative license texts and terms with hashes/date. Source labels are unverified claims.",
    "Inventory all transitive dependencies, DB/cache supported versions, native workers, image layers, plugins, model weights, training/dataset rights where relevant, fonts/codecs/media, provider/account terms. Mark N/A only with reviewed rationale. Unknown blocks selection.",
    "Review redistribution, modification, notices, source-offer/copyleft/network-use obligations, commercial restrictions and output rights with authorized legal/security reviewers; do not infer rights from project MIT.",
    "Document least privilege, data flows, retention, health, upgrades, backup/restore, resource and spend ceilings, synthetic acceptance tests and rollback. Do not turn CLI/library/plugin/provider/capacity into an invented service.",
    "Obtain named human decision bound to evidence/version/edition, scope, owner, budget, expiry and rollback. Record independent review. No agent self-approval.",
    "Request separately scoped controller-owned graph/task changes and accepted prerequisites; this register never enables tasks. Qualify in disposable offline/mock scope first.",
    "Obtain independent exact-candidate test/review and trusted merge receipt; production remains disabled pending separate verified human gates."
  ],
  "rollback": [
    "Default feature flag off; keep baseline route and data authority usable. Rehearse fallback with optional dependency absent and unavailable.",
    "Hold new submissions; reconcile native/provider IDs and UNKNOWN outcomes before retry or switching routes. Retain receipts and reservations.",
    "Export portable data and verify isolated restore; undo scoped configuration and routes using reviewed migration reversal. Never assume an external effect is undone by snapshot restore.",
    "Revoke only candidate-scoped access through an authorized operator; preserve audit and notices under retention policy. Record rollback evidence and return decision to DEFERRED through reviewed change."
  ],
  "special_cases": [
    "Activepieces remains cross-application orchestrator; Postiz-internal Temporal is baseline and is distinct from CP100 general-purpose use.",
    "LiveKit is an architectural alternative to Asterisk/Pipecat, not an automatic add-on; FreeSWITCH does not silently replace Asterisk.",
    "SIPp is test-only; python-email-validator, CookieConsent and Google Ads client are libraries; WooCommerce and Site Reviews are WordPress plugins.",
    "mailcow or Mailu requires choosing one only; compound bundles require separate rights/dependency review for every member.",
    "Model/checkpoint/node rights require exact artifact-level review distinct from runtime code licenses; OSS-core labels grant no paid-edition entitlement.",
    "External provider, dedicated IP and capacity are not installable software licenses. No DNS, relay, ad, spend or publication effects are authorized.",
    "SOPS/age and Keycloak alternatives confer no decryption authority. Native/firmware/OS management is not containerized by default."
  ],
  "evidence_requirements": [
    "Exact version/source/digest and license/edition rights review",
    "Full dependency and supported DB/cache/native-worker matrix",
    "Named human owner, rationale, evidence, review date and approval expiry",
    "Threat model and least privilege",
    "Measured baseline gap and resource/cost ceiling",
    "Offline/mock tests, failure fallback and isolated rollback evidence",
    "Independent review and trusted controller receipts"
  ]
}''')
REQUIRED_UNRESOLVED = json.loads(r'''["Named accountable owner and measured gap evidence","Exact upstream version/edition and complete dependency/runtime/DB/cache/worker inventory","License, distribution, network-use, model and provider rights evidence as applicable","Resource budget, threat model, rollback drill and separately authorized gates"]''')

def meaningful_text(value):
    return isinstance(value, str) and bool(value.strip())

def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def canonical_text_bytes(data):
    """Only reversible uniform CRLF-to-LF materialization; preserve all other bytes."""
    if not isinstance(data, bytes):
        raise TypeError("source text must be bytes")
    data.decode("utf-8", errors="strict")
    if b"\x00" in data:
        raise ValueError("declared text source contains NUL")
    if b"\r" in data:
        residual = data.replace(b"\r\n", b"")
        if b"\r" in residual or b"\n" in residual:
            raise ValueError("mixed or lone-CR line endings in declared text source")
        return data.replace(b"\r\n", b"\n")
    return data


def source_text_digest(path):
    return hashlib.sha256(canonical_text_bytes(Path(path).read_bytes())).hexdigest()


def validate(register, policy, root=ROOT):
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def digest(path):
        return source_text_digest(path)

    def source(path):
        candidate = (root / path).resolve()
        if not candidate.is_relative_to(root.resolve()):
            raise ValueError("source escapes root")
        return candidate

    require(register.get("schema_version") == "1.0", "register version")
    require(register.get("task_key") == "F19", "task binding")
    require(register.get("base_revision") == "11f7a5f0aab4b41966e9d6134215b1a3823a8e95", "base binding")
    require(register.get("input_sha256") == "5a9de3688de0bd6d06740f2402b74a326a942620340f55acc0b7b49085235ab3", "input binding")
    require(register.get("default_decision") == "DEFERRED", "register default")
    require(policy.get("default_decision") == "DEFERRED", "policy default")
    require(policy.get("production_authorized") is False, "policy production")
    require(policy.get("unknown_rights_action") == "BLOCK_ADOPTION", "unknown rights fail closed")
    # Bind normative values rather than list lengths or license substrings.
    for field, approved in APPROVED_POLICY.items():
        require(policy.get(field) == approved, "policy " + field)

    graph = read(root / "orchestration/task_graph.json")
    tasks = {t["key"]: t for t in graph["tasks"] if t["kind"] == "selection"}
    components = {c["component_id"]: c for c in read(root / "reference/components/component_registry.json")["components"]}
    records = register.get("decisions", [])
    keys = [r.get("task_key") for r in records]
    require(len(tasks) == 40 and register.get("expected_count") == 40, "source count")
    require(len(records) == 40 and len(set(keys)) == 40 and set(keys) == set(tasks), "exact selection coverage")
    required_sources = {"orchestration/task_graph.json", "reference/components/component_registry.json",
                        "reference/architecture/Consolidated_Self_Hosted_Technology_Stack_v7_Integrated.md",
                        "reference/architecture/Integration_Contracts.md", "reference/mermaid/A00.mmd",
                        "reference/mermaid/V07.mmd", "reference/workflows/V07.json", "LICENSING.md",
                        "backlog/issues/F19.md", "AGENTS.md", "docs/orchestration/EXECUTION_PROTOCOL.md"}
    require({s["path"] for s in register.get("sources", [])} == required_sources, "source inventory")
    for s in register.get("sources", []):
        require(digest(source(s["path"])) == s["sha256"], "source hash " + s["path"])
    allowed_types = {"service", "native-service", "adapter", "service-bundle", "native-service-alternatives",
                     "architecture-alternative", "model-runtime", "test-cli", "service-alternatives", "cli",
                     "library", "external-provider", "desktop-application", "model-plugin-bundle",
                     "model-checkpoints", "capacity", "plugin"}
    fixed_types = {"CP110": "architecture-alternative", "CP114": "test-cli", "CP119": "cli", "CP120": "library",
                   "CP121": "external-provider", "CP123": "cli", "CP124": "desktop-application",
                   "CP125": "model-plugin-bundle", "CP126": "model-checkpoints", "CP127": "library",
                   "CP128": "capacity", "CP130": "plugin", "CP136": "plugin", "CP137": "library", "CP138": "library"}
    for r in records:
        key = r.get("task_key")
        if key not in tasks:
            continue
        t, c = tasks[key], components[key]
        prefix = key + ": "
        require(t["initial_state"] == "DEFERRED" and t["enabled_by_default"] is False and t["production_authorized"] is False, prefix + "source deferred invariant")
        require(r.get("name") == t["component_name"] == c["name"], prefix + "name")
        require(r.get("source_classification") == c["source_classification"] == "CONDITIONAL_NOT_INSTALLED", prefix + "classification")
        require(r.get("source_deployment_mode") == c["deployment_mode"] == "conditional-no-install", prefix + "deployment")
        require(r.get("source_supports_workflows") == c["supports_workflows"], prefix + "workflow fidelity")
        require(r.get("decision") == "DEFERRED", prefix + "decision")
        for flag in ("selected", "installed", "enabled", "production_authorized"):
            require(r.get(flag) is False, prefix + flag)
        require(r.get("candidate_type") in allowed_types, prefix + "type")
        if key in fixed_types:
            require(r.get("candidate_type") == fixed_types[key], prefix + "special type")
        for field in ("adoption_trigger", "baseline_alternative", "rationale", "source_function", "type_basis"):
            require(isinstance(r.get(field), str) and bool(r[field].strip()), prefix + field)
        rights = r.get("rights", {})
        require(set(rights) == {"verification", "license", "edition", "version", "dependencies", "model_weights", "datasets", "fonts_media", "provider_terms", "evidence"}, prefix + "rights fields")
        require(all(v == "UNKNOWN" for k, v in rights.items() if k != "evidence") and rights.get("evidence") == [], prefix + "no invented rights")
        owner = r.get("owner", {})
        require(owner.get("named_person") is None and meaningful_text(owner.get("accountable_role")) and meaningful_text(owner.get("unblock_role")), prefix + "owner unresolved")
        review = r.get("review", {})
        require(review.get("recorded_on") == "2026-10-25" and review.get("reviewed_on") is None and review.get("next_review_on") is None, prefix + "no invented review date")
        require(meaningful_text(review.get("trigger")) and review.get("approval_ref") is None and review.get("independent_review_ref") is None, prefix + "no invented approval")
        unresolved = r.get("unresolved")
        require(isinstance(unresolved, list)
                and all(meaningful_text(item) for item in unresolved)
                and all(item in unresolved for item in REQUIRED_UNRESOLVED),
                prefix + "unresolved requirements")
        require(r.get("adoption_process_ref") == "policy.json#/adoption" and r.get("rollback_process_ref") == "policy.json#/rollback", prefix + "process refs")
        evidence = r.get("evidence", [])
        require(len(evidence) == 2, prefix + "evidence count")
        if len(evidence) != 2:
            continue
        issue, architecture = evidence
        require(issue.get("path") == t["body_path"], prefix + "issue path")
        issue_path = source(t["body_path"])
        require(digest(issue_path) == issue.get("sha256") == t["body_sha256"], prefix + "issue hash")
        functions = [line[len("**Functions:** "):]
                     for line in issue_path.read_text(encoding="utf-8-sig").splitlines()
                     if line.startswith("**Functions:** ")]
        require(len(functions) == 1 and r.get("source_function") == functions[0],
                prefix + "function fidelity")
        arch_path = "reference/architecture/Consolidated_Self_Hosted_Technology_Stack_v7_Integrated.md"
        require(architecture.get("path") == arch_path, prefix + "architecture path")
        row = architecture.get("source_row", "")
        require(row in source(arch_path).read_text(encoding="utf-8-sig").splitlines(), prefix + "source row")
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        is_new = int(key[2:]) >= 130
        require(len(cells) == (5 if is_new else 3), prefix + "row shape")
        if len(cells) == (5 if is_new else 3):
            # Bind each evidence row to this candidate, not just any valid source row.
            require(c["name"] in cells[0], prefix + "row identity")
            require(r["baseline_alternative"] == cells[2], prefix + "baseline fidelity")
            require(r["adoption_trigger"] == cells[4 if is_new else 1], prefix + "trigger fidelity")
            require(r.get("source_license_claim") == (cells[3] if is_new else None), prefix + "claim fidelity")
            require(architecture.get("section") == ("2.2" if is_new else "2.1"), prefix + "section")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        errors = validate(read(HERE / "register.json"), read(HERE / "policy.json"), args.root)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        print("FAIL: malformed or missing input: " + str(exc))
        return 1
    for error in errors:
        print("FAIL: " + error)
    if not errors:
        print("PASS: 40 deferred decisions; source fidelity and fail-closed policy")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
