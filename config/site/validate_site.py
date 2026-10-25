"""Offline F15 planning validator. No network, subprocesses, or writes.

Exit 0: safe incomplete planning package. Exit 1: invalid/unsafe package.
Exit 2: production readiness requested; this package never authorizes production.
Diagnostics contain field paths only, never input values.
"""
import argparse
import json
from pathlib import Path

OWNERS = {
    "domains": "DNS owner", "cidrs": "Network owner",
    "hardware": "Infrastructure owner", "accounts": "Service owner",
    "supported_versions": "Platform owner", "native_workers": "Platform owner",
    "timezone": "Business operations owner", "client_owners": "Client governance owner",
    "rpo_seconds": "Business continuity owner", "rto_seconds": "Business continuity owner",
    "provider_approvals": "Provider governance owner", "secret_references": "Security owner",
    "backup_restore": "Backup owner", "data_residency": "Privacy owner",
    "channel_permissions": "Channel compliance owner", "budget_limits": "Budget owner",
}
ENGINEERING = {
    "github_org": "CT-Infrastructure", "repository_visibility": "public",
    "repository_license": "MIT", "model": "GPT-6.1-Sol", "reasoning_effort": "low",
    "model_access": "ChatGPT subscription", "code_review": "Copilot review",
}
SAFETY = {
    "production_authorized": False, "deployment_hold": True, "outbound_state": "HOLD",
    "dns_change_hold": True, "publication_hold": True, "spend_hold": True,
    "provider_effects_hold": True, "approval_ref": None,
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("non-JSON constant")


def load(path):
    # Bound accidental oversized input and reject duplicates and NaN/Infinity.
    with Path(path).open("rb") as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("oversized document")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def validate(site, register):
    errors = []

    def keys(obj, expected, path):
        if type(obj) is not dict or set(obj) != set(expected):
            errors.append(path + ": invalid keys/object")
            return False
        return True

    def exact(actual, expected, path):
        if type(actual) is not type(expected) or actual != expected:
            errors.append(path + ": invalid fixed value")

    if keys(site, ("schema_version", "purpose", "engineering", "production", "safety"), "site"):
        exact(site["schema_version"], "1.0", "site.schema_version")
        exact(site["purpose"], "nonsecret-planning-example", "site.purpose")
        for section, expected in (("engineering", ENGINEERING), ("safety", SAFETY),
                                  ("production", dict.fromkeys(OWNERS))):
            if keys(site[section], expected, "site." + section):
                for field, value in expected.items():
                    exact(site[section][field], value, "site." + section + "." + field)
    if keys(register, ("schema_version", "decisions"), "register"):
        exact(register["schema_version"], "1.0", "register.schema_version")
        rows = register["decisions"]
        if type(rows) is not list or len(rows) != len(OWNERS):
            errors.append("register.decisions: invalid count/list")
            return errors
        seen = set()
        for row in rows:
            if not keys(row, ("id", "field", "value", "status", "owner_role", "blocker",
                              "evidence_ref", "approved_by_role", "approved_at"), "decision"):
                continue
            field = row["field"]
            if type(field) is not str or field not in OWNERS or field in seen:
                errors.append("decision.field: unknown or duplicate")
                continue
            seen.add(field)
            expected = {"id": "SITE-%02d" % (list(OWNERS).index(field) + 1),
                        "value": None, "status": "UNSET", "owner_role": OWNERS[field],
                        "evidence_ref": None, "approved_by_role": None, "approved_at": None,
                        "blocker": "Missing approved %s; blocks production use of this input, not offline mocks." % field}
            for key, value in expected.items():
                exact(row[key], value, "decision." + key)
        if seen != set(OWNERS):
            errors.append("register.decisions: incomplete coverage")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path)
    parser.add_argument("register", type=Path)
    parser.add_argument("--require-production-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        errors = validate(load(args.site), load(args.register))
    except (OSError, ValueError, RecursionError):
        print("INVALID: unreadable or malformed input; values redacted")
        return 1
    if errors:
        print("INVALID: " + "; ".join(errors))
        return 1
    if args.require_production_ready:
        print("BLOCKED: production inputs UNSET; all holds remain; separate human gates required")
        return 2
    print("VALID planning package; production BLOCKED; %d owner-role blockers" % len(OWNERS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
