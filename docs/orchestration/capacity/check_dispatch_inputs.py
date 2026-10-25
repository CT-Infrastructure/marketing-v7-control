#!/usr/bin/env python3
"""Report missing dispatch authority; never claim, launch, or alter policy."""
import argparse
import json
from pathlib import Path


def blockers(record):
    missing = []
    for key in ("provider", "provider_rpm", "provider_tpm", "provider_concurrency", "total_spend_usd", "per_task_spend_usd",
                "task_timeout_seconds", "approved_headroom", "agent_image_digest", "credential_broker_ref", "g02_approval_ref"):
        value = record.get(key)
        if value is None or value == "" or value == {}:
            missing.append(key)
    for key in ("capacity_approved", "egress_qualified", "disk_quota_qualified", "cancellation_qualified", "provider_limits_enforced", "cross_repository_source_qualified"):
        if record.get(key) is not True:
            missing.append(key)
    if record.get("production_actions_allowed") is not False:
        missing.append("production_actions_allowed_must_be_false")
    return missing


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path(__file__).with_name("dispatch-inputs.json"))
    args = parser.parse_args()
    record = json.loads(args.input.read_text())
    missing = blockers(record)
    print(json.dumps({"live_dispatch": "HOLD" if missing else "INPUTS_PRESENT_QUALIFICATION_STILL_REQUIRED", "missing": missing}, indent=2))
    raise SystemExit(2 if missing else 0)
