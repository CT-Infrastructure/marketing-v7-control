#!/usr/bin/env python3
"""Read-only input checks; successful validation is not dispatch authority."""
import argparse
import json
import math
import sys
from pathlib import Path


def number(value, positive=False):
    # Bound integers before math.isfinite converts them to a float.
    return (type(value) in (int, float) and abs(value) <= sys.float_info.max
            and math.isfinite(value) and (value > 0 if positive else value >= 0))


def blockers(record, measurements=None):
    if not isinstance(record, dict):
        return ["dispatch_input_must_be_object"]
    missing = []
    for key in ("agent_image_digest", "credential_broker_ref", "g02_approval_ref"):
        if not isinstance(record.get(key), str) or not record[key].strip():
            missing.append(key)
    for key in ("provider_rpm", "provider_tpm", "provider_concurrency", "task_timeout_seconds"):
        if not number(record.get(key), positive=True):
            missing.append(key)
    for key in ("total_spend_usd", "per_task_spend_usd"):
        if not number(record.get(key)):
            missing.append(key)
    if all(number(record.get(k)) for k in ("total_spend_usd", "per_task_spend_usd")) and record["per_task_spend_usd"] > record["total_spend_usd"]:
        missing.append("per_task_spend_exceeds_total")
    headroom = record.get("approved_headroom")
    if not isinstance(headroom, dict) or any(not number(headroom.get(k)) for k in ("cpu", "memory_mib", "disk_gib", "gpu_vram_mib")):
        missing.append("approved_headroom")
    for key in ("capacity_approved", "egress_qualified", "disk_quota_qualified", "cancellation_qualified", "provider_limits_enforced", "cross_repository_source_qualified", "identity_qualified", "adapter_qualified", "subscription_entitlement_verified", "worker_environment_qualified"):
        if record.get(key) is not True:
            missing.append(key)
    for key in ("production_actions_allowed", "api_key_auth_allowed", "extra_usage_purchase_allowed"):
        if record.get(key) is not False:
            missing.append(key + "_must_be_false")
    for key, expected in (("provider", "codex-cli"), ("billing_mode", "ChatGPT subscription"), ("implementation_model", "GPT-6.1-Sol"), ("implementation_reasoning_effort", "low"), ("review_provider", "GitHub Copilot")):
        if record.get(key) != expected:
            missing.append(key)
    if measurements is not None:
        missing.extend(measurement_blockers(measurements))
    return missing


def measurement_blockers(record):
    if not isinstance(record, dict):
        return ["measurements_must_be_object"]
    errors = []
    for group, keys in {"windows": ("logical_cpu", "total_memory_mib", "available_memory_mib", "workspace_free_gib"), "wsl": ("logical_cpu", "memory_total_mib", "memory_available_mib", "root_free_gib"), "gpu": ("memory_total_mib", "memory_used_mib")}.items():
        values = record.get(group)
        if not isinstance(values, dict):
            errors.append("measurements." + group)
            continue
        for key in keys:
            if not number(values.get(key)):
                errors.append("measurements." + group + "." + key)
        pairs = {"windows": ("available_memory_mib", "total_memory_mib"), "wsl": ("memory_available_mib", "memory_total_mib"), "gpu": ("memory_used_mib", "memory_total_mib")}
        part, total = pairs[group]
        if number(values.get(part)) and number(values.get(total)) and values[part] > values[total]:
            errors.append("measurements." + group + ".memory_exceeds_total")
    if record.get("scope") != "development_only":
        errors.append("measurements.scope")
    nonadditive = record.get("not_additive")
    if not isinstance(nonadditive, list) or not {"windows_memory", "wsl_memory"}.issubset(set(x for x in nonadditive if isinstance(x, str))):
        errors.append("measurements.not_additive")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path(__file__).with_name("dispatch-inputs.json"))
    parser.add_argument("--measurements", type=Path, default=Path(__file__).with_name("measurements.json"))
    args = parser.parse_args()
    try:
        record = json.loads(args.input.read_text())
        measurements = json.loads(args.measurements.read_text())
        missing = blockers(record) + measurement_blockers(measurements)
    except (OSError, ValueError) as error:
        missing = ["unreadable_or_invalid_json:" + type(error).__name__]
    print(json.dumps({"live_dispatch": "HOLD" if missing else "INPUTS_PRESENT_QUALIFICATION_STILL_REQUIRED", "missing": missing}, indent=2))
    return 2 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
