#!/usr/bin/env python3
"""Verify source custody from immutable Git blobs; execute no source hooks."""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def verify(classification_path=None):
    revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    manifest = json.loads(subprocess.check_output(["git", "-C", str(ROOT), "cat-file", "blob", revision + ":PACKAGE_MANIFEST.json"]))
    names = [row["path"] for row in manifest["file_hashes"]]
    request = "".join(revision + ":" + name + "\n" for name in names).encode()
    result = subprocess.run(["git", "-C", str(ROOT), "cat-file", "--batch"], input=request, capture_output=True, check=True, timeout=60)
    stream = io.BytesIO(result.stdout)
    blobs = {}
    for name in names:
        header = stream.readline().split()
        if len(header) != 3 or header[1] != b"blob":
            raise ValueError("Missing original source blob: " + name)
        blobs[name] = stream.read(int(header[2]))
        if stream.read(1) != b"\n":
            raise ValueError("Invalid Git blob response")
    classification = json.loads(Path(classification_path or ROOT / "docs/provenance/file-classification.json").read_text(encoding="utf-8"))
    classified = {row["path"]: row for row in classification["files"]}
    expected = {row["path"]: row for row in manifest["file_hashes"]}
    normalization = json.loads((ROOT / "docs/provenance/git-normalization.json").read_text())
    normalized = {row["path"]: row for row in normalization["diff"]}
    if any(row["kind"] != "CRLF_TO_LF" for row in normalized.values()) or not set(normalized).issubset(expected):
        raise ValueError("Unknown source transformation")
    if set(classified) != set(expected) or len(classification["files"]) != len(expected):
        raise ValueError("Every original manifest path must be classified exactly once")
    for name, entry in expected.items():
        data = blobs.get(name)
        source_bytes = data
        if name in normalized and data is not None:
            if b"\r" in data or hashlib.sha256(data).hexdigest() != normalized[name]["git_sha256"]:
                raise ValueError("Normalized Git blob changed: " + name)
            source_bytes = data.replace(b"\n", b"\r\n")
        if source_bytes is None or len(source_bytes) != entry["bytes"] or hashlib.sha256(source_bytes).hexdigest() != entry["sha256"]:
            raise ValueError("Original source blob changed: " + name)
        if classified[name]["sha256"] != entry["sha256"] or not classified[name]["classification"]:
            raise ValueError("Classification is not bound to source bytes: " + name)
    register = json.loads((ROOT / "docs/provenance/source-register.json").read_text(encoding="utf-8"))
    workflows = json.loads(blobs["reference/workflow_catalog.json"])["workflows"]
    components = json.loads(blobs["reference/components/component_registry.json"])["components"]
    cases = list(csv.DictReader(io.StringIO(blobs["reference/acceptance/Original_Acceptance_Matrix.csv"].decode())))
    trace = list(csv.DictReader(io.StringIO(blobs["backlog/acceptance_traceability.csv"].decode())))
    legacy = json.loads(blobs["backlog/legacy_evidence_traceability.json"])["rows"]
    comparisons = [
        (register["workflow_ids"], [r["id"] for r in workflows], 190),
        (register["component_ids"], [r["component_id"] for r in components], 147),
        (register["acceptance_ids"], [r["test_id"] for r in cases], 576),
        (register["legacy_opaque_ids"], [r["opaque_source_row_id"] for r in legacy], 329),
    ]
    for actual, required, count in comparisons:
        if len(actual) != count or len(set(actual)) != count or set(actual) != set(required):
            raise ValueError("Source identity coverage changed")
    if any(r["initial_status"] != "NOT_RUN" for r in trace):
        raise ValueError("Runtime acceptance status was promoted without execution evidence")
    if register["original_source_archive_hash_independently_verified"] is not False:
        raise ValueError("Unprovided original archive cannot be attested")
    return {"status": "PASS", "scope": "IMMUTABLE_SOURCE_CUSTODY_ONLY", "tested_commit": revision,
            "manifest_paths": len(expected), "workflows": 190, "components": 147,
            "acceptance_ids": 576, "legacy_rows": 329, "reversible_csv_normalizations": len(normalized), "runtime_cases_run": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--classification")
    args = parser.parse_args()
    print(json.dumps(verify(args.classification), indent=2))
