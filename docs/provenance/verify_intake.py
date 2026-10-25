#!/usr/bin/env python3
"""Verify source custody from immutable Git blobs; execute no source hooks."""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import subprocess
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Fixed intake baseline supplied by the trusted controller's source-manifest.json.
# Never derive this trust anchor from the candidate revision or its metadata.
TRUSTED_MANIFEST_SHA256 = "c7b6564a2e4113abb25ae3bfad15f9f7a862879e8da62f5b31f2bef4c8c859a7"


def indexed(rows, label):
    """Reject ambiguous paths before building maps or Git batch requests."""
    result = {}
    for row in rows:
        name = row["path"]
        if (not isinstance(name, str) or not name or "\\" in name
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or ":" in name or any(p in ("", ".", "..") for p in name.split("/"))):
            raise ValueError("Unsafe " + label + " path")
        if name in result:
            raise ValueError("Duplicate " + label + " path: " + name)
        result[name] = row
    return result


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_custody(manifest, classification, normalization, blobs):
    expected = indexed(manifest["file_hashes"], "manifest")
    classified = indexed(classification["files"], "classification")
    normalized = indexed(normalization["diff"], "normalization")
    if set(classified) != set(expected) or set(blobs) != set(expected):
        raise ValueError("Every original manifest path must be classified and loaded exactly once")
    if not set(normalized).issubset(expected):
        raise ValueError("Unknown source transformation")
    if normalization["counts"] != {"IDENTICAL": len(expected)-len(normalized), "CRLF_TO_LF": len(normalized)}:
        raise ValueError("Normalization counts do not reconcile")
    for name, entry in expected.items():
        data = blobs[name]
        if not digest(entry["sha256"]) or type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise ValueError("Invalid manifest hash or size: " + name)
        source_bytes = data
        if name in normalized:
            row = normalized[name]
            if (row["kind"] != "CRLF_TO_LF" or not digest(row["git_sha256"])
                    or row["source_bytes"] != entry["bytes"] or row["git_bytes"] != len(data)
                    or b"\r" in data or b"\n" not in data
                    or hashlib.sha256(data).hexdigest() != row["git_sha256"]):
                raise ValueError("Invalid normalized Git blob: " + name)
            source_bytes = data.replace(b"\n", b"\r\n")
        if len(source_bytes) != entry["bytes"] or hashlib.sha256(source_bytes).hexdigest() != entry["sha256"]:
            raise ValueError("Original source blob changed: " + name)
        row = classified[name]
        if (row["sha256"] != entry["sha256"] or row["bytes"] != entry["bytes"]
                or not isinstance(row["classification"], str) or not row["classification"].strip()):
            raise ValueError("Classification is not bound to source bytes: " + name)
    return expected, normalized


def validate_register(register, blobs):
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
        if len(actual) != count or len(set(actual)) != count or len(required) != count or len(set(required)) != count or set(actual) != set(required):
            raise ValueError("Source identity coverage changed")
    if len(trace) != 576 or Counter(r["source_test_id"] for r in trace) != Counter(register["acceptance_ids"]):
        raise ValueError("Acceptance trace coverage changed")
    counts = dict(Counter(r["opaque_source_row_id"].split("-", 1)[0] for r in legacy))
    if counts != {"SERVICE": 156, "RECOVERY": 104, "ROUTE": 69} or register["legacy_counts"] != counts:
        raise ValueError("Legacy categories do not reconcile")
    if any(r["initial_status"] != "NOT_RUN" for r in trace):
        raise ValueError("Runtime acceptance status was promoted without execution evidence")
    if register["original_source_archive_hash_independently_verified"] is not False:
        raise ValueError("Unprovided original archive cannot be attested")
    if register["source_provenance"] != json.loads(blobs["reference/provenance.json"]):
        raise ValueError("Source provenance changed")


def verify(classification_path=None):
    revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    manifest_bytes = subprocess.check_output(["git", "-C", str(ROOT), "cat-file", "blob", revision + ":PACKAGE_MANIFEST.json"])
    if hashlib.sha256(manifest_bytes).hexdigest() != TRUSTED_MANIFEST_SHA256:
        raise ValueError("Package manifest differs from trusted intake baseline")
    manifest = json.loads(manifest_bytes)
    if len(manifest["file_hashes"]) != 1290:
        raise ValueError("Original manifest path count changed")
    names = list(indexed(manifest["file_hashes"], "manifest"))
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
    if stream.read():
        raise ValueError("Unexpected trailing Git batch output")
    metadata = {}
    documents = {}
    for name in ("file-classification.json", "git-normalization.json", "source-register.json"):
        path = "docs/provenance/" + name
        if name == "file-classification.json" and classification_path is not None:
            external = Path(classification_path).resolve()
            data = external.read_bytes()
            origin = {"origin": "external_file", "path": str(external)}
        else:
            data = subprocess.check_output(["git", "-C", str(ROOT), "cat-file", "blob", revision + ":" + path])
            origin = {"origin": "git_blob", "path": path, "commit": revision}
        metadata[name] = dict(origin, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
        documents[name] = json.loads(data)
    classification = documents["file-classification.json"]
    normalization = documents["git-normalization.json"]
    expected, normalized = validate_custody(manifest, classification, normalization, blobs)
    register = documents["source-register.json"]
    validate_register(register, blobs)
    return {"status": "PASS", "scope": ("MIXED_INPUT_SOURCE_CUSTODY_ONLY" if classification_path is not None
                                            else "IMMUTABLE_SOURCE_CUSTODY_ONLY"),
            "tested_commit": revision, "custody_metadata": metadata,
            "trusted_manifest_sha256": TRUSTED_MANIFEST_SHA256,
            "manifest_paths": len(expected), "workflows": 190, "components": 147,
            "acceptance_ids": 576, "legacy_rows": 329, "reversible_csv_normalizations": len(normalized), "runtime_cases_run": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--classification")
    args = parser.parse_args()
    print(json.dumps(verify(args.classification), indent=2))
