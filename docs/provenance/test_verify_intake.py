"""Synthetic custody regression tests; no Git, network, or source scripts run."""
import copy
import hashlib
import json
import unittest
import io
import tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import verify_intake
from verify_intake import indexed, validate_custody, validate_register


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.source = b"alpha\r\nbeta\r\n"
        self.blob = self.source.replace(b"\r\n", b"\n")
        row = {"path": "input/data.csv", "bytes": len(self.source),
               "sha256": hashlib.sha256(self.source).hexdigest()}
        self.manifest = {"file_hashes": [row]}
        self.classification = {"files": [dict(row, classification="sanitized") ]}
        self.normalization = {"counts": {"IDENTICAL": 0, "CRLF_TO_LF": 1}, "diff": [
            {"path": row["path"], "kind": "CRLF_TO_LF", "source_bytes": len(self.source),
             "git_bytes": len(self.blob), "git_sha256": hashlib.sha256(self.blob).hexdigest()}]}
        self.blobs = {row["path"]: self.blob}

    def check(self):
        return validate_custody(self.manifest, self.classification, self.normalization, self.blobs)

    def test_reversible_normalization(self):
        self.assertEqual(len(self.check()[0]), 1)

    def test_identical_source(self):
        self.blobs["input/data.csv"] = self.source
        self.normalization = {"counts": {"IDENTICAL": 1, "CRLF_TO_LF": 0}, "diff": []}
        self.check()

    def test_duplicate_paths_rejected_in_all_registers(self):
        for key, document in [("file_hashes", self.manifest), ("files", self.classification),
                              ("diff", self.normalization)]:
            with self.subTest(key=key):
                document[key].append(copy.deepcopy(document[key][0]))
                with self.assertRaises(ValueError):
                    self.check()
                document[key].pop()

    def test_unsafe_paths_rejected(self):
        for path in ["", "/absolute", "../escape", "a/../b", "a//b", "a/./b",
                     "C:/drive", "a\\b", "x\ny", "x\ry", "x\x00y"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                indexed([{"path": path}], "fixture")

    def test_classification_metadata_bound(self):
        for key, value in [("bytes", 999), ("sha256", "0"*64), ("classification", " ")]:
            with self.subTest(key=key):
                original = self.classification["files"][0][key]
                self.classification["files"][0][key] = value
                with self.assertRaises(ValueError):
                    self.check()
                self.classification["files"][0][key] = original

    def test_empty_and_non_string_classifications_rejected(self):
        for value in ["", " ", "\t\r\n", None, False, 0, [], {}]:
            with self.subTest(value=value):
                self.classification["files"][0]["classification"] = value
                with self.assertRaisesRegex(ValueError, "Classification is not bound"):
                    self.check()

    def test_normalization_metadata_bound(self):
        for key, value in [("source_bytes", 999), ("git_bytes", 999),
                           ("git_sha256", "0"*64), ("kind", "UNKNOWN")]:
            with self.subTest(key=key):
                original = self.normalization["diff"][0][key]
                self.normalization["diff"][0][key] = value
                with self.assertRaises(ValueError):
                    self.check()
                self.normalization["diff"][0][key] = original

    def test_changed_blob_rejected(self):
        self.blobs["input/data.csv"] = b"changed\n"
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_and_extra_blobs_rejected(self):
        for blobs in [{}, dict(self.blobs, extra=b"extra")]:
            with self.subTest(blobs=blobs):
                self.blobs = blobs
                with self.assertRaises(ValueError):
                    self.check()

    def test_counts_rejected(self):
        self.normalization["counts"]["IDENTICAL"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_manifest_digest_and_size_rejected(self):
        for key, value in [("sha256", "BAD"), ("bytes", True), ("bytes", -1)]:
            with self.subTest(key=key):
                original = self.manifest["file_hashes"][0][key]
                self.manifest["file_hashes"][0][key] = value
                with self.assertRaises(ValueError):
                    self.check()
                self.manifest["file_hashes"][0][key] = original


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.register = {
            "workflow_ids": [f"W{i}" for i in range(190)],
            "component_ids": [f"C{i}" for i in range(147)],
            "acceptance_ids": [f"A{i}" for i in range(576)],
            "legacy_opaque_ids": [f"{kind}-{i:03}" for kind, count in
                                  [("SERVICE", 156), ("RECOVERY", 104), ("ROUTE", 69)]
                                  for i in range(1, count+1)],
            "legacy_counts": {"SERVICE": 156, "RECOVERY": 104, "ROUTE": 69},
            "acceptance_traceability_status": {"NOT_RUN": 576},
            "original_source_archive_hash_independently_verified": False,
            "source_provenance": {"fixture": True}}
        self.blobs = {
            "reference/workflow_catalog.json": json.dumps({"workflows": [
                {"id": x} for x in self.register["workflow_ids"]]}).encode(),
            "reference/components/component_registry.json": json.dumps({"components": [
                {"component_id": x} for x in self.register["component_ids"]]}).encode(),
            "reference/acceptance/Original_Acceptance_Matrix.csv": (
                "test_id\n" + "\n".join(self.register["acceptance_ids"])).encode(),
            "backlog/acceptance_traceability.csv": ("source_test_id,initial_status\n" +
                "\n".join(x+",NOT_RUN" for x in self.register["acceptance_ids"])).encode(),
            "backlog/legacy_evidence_traceability.json": json.dumps({"rows": [
                {"opaque_source_row_id": x} for x in self.register["legacy_opaque_ids"]]}).encode(),
            "reference/provenance.json": b'{"fixture": true}'}

    def test_complete_fixture(self):
        validate_register(self.register, self.blobs)

    def test_missing_trace_rejected(self):
        key = "backlog/acceptance_traceability.csv"
        self.blobs[key] = self.blobs[key].rsplit(b"\n", 1)[0]
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)

    def test_runtime_promotion_rejected(self):
        key = "backlog/acceptance_traceability.csv"
        self.blobs[key] = self.blobs[key].replace(b"NOT_RUN", b"PASS", 1)
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)

    def test_promoted_status_summary_rejected(self):
        for summary in [{"PASS": 576}, {"NOT_RUN": 575, "PASS": 1}]:
            with self.subTest(summary=summary):
                self.register["acceptance_traceability_status"] = summary
                with self.assertRaisesRegex(ValueError, "status summary does not reconcile"):
                    validate_register(self.register, self.blobs)

    def test_malformed_status_summaries_rejected(self):
        for summary in [None, [], "NOT_RUN", 576, {}, {"NOT_RUN": 575},
                        {"NOT_RUN": -576}, {"NOT_RUN": "576"},
                        {"NOT_RUN": 576.0}, {"NOT_RUN": True},
                        {"NOT_RUN": 576, "PASS": 0}]:
            with self.subTest(summary=summary):
                self.register["acceptance_traceability_status"] = summary
                with self.assertRaisesRegex(ValueError, "status summary does not reconcile"):
                    validate_register(self.register, self.blobs)

    def test_missing_status_summary_rejected(self):
        del self.register["acceptance_traceability_status"]
        with self.assertRaisesRegex(ValueError, "status summary does not reconcile"):
            validate_register(self.register, self.blobs)

    def test_archive_attestation_rejected(self):
        self.register["original_source_archive_hash_independently_verified"] = True
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)

    def test_provenance_drift_rejected(self):
        self.register["source_provenance"]["fixture"] = False
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)

    def test_duplicate_source_identity_rejected(self):
        key = "reference/workflow_catalog.json"
        data = json.loads(self.blobs[key])
        data["workflows"].append(data["workflows"][0])
        self.blobs[key] = json.dumps(data).encode()
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)

    def test_category_drift_rejected(self):
        self.register["legacy_counts"]["SERVICE"] = 157
        with self.assertRaises(ValueError):
            validate_register(self.register, self.blobs)


class RevisionBindingTests(unittest.TestCase):
    """Exercise the real wrapper and validators with only Git transport mocked."""
    def setUp(self):
        fixture = RegisterTests()
        fixture.setUp()
        self.blobs = fixture.blobs
        for i in range(1290 - len(self.blobs)):
            self.blobs[f"fixture/{i}.txt"] = b"synthetic"
        rows = [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in self.blobs.items()]
        self.metadata = {
            "file-classification.json": json.dumps({"files": [dict(row, classification="sanitized") for row in rows]}).encode(),
            "git-normalization.json": json.dumps({"counts": {"IDENTICAL": 1290, "CRLF_TO_LF": 0}, "diff": []}).encode(),
            "source-register.json": json.dumps(fixture.register).encode()}
        self.manifest = json.dumps({"file_hashes": rows}).encode()
        self.trusted_manifest_digest = hashlib.sha256(self.manifest).hexdigest()
        self.revision = "f" * 40

    def output(self, args, **kwargs):
        if args[-2:] == ["rev-parse", "HEAD"]:
            return self.revision + "\n"
        spec = args[-1]
        self.assertTrue(spec.startswith(self.revision + ":"))
        path = spec.split(":", 1)[1]
        if path == "PACKAGE_MANIFEST.json":
            return self.manifest
        return self.metadata[path.removeprefix("docs/provenance/")]

    def batch(self, args, **kwargs):
        stream = io.BytesIO()
        for spec in kwargs["input"].decode().splitlines():
            self.assertTrue(spec.startswith(self.revision + ":"))
            data = self.blobs[spec.split(":", 1)[1]]
            stream.write(b"0" * 40 + b" blob " + str(len(data)).encode() + b"\n" + data + b"\n")
        return SimpleNamespace(stdout=stream.getvalue())

    def run_verify(self, external=None):
        with patch.object(verify_intake, "TRUSTED_MANIFEST_SHA256", self.trusted_manifest_digest), patch.object(verify_intake.subprocess, "check_output", side_effect=self.output), patch.object(verify_intake.subprocess, "run", side_effect=self.batch):
            return verify_intake.verify(external)

    def test_manifest_raw_bytes_must_match_fixed_baseline(self):
        self.manifest += b" "  # Semantically identical JSON still changes custody bytes.
        with patch.object(verify_intake.subprocess, "run", side_effect=AssertionError("inventory loaded before trust check")):
            with self.assertRaisesRegex(ValueError, "trusted intake baseline"):
                self.run_verify()

    def test_coordinated_manifest_and_classification_removal_rejected(self):
        manifest = json.loads(self.manifest)
        classification = json.loads(self.metadata["file-classification.json"])
        removed = manifest["file_hashes"].pop()
        classification["files"] = [r for r in classification["files"] if r["path"] != removed["path"]]
        self.blobs.pop(removed["path"])
        self.manifest = json.dumps(manifest).encode()
        self.metadata["file-classification.json"] = json.dumps(classification).encode()
        with self.assertRaisesRegex(ValueError, "trusted intake baseline"):
            self.run_verify()

    def test_same_count_manifest_replacement_rejected(self):
        manifest = json.loads(self.manifest)
        manifest["file_hashes"][-1]["path"] = "attacker/replacement.txt"
        self.manifest = json.dumps(manifest).encode()
        with self.assertRaisesRegex(ValueError, "trusted intake baseline"):
            self.run_verify()

    def test_dirty_working_metadata_is_never_read(self):
        # Old wrapper read local JSON here, allowing dirty metadata under a commit label.
        with patch.object(Path, "read_text", side_effect=AssertionError("working tree read")), patch.object(Path, "read_bytes", side_effect=AssertionError("working tree read")):
            result = self.run_verify()
        self.assertEqual(result["scope"], "IMMUTABLE_SOURCE_CUSTODY_ONLY")
        for name, data in self.metadata.items():
            receipt = result["custody_metadata"][name]
            self.assertEqual(receipt["commit"], self.revision)
            self.assertEqual(receipt["origin"], "git_blob")
            self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())

    def test_invalid_committed_metadata_cannot_be_masked_by_working_copy(self):
        register = json.loads(self.metadata["source-register.json"])
        register["original_source_archive_hash_independently_verified"] = True
        self.metadata["source-register.json"] = json.dumps(register).encode()
        with self.assertRaisesRegex(ValueError, "Unprovided original archive"):
            self.run_verify()

    def test_promoted_committed_status_summary_rejected(self):
        register = json.loads(self.metadata["source-register.json"])
        register["acceptance_traceability_status"] = {"PASS": 576}
        self.metadata["source-register.json"] = json.dumps(register).encode()
        with self.assertRaisesRegex(ValueError, "status summary does not reconcile"):
            self.run_verify()

    def test_external_classification_is_hashed_and_marked_mixed(self):
        classification = json.loads(self.metadata["file-classification.json"])
        classification["files"][0]["classification"] = "external review label"
        data = json.dumps(classification).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "classification.json"
            path.write_bytes(data)
            result = self.run_verify(path)
            receipt = result["custody_metadata"]["file-classification.json"]
            self.assertEqual(receipt["path"], str(path.resolve()))
        self.assertEqual(result["scope"], "MIXED_INPUT_SOURCE_CUSTODY_ONLY")
        self.assertEqual(receipt["origin"], "external_file")
        self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(receipt["bytes"], len(data))
        self.assertNotIn("commit", receipt)

    def test_invalid_external_classification_still_fails_custody(self):
        classification = json.loads(self.metadata["file-classification.json"])
        classification["files"][0]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "classification.json"
            path.write_text(json.dumps(classification))
            with self.assertRaisesRegex(ValueError, "Classification is not bound"):
                self.run_verify(path)


if __name__ == "__main__":
    unittest.main()
