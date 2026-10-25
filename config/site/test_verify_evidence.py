"""Canonical-byte regressions; temporary synthetic files only."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import verify_evidence as evidence


class EvidenceHashTests(unittest.TestCase):
    def test_actual_final_candidate(self):
        self.assertEqual(evidence.verify(Path(__file__).resolve().parents[2]), 8)

    def test_lf_exact_and_explicit_uniform_crlf(self):
        raw = "synthetic \u00e9\nsecond\n".encode("utf-8")
        crlf = raw.replace(b"\n", b"\r\n")
        self.assertEqual(evidence.canonical_bytes(raw), raw)
        with self.assertRaises(ValueError): evidence.canonical_bytes(crlf)
        self.assertEqual(evidence.canonical_bytes(crlf, normalize_crlf=True), raw)
        self.assertNotEqual(evidence.canonical_bytes(raw), evidence.canonical_bytes(raw.rstrip(b"\n")))

    def test_mixed_lone_cr_bom_and_invalid_encoding_rejected(self):
        for raw in (b"one\r\ntwo\n", b"one\rtwo", b"\xef\xbb\xbftext\n", b"\xff"):
            for normalize in (False, True):
                with self.subTest(raw=raw, normalize=normalize), self.assertRaises((ValueError, UnicodeError)):
                    evidence.canonical_bytes(raw, normalize_crlf=normalize)

    def make_fixture(self, root, *, crlf=False):
        raw = b"synthetic-content\nsecond-line\n"
        hashes = {}
        for relative in evidence.ARTIFACT_PATHS:
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw.replace(b"\n", b"\r\n") if crlf else raw)
            hashes[relative] = hashlib.sha256(raw).hexdigest()
        manifest = dict(hash_policy=evidence.POLICY, artifact_hashes=hashes, manifest_excludes_itself=True)
        path = root / "docs/decisions/site/evidence-manifest.json"
        text = json.dumps(manifest, indent=2).encode() + b"\n"
        path.write_bytes(text.replace(b"\n", b"\r\n") if crlf else text)

    def test_complete_uniform_crlf_materialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.make_fixture(root, crlf=True)
            with self.assertRaises(ValueError): evidence.verify(root)
            self.assertEqual(evidence.verify(root, normalize_crlf=True), 8)

    def test_content_tamper_and_missing_coverage_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self.make_fixture(root)
            path = root / "config/site/site.example.json"
            path.write_bytes(path.read_bytes().replace(b"synthetic", b"modified"))
            with self.assertRaises(ValueError): evidence.verify(root)
            self.make_fixture(root)
            manifest_path = root / "docs/decisions/site/evidence-manifest.json"
            manifest = json.loads(manifest_path.read_text()); manifest["artifact_hashes"].pop("config/site/site.example.json")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError): evidence.verify(root)

    def link(self, link, target, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows symbolic link privilege unavailable; required on Linux")
            raise

    def test_manifest_symlink_escape_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);root=parent/"root";self.make_fixture(root)
            manifest=root/"docs/decisions/site/evidence-manifest.json"
            outside=parent/"outside-manifest.json";outside.write_bytes(manifest.read_bytes())
            manifest.unlink();self.link(manifest,outside)
            with mock.patch.object(Path,"read_bytes",side_effect=AssertionError("must reject before read")):
                with self.assertRaises(ValueError): evidence.verify(root)

    def test_manifest_parent_symlink_escape_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);outside=parent/"outside";self.make_fixture(outside)
            root=parent/"root";root.mkdir();self.link(root/"docs",outside/"docs",directory=True)
            with mock.patch.object(Path,"read_bytes",side_effect=AssertionError("must reject before read")):
                with self.assertRaises(ValueError): evidence.verify(root)

    def test_artifact_parent_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);outside=parent/"outside";self.make_fixture(outside)
            root=parent/"root";manifest=root/"docs/decisions/site/evidence-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes((outside/"docs/decisions/site/evidence-manifest.json").read_bytes())
            # Copy in-root docs artifacts; all config artifacts are behind an escaping link.
            for name in ("README.md","RUNBOOK.md","decision-register.json"):
                (manifest.parent/name).write_bytes((outside/"docs/decisions/site"/name).read_bytes())
            self.link(root/"config",outside/"config",directory=True)
            with self.assertRaises(ValueError): evidence.verify(root)

    def test_nonregular_manifest_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.make_fixture(root)
            manifest=root/"docs/decisions/site/evidence-manifest.json"
            manifest.unlink();manifest.mkdir()
            with mock.patch.object(Path,"read_bytes",side_effect=AssertionError("must reject before read")):
                with self.assertRaises(ValueError): evidence.verify(root)

    def test_utf16_utf32_manifest_not_autodetected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.make_fixture(root)
            manifest=root/"docs/decisions/site/evidence-manifest.json"
            text=json.dumps(json.loads(manifest.read_text(encoding="utf-8")),separators=(",",":"))
            for encoding in ("utf-16-le","utf-16-be","utf-32-le","utf-32-be","utf-16","utf-32"):
                for normalize in (False,True):
                    manifest.write_bytes(text.encode(encoding))
                    with self.subTest(encoding=encoding,normalize=normalize),self.assertRaises((ValueError,UnicodeError)):
                        evidence.verify(root,normalize_crlf=normalize)


if __name__ == "__main__": unittest.main()
