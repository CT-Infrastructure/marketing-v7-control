"""Canonical-byte regressions; temporary synthetic files only."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
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


if __name__ == "__main__": unittest.main()
