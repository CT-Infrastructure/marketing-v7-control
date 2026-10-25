"""Offline tests authored for root execution; Python was not available to the author."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("validate_site", HERE / "validate_site.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class PlanningContractTests(unittest.TestCase):
    def setUp(self):
        self.site = validator.load(HERE / "site.example.json")
        self.register = validator.load(ROOT / "docs/decisions/site/decision-register.json")

    def test_safe_template_and_blocker_coverage(self):
        self.assertEqual([], validator.validate(self.site, self.register))
        self.assertEqual(set(self.site["production"]), {r["field"] for r in self.register["decisions"]})
        self.assertTrue(all(v is None for v in self.site["production"].values()))

    def test_each_production_value_fails_closed(self):
        for field in self.site["production"]:
            for injected in ("UNSET", "synthetic.invalid", "192.0.2.0/24", 0, False, [], {}):
                with self.subTest(field=field, injected=injected):
                    candidate = copy.deepcopy(self.site)
                    candidate["production"][field] = injected
                    self.assertTrue(validator.validate(candidate, self.register))

    def test_every_hold_and_approval_are_protected(self):
        for field, value in self.site["safety"].items():
            for injected in (None, False, True, 0, 1, "APPROVED"):
                if type(value) is type(injected) and value == injected:
                    continue
                candidate = copy.deepcopy(self.site)
                candidate["safety"][field] = injected
                with self.subTest(field=field, injected=injected):
                    self.assertTrue(validator.validate(candidate, self.register))

    def test_missing_and_unknown_keys(self):
        for section in (None, "engineering", "production", "safety"):
            candidate = copy.deepcopy(self.site)
            target = candidate if section is None else candidate[section]
            target.pop(next(iter(target)))
            self.assertTrue(validator.validate(candidate, self.register))
            candidate = copy.deepcopy(self.site)
            target = candidate if section is None else candidate[section]
            target["token"] = "synthetic-secret-do-not-print"
            self.assertTrue(validator.validate(candidate, self.register))

    def test_engineering_facts_cannot_grant_production_authority(self):
        for field in self.site["engineering"]:
            candidate = copy.deepcopy(self.site)
            candidate["engineering"][field] = "unapproved"
            self.assertTrue(validator.validate(candidate, self.register))

    def test_decision_tampering_and_incomplete_coverage(self):
        for field, value in (("owner_role", ""), ("status", "APPROVED"), ("value", 1),
                             ("evidence_ref", "invented"), ("approved_by_role", "invented"),
                             ("approved_at", "2026-10-25"), ("blocker", ""), ("id", "SITE-99")):
            candidate = copy.deepcopy(self.register)
            candidate["decisions"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(validator.validate(self.site, candidate))
        for rows in ([], self.register["decisions"][:-1],
                     [self.register["decisions"][0]] * len(self.register["decisions"])):
            candidate = copy.deepcopy(self.register)
            candidate["decisions"] = rows
            self.assertTrue(validator.validate(self.site, candidate))

    def test_wrong_shapes(self):
        for value in (None, [], "", 1, True):
            self.assertTrue(validator.validate(value, self.register))
            self.assertTrue(validator.validate(self.site, value))
        candidate = copy.deepcopy(self.register)
        candidate["decisions"][0]["field"] = []
        self.assertTrue(validator.validate(self.site, candidate))

    def test_parser_rejects_ambiguous_or_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{', b'\xff', b' ' * 1048577):
                path.write_bytes(raw)
                with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                    validator.load(path)

    def test_cli_exit_codes_and_redacted_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            site_path = Path(directory) / "site.json"
            register_path = Path(directory) / "register.json"
            site_path.write_text(json.dumps(self.site), encoding="utf-8")
            register_path.write_text(json.dumps(self.register), encoding="utf-8")
            command = [sys.executable, "-B", str(HERE / "validate_site.py"), str(site_path), str(register_path)]
            for extra, expected in (([], 0), (["--require-production-ready"], 2)):
                result = subprocess.run(command + extra, capture_output=True, text=True, timeout=10)
                self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
            self.site["production"]["accounts"] = "synthetic-secret-do-not-print"
            site_path.write_text(json.dumps(self.site), encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(1, result.returncode)
            self.assertNotIn("synthetic-secret-do-not-print", result.stdout + result.stderr)
            site_path.unlink()
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(1, result.returncode)


if __name__ == "__main__":
    unittest.main()
