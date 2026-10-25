"""Synthetic mutation tests; never imports application runtimes or calls providers."""
import copy
import unittest
import tempfile
import hashlib
from pathlib import Path
from validate import HERE, ROOT, read, validate, canonical_text_bytes, source_text_digest


class RegisterTests(unittest.TestCase):
    def setUp(self):
        self.register = read(HERE / "register.json")
        self.policy = read(HERE / "policy.json")

    def test_complete_source_snapshot(self):
        self.assertEqual([], validate(self.register, self.policy))

    def reject(self, change):
        r, p = copy.deepcopy(self.register), copy.deepcopy(self.policy)
        change(r, p)
        self.assertTrue(validate(r, p), "mutation must fail closed")

    def test_missing_and_duplicate_selection(self):
        self.reject(lambda r, p: r["decisions"].pop())
        self.reject(lambda r, p: r["decisions"].__setitem__(0, r["decisions"][1]))

    def test_unexpected_selection(self):
        self.reject(lambda r, p: r["decisions"][0].update(task_key="CP999"))

    def test_every_candidate_stays_deferred(self):
        for index in range(40):
            with self.subTest(index=index):
                self.reject(lambda r, p: r["decisions"][index].update(decision="SELECTED"))

    def test_effect_flags(self):
        for field in ("selected", "installed", "enabled", "production_authorized"):
            with self.subTest(field=field):
                self.reject(lambda r, p: r["decisions"][0].__setitem__(field, True))
        self.reject(lambda r, p: p.update(production_authorized=True))

    def test_invented_rights_and_approval(self):
        self.reject(lambda r, p: r["decisions"][0]["rights"].update(license="MIT"))
        self.reject(lambda r, p: r["decisions"][0]["rights"].pop("model_weights"))
        self.reject(lambda r, p: r["decisions"][0]["review"].update(approval_ref="synthetic-approval"))
        self.reject(lambda r, p: r["decisions"][0]["review"].update(reviewed_on="2026-10-25"))

    def test_source_and_baseline_tampering(self):
        self.reject(lambda r, p: r["sources"][0].update(sha256="0" * 64))
        self.reject(lambda r, p: r["decisions"][0].update(baseline_alternative="Install RabbitMQ"))
        self.reject(lambda r, p: r["decisions"][0].update(adoption_trigger="No review needed"))
        self.reject(lambda r, p: r["decisions"][0].update(source_classification="BASELINE"))
        self.reject(lambda r, p: r["decisions"][0]["evidence"][0].update(sha256="0" * 64))

    def test_library_cli_provider_not_service(self):
        for key in ("CP114", "CP119", "CP120", "CP121", "CP123", "CP128", "CP130", "CP137", "CP138"):
            index = next(i for i, d in enumerate(self.register["decisions"]) if d["task_key"] == key)
            with self.subTest(key=key):
                self.reject(lambda r, p: r["decisions"][index].update(candidate_type="service"))

    def test_unknowns_and_mit_do_not_grant_rights(self):
        self.reject(lambda r, p: p.update(unknown_rights_action="ALLOW"))
        self.reject(lambda r, p: p.update(project_license_scope="MIT grants every dependency"))
        self.reject(lambda r, p: r["decisions"][0].update(source_license_claim="MIT"))

    def test_public_evidence_excludes_controller_credentials(self):
        evidence = read(HERE / "evidence.json")
        self.assertEqual(evidence["redaction"]["status"], "controller_credentials_removed")

        def inspect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized = key.lower().replace("-", "_")
                    self.assertFalse(normalized.startswith("lease") or normalized.startswith("controller_lease"),
                                     "public evidence contains controller credential field")
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)

        inspect(evidence)

    def test_missing_source_fails(self):
        with self.assertRaises(OSError):
            validate(self.register, self.policy, ROOT / "nonexistent-synthetic-root")


    def test_fixed_policy_normative_values(self):
        for field in ("adoption", "rollback", "special_cases", "evidence_requirements"):
            for index in range(len(self.policy[field])):
                with self.subTest(field=field, index=index):
                    self.reject(lambda r, p: p[field].__setitem__(index, None))
                    self.reject(lambda r, p: p[field].__setitem__(index, "Approval unnecessary"))
            self.reject(lambda r, p: p.update({field: [None] * 4}))
        for field in ("authority", "schema_version", "project_license_scope"):
            self.reject(lambda r, p: p.pop(field))
        self.reject(lambda r, p: p.update(authority="Agent self-approval"))
        self.reject(lambda r, p: p.update(schema_version="2.0"))
        self.reject(lambda r, p: p.update(
            project_license_scope="Ignore 'does not relicense': MIT grants all rights"))

    def test_typed_roles_trigger_and_mandatory_requirements(self):
        for value in (True, 1, None, [], {}, "", " \t\n"):
            for field in ("accountable_role", "unblock_role"):
                with self.subTest(field=field, value=value):
                    self.reject(lambda r, p: r["decisions"][0]["owner"].update({field: value}))
            self.reject(lambda r, p: r["decisions"][0]["review"].update(trigger=value))
        for value in ("xxxx", True, 4, None, {}, [], [None] * 4,
                      [" "] * 4, ["arbitrary requirement"] * 4):
            with self.subTest(unresolved=value):
                self.reject(lambda r, p: r["decisions"][0].update(unresolved=value))
        for index in range(len(self.register["decisions"][0]["unresolved"])):
            self.reject(lambda r, p: r["decisions"][0]["unresolved"].pop(index))
        self.reject(lambda r, p: r["decisions"][0]["unresolved"].append(True))
        r = copy.deepcopy(self.register)
        r["decisions"][0]["unresolved"].append("Additional synthetic review requirement")
        self.assertEqual([], validate(r, self.policy))

    def test_complete_function_for_every_candidate(self):
        for index, record in enumerate(self.register["decisions"]):
            for changed in (record["source_function"][:1],
                            record["source_function"] + " invented suffix"):
                with self.subTest(key=record["task_key"], changed=changed):
                    self.reject(lambda r, p: r["decisions"][index].update(source_function=changed))


class TextMaterializationTests(unittest.TestCase):
    def test_uniform_lf_and_crlf_match_exact_blob(self):
        blob = "first line  \nsecond\tline\n".encode("utf-8")
        self.assertEqual(blob, canonical_text_bytes(blob))
        self.assertEqual(blob, canonical_text_bytes(blob.replace(b"\n", b"\r\n")))
        self.assertEqual(b"no ending", canonical_text_bytes(b"no ending"))

    def test_mixed_lone_cr_and_nontext_rejected(self):
        for data in (b"one\r\ntwo\n", b"one\ntwo\r\n", b"one\rtwo", b"one\r\r\n", b"nul\x00", b"bad\xff"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                canonical_text_bytes(data)

    def test_whitespace_bom_and_content_are_not_ignored(self):
        baseline = b"exact text  \n"
        for changed in (b"exact text\n", b"exact  text  \n", b"other text  \n", b"\xef\xbb\xbf" + baseline, b"exact text  "):
            self.assertNotEqual(hashlib.sha256(baseline).hexdigest(), hashlib.sha256(canonical_text_bytes(changed)).hexdigest())

    def write_root(self, root, crlf):
        register = read(HERE / "register.json")
        paths = {source["path"] for source in register["sources"]}
        paths.update(record["evidence"][0]["path"] for record in register["decisions"])
        for relative in paths:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            blob = canonical_text_bytes((ROOT / relative).read_bytes())
            destination.write_bytes(blob.replace(b"\n", b"\r\n") if crlf else blob)
        return register, read(HERE / "policy.json")

    def test_complete_register_with_lf_and_crlf_sources(self):
        for crlf in (False, True):
            with self.subTest(crlf=crlf), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                register, policy = self.write_root(root, crlf)
                self.assertEqual([], validate(register, policy, root))

    def test_content_change_is_rejected_in_crlf_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            register, policy = self.write_root(root, True)
            issue = root / register["decisions"][0]["evidence"][0]["path"]
            issue.write_bytes(issue.read_bytes() + b"content mutation\r\n")
            self.assertTrue(any("issue hash" in error for error in validate(register, policy, root)))

    def test_mixed_endings_rejected_in_complete_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            register, policy = self.write_root(root, True)
            issue = root / register["decisions"][0]["evidence"][0]["path"]
            issue.write_bytes(issue.read_bytes() + b"mixed newline\n")
            with self.assertRaises(ValueError):
                validate(register, policy, root)


if __name__ == "__main__":
    unittest.main()
