"""Exercise multi-repository routing without external calls."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from seed_github_multi import bind_journal, load_layout, plan, relationships


class Journal:
    def __init__(self):
        self.state = {}
    def save(self):
        pass


class LayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issues = json.loads((ROOT / "backlog/issues.json").read_text())["issues"]
        cls.layout = load_layout(ROOT / "config/repositories.json", cls.issues)

    def validate_modified(self, layout):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "layout.json"
            path.write_text(json.dumps(layout))
            return load_layout(path, self.issues)

    def test_complete_unique_routing_and_original_edges(self):
        report = plan(self.layout, self.issues)
        self.assertEqual(report["issues"], 785)
        self.assertEqual(sum(report["repositories"].values()), 785)
        self.assertEqual(len(report["repositories"]), 8)
        self.assertEqual(report["parent_links"], 784)
        self.assertEqual(report["dependency_links"], 4848)
        self.assertGreater(report["cross_repository_dependency_links"], 0)

    def test_missing_issue_rejected(self):
        layout = copy.deepcopy(self.layout)
        layout["issue_repositories"].pop("F01")
        with self.assertRaises(ValueError):
            self.validate_modified(layout)

    def test_unknown_repository_rejected(self):
        layout = copy.deepcopy(self.layout)
        layout["issue_repositories"]["F01"] = "unapproved"
        with self.assertRaises(ValueError):
            self.validate_modified(layout)

    def test_duplicate_repository_rejected(self):
        layout = copy.deepcopy(self.layout)
        layout["repositories"].append(layout["repositories"][0])
        with self.assertRaises(ValueError):
            self.validate_modified(layout)

    def test_journal_rejects_layout_drift(self):
        journal = Journal()
        bind_journal(journal, self.layout)
        changed = copy.deepcopy(self.layout)
        changed["issue_repositories"]["F01"] = "marketing-v7-email"
        with self.assertRaises(ValueError):
            bind_journal(journal, changed)

    def test_cross_repository_relationship_targets_actual_parent(self):
        issues = [{"key": "P", "parent_key": None, "depends_on": []},
                  {"key": "C", "parent_key": "P", "depends_on": ["P"]}]
        layout = {"owner": "test", "repositories": [{"name": "a"}, {"name": "b"}],
                  "issue_repositories": {"P": "a", "C": "b"}}

        class Fake:
            def __init__(self):
                self.writes = []
            def adopt(self, key):
                pass
            def api(self, path, method="GET", data=None, key=None, paginate=False):
                if method == "POST":
                    self.writes.append((path, data, key))
                    return {}
                if "/issues?" in path:
                    name = "P" if "/test/a/" in path else "C"
                    return [{"id": 101 if name == "P" else 205, "number": 7 if name == "P" else 9,
                             "body": "<!-- v7-agent-package:" + name + " -->", "html_url": "test"}]
                return []

        fake = Fake()
        relationships(fake, layout, issues)
        self.assertEqual(fake.writes, [
            ("/repos/test/a/issues/7/sub_issues", {"sub_issue_id": 205}, "parent:C"),
            ("/repos/test/b/issues/9/dependencies/blocked_by", {"issue_id": 101}, "dependency:C:P")])


if __name__ == "__main__":
    unittest.main()
