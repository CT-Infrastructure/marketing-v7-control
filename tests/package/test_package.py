import io,json,tarfile,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from workspace import extract_archive,inventory
from seed_github import preserve_human_notes,validate_destination
from run_agents import validate_live_policy,command
from validate_package import validate

class PackageTests(unittest.TestCase):
    def test_full_coverage(self):
        r=validate(ROOT);self.assertEqual(r['workflow_count'],190);self.assertEqual(r['component_count'],147);self.assertEqual(r['source_acceptance_ids'],576)
    def test_human_notes_retained(self):
        a='<!-- BEGIN V7 GENERATED -->old<!-- END V7 GENERATED -->\nHuman: keep this'
        b='<!-- BEGIN V7 GENERATED -->new<!-- END V7 GENERATED -->\nOther'
        self.assertIn('Human: keep this',preserve_human_notes(a,b));self.assertIn('new',preserve_human_notes(a,b))
    def test_missing_update_markers_rejected(self):
        with self.assertRaises(ValueError):preserve_human_notes('unmanaged','also unmanaged')
    def test_public_destination_rejected(self):
        with self.assertRaises(ValueError):validate_destination({'visibility':'public'},False)
    def test_apply_requires_review(self):
        with self.assertRaises(ValueError):validate_destination({'visibility':'private','owner':'example','repository':'test'},True)
    def test_real_launcher_disabled_by_default(self):
        p=json.loads((ROOT/'config/orchestration.example.json').read_text())
        with self.assertRaises(ValueError):validate_live_policy(p)
    def archive(self,name,kind=None):
        f=io.BytesIO()
        with tarfile.open(fileobj=f,mode='w') as tar:
            m=tarfile.TarInfo(name)
            if kind:m.type=kind;m.linkname='/etc/passwd';tar.addfile(m)
            else:m.size=3;tar.addfile(m,io.BytesIO(b'abc'))
        return f.getvalue()
    def test_archive_path_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_archive(self.archive('../escape'),Path(tmp))
    def test_archive_symlink_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_archive(self.archive('link',tarfile.SYMTYPE),Path(tmp))
    def test_archive_safe_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            extract_archive(self.archive('src/a.py'),Path(tmp));self.assertEqual((Path(tmp)/'src/a.py').read_bytes(),b'abc')
    def test_inventory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'bad').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):inventory(Path(tmp))
    def test_archive_size_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):extract_archive(self.archive('large'),Path(tmp),2)
if __name__=='__main__':unittest.main()
