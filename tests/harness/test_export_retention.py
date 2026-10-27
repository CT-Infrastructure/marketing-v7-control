import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from export_retention import Exports, POLICY

class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.time = '2026-10-01T00:00:00.000000Z'
        self.store = Exports(self.root, 'a'*32, lambda: self.time)

    def test_size_exact_and_over(self):
        first = self.store.export('size-boundary')
        (self.root/first['path']).unlink()
        exact = self.store.export('size-boundary', 1048576-first['bytes'])
        self.assertEqual(exact['bytes'],1048576)
        before = set(self.root.iterdir())
        with self.assertRaises(ValueError): self.store.export('size-boundary',1048577-first['bytes'])
        self.assertEqual(set(self.root.iterdir()),before)

    def test_boundary_and_idempotence(self):
        old = self.store.export('retention-boundary')['path']
        self.time = '2026-10-07T23:59:59.999999Z'
        self.assertEqual(self.store.sweep(),[])
        fresh = self.store.export('synthetic-pass')['path']
        sibling = self.root/'sibling'; sibling.write_text('preserve')
        other = Exports(self.root,'b'*32,lambda:self.time).export('synthetic-pass')['path']
        self.time = '2026-10-08T00:00:00.000000Z'
        self.assertEqual(self.store.sweep(),[old])
        self.time = '2026-10-08T00:00:00.000001Z'
        self.assertEqual(self.store.sweep(),[])
        self.assertTrue((self.root/fresh).exists())
        self.assertTrue((self.root/other).exists())
        self.assertEqual(sibling.read_text(),'preserve')

    def test_invalid_policy(self):
        policy=json.loads(POLICY.read_text(encoding='utf-8-sig'))
        for key in ('exported_test_artifact_max_age_days','exported_test_artifact_max_bytes'):
            for value in (True,0,-1,8,'7',None):
                with self.subTest(key=key,value=value):
                    with self.assertRaises(ValueError): Exports(self.root,'a'*32,lambda:self.time,dict(policy,**{key:value}))

    def test_invalid_and_future_timestamps_preserve(self):
        receipt=self.store.export('synthetic-pass'); path=self.root/receipt['path']
        doc=json.loads(path.read_text())
        for value in ('2026-10-02T00:00:00.000000Z','2026-10-01T00:00:00','2026-10-01T00:00:00+00:00','invalid'):
            doc['created_at']=value; path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError): self.store.sweep()
            self.assertTrue(path.exists())

    def test_failures_never_return_success(self):
        for target in ('os.fsync','os.rename'):
            with self.subTest(target=target),patch('export_retention.'+target,side_effect=OSError('synthetic interruption')):
                with self.assertRaises(OSError): self.store.export('synthetic-pass')
            self.assertEqual(list(self.root.iterdir()),[])
        receipt=self.store.export('synthetic-pass'); self.time='2026-10-08T00:00:00.000000Z'
        with patch.object(Path,'unlink',side_effect=PermissionError('synthetic delete denial')):
            with self.assertRaises(PermissionError): self.store.sweep()
        self.assertTrue((self.root/receipt['path']).exists())
        self.assertEqual(self.store.sweep(),[receipt['path']])

    def test_reject_paths_and_special_files(self):
        for root in (Path('relative'),self.root/'..',self.root/'missing'):
            with self.assertRaises(ValueError): Exports(root,'a'*32,lambda:self.time)
        for owner in ('../escape','a/b',''):
            with self.assertRaises(ValueError): Exports(self.root,owner,lambda:self.time)
        special=self.root/('synthetic-'+'a'*32+'-'+'b'*32+'.json')
        special.mkdir()
        with self.assertRaises(ValueError): self.store.sweep()
        special.rmdir()
        with patch('export_retention.stat.S_ISREG',return_value=False):
            special.write_text('{}')
            with self.assertRaises(ValueError): self.store.sweep()
        special.unlink()

    def test_symlink_rejected(self):
        target=self.root/'sibling'; target.write_text('preserve')
        link=self.root/('synthetic-'+'a'*32+'-'+'b'*32+'.json')
        try: link.symlink_to(target)
        except OSError as exc: self.skipTest('symlink capability unavailable: '+str(exc))
        with self.assertRaises(ValueError): self.store.sweep()
        self.assertEqual(target.read_text(),'preserve')

    def test_interrupted_write_and_cleanup_failure(self):
        real_open = Path.open
        class BrokenWriter:
            def __init__(self, path): self.stream=real_open(path,'xb')
            def __enter__(self): return self
            def __exit__(self,*args): self.stream.close()
            def write(self,data):
                self.stream.write(data[:12])
                raise InterruptedError('synthetic partial write')
        def opening(path,*args,**kwargs):
            return BrokenWriter(path) if args == ('xb',) else real_open(path,*args,**kwargs)
        with patch.object(Path,'open',opening):
            with self.assertRaises(InterruptedError): self.store.export('synthetic-pass')
        self.assertEqual(list(self.root.iterdir()),[])
        with patch('export_retention.os.fsync',side_effect=OSError('synthetic failure')), patch.object(Path,'unlink',side_effect=PermissionError('synthetic cleanup denial')):
            with self.assertRaises(PermissionError): self.store.export('synthetic-pass')
        self.assertEqual(len(list(self.root.glob('*.partial'))),1)
        self.assertEqual(list(self.root.glob('*.json')),[])

    def test_collision_preserves_existing_sibling(self):
        class Fixed: hex='b'*32
        path=self.root/('synthetic-'+'a'*32+'-'+'b'*32+'.json')
        path.write_text('preserve')
        with patch('export_retention.uuid.uuid4',return_value=Fixed()):
            with self.assertRaises(FileExistsError): self.store.export('synthetic-pass')
        self.assertEqual(path.read_text(),'preserve')
        self.assertEqual(list(self.root.glob('*.partial')),[])

    def test_malformed_partial_fails_closed(self):
        path=self.root/('synthetic-'+'a'*32+'-'+'b'*32+'.partial')
        path.write_text('{')
        self.time='2026-10-09T00:00:00.000000Z'
        with self.assertRaises(ValueError): self.store.sweep()
        self.assertTrue(path.exists())

    def test_validation_precedes_any_deletion(self):
        old=self.store.export('synthetic-pass')['path']
        invalid=self.store.export('synthetic-pass')['path']
        (self.root/invalid).write_text('{"created_at":"bad","created_at":"duplicate"}')
        self.time='2026-10-08T00:00:00.000000Z'
        with self.assertRaises(ValueError): self.store.sweep()
        self.assertTrue((self.root/old).exists())

    def test_link_checks_without_symlink_privilege(self):
        receipt=self.store.export('synthetic-pass')
        with patch.object(Path,'is_symlink',return_value=True):
            with self.assertRaises(ValueError): self.store.sweep()
        self.assertTrue((self.root/receipt['path']).exists())
        with patch.object(Path,'is_symlink',return_value=True):
            with self.assertRaises(ValueError): Exports(self.root,'a'*32,lambda:self.time)

    def test_valid_interrupted_partial_expires_only_at_boundary(self):
        receipt=self.store.export('synthetic-pass')
        path=self.root/receipt['path']
        partial=path.with_suffix('.partial'); path.rename(partial)
        self.assertEqual(self.store.sweep(),[])
        self.time='2026-10-08T00:00:00.000000Z'
        self.assertEqual(self.store.sweep(),[partial.name])
        self.assertEqual(self.store.sweep(),[])

    def test_no_arbitrary_content(self):
        for case in ('secret','../escape',{},None):
            with self.assertRaises(ValueError): self.store.export(case)
        for count in (-1,True,'1',1048577):
            with self.assertRaises(ValueError): self.store.export('synthetic-pass',count)
        self.assertEqual(list(self.root.iterdir()),[])

if __name__ == '__main__': unittest.main(verbosity=2)
