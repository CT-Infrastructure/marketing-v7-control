"""Synthetic provenance fixtures; execute only in root's admitted isolation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_process_restart import SOURCE_PATHS, source_binding


class SourceRevisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / 'export'
        self.root.mkdir()
        for name in SOURCE_PATHS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic ' + name + '\n').encode())
        self.expected = 'a' * 40
        self.manifest = self.base / 'provenance.json'
        self.document = dict(source_revision=self.expected, source_hashes={
            name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
            for name in SOURCE_PATHS})
        self.write_manifest(self.document)

    def write_manifest(self, document):
        self.manifest.write_text(json.dumps(document), encoding='utf-8')

    def binding(self, **kwargs):
        inputs = dict(expected=self.expected, manifest=str(self.manifest))
        inputs.update(kwargs)
        return source_binding(self.root, **inputs)

    def git(self, *args, root=None):
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME='Synthetic Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                   GIT_COMMITTER_NAME='Synthetic Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        return subprocess.run(['git', '-C', str(root or self.root), *args], env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True, timeout=15).stdout.decode().strip()

    def checkout(self):
        if shutil.which('git') is None:
            self.skipTest('Git fixture executable unavailable')
        self.git('init', '--quiet')
        self.git('config', 'core.autocrlf', 'false')
        self.git('add', '--', *SOURCE_PATHS)
        self.git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'synthetic initial')
        return self.git('rev-parse', 'HEAD')

    def test_export_reports_declaration_and_exact_covered_bytes(self):
        bound = self.binding()
        self.assertEqual(bound['source_revision'], self.expected)
        self.assertEqual(bound['source_hashes'], self.document['source_hashes'])
        self.assertEqual(bound['source_provenance'], 'executor-declared-export-with-verified-bytes')
        self.assertFalse((self.root / '.git').exists())

    def test_export_requires_both_executor_inputs(self):
        for inputs in ({'expected': None}, {'manifest': None}, {'expected': None, 'manifest': None}):
            with self.subTest(inputs=inputs), self.assertRaises(ValueError):
                self.binding(**inputs)

    def test_strict_revision_types_and_formats(self):
        for bad in (True, False, 123, '', '0' * 40, 'a' * 39, 'a' * 41,
                    'A' * 40, 'g' * 40, 'a' * 40 + '\n', ['a' * 40]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.binding(expected=bad)
            malformed = copy.deepcopy(self.document)
            malformed['source_revision'] = bad
            self.write_manifest(malformed)
            with self.subTest(manifest_revision=bad), self.assertRaises(ValueError):
                self.binding()
        self.write_manifest(self.document)

    def test_conflicting_or_stale_manifest_revision(self):
        with self.assertRaises(ValueError):
            self.binding(expected='b' * 40)

    def test_manifest_schema_hash_and_path_coverage_fail_closed(self):
        variants = [None, [], True, {'source_revision': self.expected},
                    dict(self.document, extra=True)]
        for coverage in (None, [], True, {}, dict(self.document['source_hashes'], extra='a' * 64)):
            variants.append(dict(self.document, source_hashes=coverage))
        for bad_hash in (True, 'g' * 64, 'a' * 63, 'a' * 64 + '\n'):
            item = copy.deepcopy(self.document)
            item['source_hashes'][SOURCE_PATHS[0]] = bad_hash
            variants.append(item)
        for bad_path in ('../outside.py', '/outside.py', 'tests/../outside.py',
                         'tests\\outside.py', 'C:/outside.py'):
            item = copy.deepcopy(self.document)
            item['source_hashes'][bad_path] = item['source_hashes'].pop(SOURCE_PATHS[0])
            variants.append(item)
        for item in variants:
            self.write_manifest(item)
            with self.subTest(document=item), self.assertRaises(ValueError):
                self.binding()

    def test_malformed_duplicate_missing_and_relative_manifest(self):
        for raw in ('{', '{"source_revision":"a", "source_revision":"b"}'):
            self.manifest.write_text(raw, encoding='utf-8')
            with self.assertRaises(ValueError):
                self.binding()
        for bad in ('', True, 'relative.json'):
            with self.subTest(path=bad), self.assertRaises(ValueError):
                self.binding(manifest=bad)
        self.manifest.unlink()
        with self.assertRaises(FileNotFoundError):
            self.binding()

    def test_every_covered_changed_or_missing_file_is_rejected(self):
        for name in SOURCE_PATHS:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with self.subTest(changed=name), self.assertRaises(ValueError):
                self.binding()
            path.unlink()
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.binding()
            path.write_bytes(original)

    def test_stale_validly_shaped_digest_is_rejected(self):
        stale = copy.deepcopy(self.document)
        stale['source_hashes'][SOURCE_PATHS[0]] = '0' * 64
        self.write_manifest(stale)
        with self.assertRaises(ValueError):
            self.binding()

    def test_change_during_binding_fails_closed(self):
        from test_process_restart import source_hashes
        stable = source_hashes(self.root)
        changed = dict(stable, **{SOURCE_PATHS[0]: '0' * 64})
        with patch('test_process_restart.source_hashes', side_effect=[stable, changed]):
            with self.assertRaises(ValueError):
                self.binding()

    def test_relative_source_root_is_rejected(self):
        with self.assertRaises(ValueError):
            source_binding(Path('relative-export'), expected=self.expected, manifest=str(self.manifest))

    def test_linked_covered_file_is_rejected(self):
        path = self.root / SOURCE_PATHS[0]
        outside = self.base / 'outside.py'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as error:
            self.skipTest('Symlink fixture unavailable: ' + str(error))
        with self.assertRaises(ValueError):
            self.binding()

    def test_linked_parent_directory_is_rejected(self):
        parent = self.root / 'tools'
        outside = self.base / 'outside-tools'
        parent.rename(outside)
        try:
            parent.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest('Directory link fixture unavailable: ' + str(error))
        with self.assertRaises(ValueError):
            self.binding()

    def test_checkout_head_advances_without_source_constant_or_cwd_dependency(self):
        first = self.checkout()
        foreign = self.base / 'other'
        foreign.mkdir()
        self.git('init', '--quiet', root=foreign)
        with patch.dict(os.environ, {'GIT_DIR': str(foreign / '.git'),
                                    'GIT_WORK_TREE': str(foreign)}):
            previous = Path.cwd()
            try:
                os.chdir(foreign)
                bound = source_binding(self.root)
            finally:
                os.chdir(previous)
        self.assertEqual(bound['source_revision'], first)
        self.assertEqual(bound['source_provenance'], 'checkout-git-head-and-blobs')
        self.git('-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '--quiet', '-m', 'advance')
        second = self.git('rev-parse', 'HEAD')
        self.assertNotEqual(first, second)
        self.assertEqual(source_binding(self.root)['source_revision'], second)
        with self.assertRaises(ValueError):
            source_binding(self.root, expected=first)
        self.assertEqual(source_binding(self.root, expected=second)['source_revision'], second)

    def test_checkout_rejects_dirty_bytes_even_with_updated_declared_hash(self):
        head = self.checkout()
        path = self.root / SOURCE_PATHS[0]
        path.write_bytes(path.read_bytes() + b'dirty')
        document = copy.deepcopy(self.document)
        document['source_revision'] = head
        document['source_hashes'][SOURCE_PATHS[0]] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_manifest(document)
        with self.assertRaises(ValueError):
            source_binding(self.root, expected=head, manifest=str(self.manifest))

    def test_uncommitted_new_regression_file_cannot_inherit_checkout_revision(self):
        self.checkout()
        name = 'tests/controller/test_process_revision.py'
        self.git('rm', '--cached', '--', name)
        self.git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'omit unpublished regression')
        self.assertTrue((self.root / name).is_file())
        with self.assertRaises(subprocess.CalledProcessError):
            source_binding(self.root)

    def test_checkout_manifest_must_agree_with_actual_head(self):
        head = self.checkout()
        with self.assertRaises(ValueError):
            self.binding()
        document = copy.deepcopy(self.document)
        document['source_revision'] = head
        self.write_manifest(document)
        self.assertEqual(self.binding(expected=head)['source_revision'], head)

    def test_linked_worktree_uses_its_own_head(self):
        head = self.checkout()
        worktree = self.base / 'linked'
        self.git('worktree', 'add', '--quiet', '--detach', str(worktree), head)
        self.assertTrue((worktree / '.git').is_file())
        self.assertEqual(source_binding(worktree)['source_revision'], head)

    def test_export_inside_unrelated_checkout_does_not_inherit_ancestor_head(self):
        self.checkout()
        nested = self.root / 'nested-export'
        shutil.copytree(self.root, nested, ignore=shutil.ignore_patterns('.git', 'nested-export'))
        with self.assertRaises(ValueError):
            source_binding(nested)


if __name__ == '__main__':
    unittest.main()
