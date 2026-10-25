"""Offline adversarial regression tests; no API or acceptance evidence.

Each invocation uses a mutated snapshot and synthetic CODEOWNERS in an isolated
local fixture. No production file is changed by the test runner.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((HERE / 'capabilities.json').read_text(encoding='utf-8'))
        cls.configuration = (HERE.parents[2] / 'config' / 'repositories.json').read_text(encoding='utf-8')
        cls.verifier = (HERE / 'verify_snapshot.py').read_text(encoding='utf-8')

    def run_snapshot(self, mutate=lambda doc: None, *, optimized=False, owners=b'* @synthetic-owner\n'):
        doc = copy.deepcopy(self.document)
        doc['authority']['codeowners_sha256'] = hashlib.sha256(b'* @synthetic-owner\n').hexdigest()
        # Explicitly synthetic identity evidence; never written to the source snapshot.
        for repository in doc['repositories']:
            for environment in repository['environments']:
                environment['required_reviewers'][0]['reviewers'] = [
                    {'login': 'CompleteDotTech', 'id': 5861166, 'type': 'User'}]
        mutate(doc)
        with tempfile.TemporaryDirectory(prefix='snapshot-test-') as fixture:
            root = Path(fixture)
            script_dir = root / 'docs' / 'github' / 'runtime-capabilities'
            script_dir.mkdir(parents=True)
            (root / 'config').mkdir()
            (root / 'config' / 'repositories.json').write_text(self.configuration, encoding='utf-8')
            (root / '.github').mkdir()
            (root / '.github' / 'CODEOWNERS').write_bytes(owners)
            script = script_dir / 'verify_snapshot.py'
            script.write_text(self.verifier, encoding='utf-8')
            (script_dir / 'capabilities.json').write_text(json.dumps(doc), encoding='utf-8')
            return subprocess.run([sys.executable, '-B', *(['-O'] if optimized else []), str(script)],
                                  capture_output=True, text=True, timeout=15, cwd=root)

    def reject(self, mutation, **kwargs):
        result = self.run_snapshot(mutation, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('PASS:', result.stdout)

    def test_bounded_snapshot_passes_with_caveats(self):
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.run_snapshot(optimized=optimized)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('no live verification or acceptance', result.stdout)
        self.assertEqual(self.document['project']['saved_views']['grouping'], 'unverified')
        self.assertEqual(len(self.document['project']['verified_issue_mappings']), 6)
        self.assertIn('no review receipt', self.document['authority']['copilot'])

    def test_authority_and_owner_tampering(self):
        mutations = {
            'approved kind': lambda d: d.update(kind='approved_configuration'),
            'production approval': lambda d: d['authority'].update(production_authorized=True),
            'owner hash': lambda d: d['authority'].update(codeowners_sha256='0' * 64),
            'human gate approval': lambda d: d['human_gates'][0].update(status='approved'),
            'missing gate': lambda d: d['human_gates'].pop(),
            'duplicate gate': lambda d: d['human_gates'].append(copy.deepcopy(d['human_gates'][0])),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.reject(mutation)
        self.reject(lambda d: None, owners=b'* @different-owner\n')

    def test_optimization_cannot_disable_validation(self):
        self.reject(lambda d: d['authority'].update(production_authorized=True), optimized=True)

    def test_repository_controls(self):
        mutations = {
            'unprotected': lambda r: r.update(main_protected=False),
            'truthy string protection': lambda r: r.update(main_protected='false'),
            'write tokens': lambda r: r['token_policy'].update(default_workflow_permissions='write'),
            'token approval': lambda r: r['token_policy'].update(can_approve_pull_request_reviews=True),
            'unpinned action': lambda r: r['action_allowlist'].update(patterns_allowed=['actions/checkout@main']),
            'all github actions': lambda r: r['action_allowlist'].update(github_owned_allowed=True),
            'all verified actions': lambda r: r['action_allowlist'].update(verified_allowed=True),
            'no rules': lambda r: r.update(rulesets=[]),
            'disabled rules': lambda r: r['rulesets'][0].update(enforcement='disabled'),
            'bypass': lambda r: r['rulesets'][0].update(bypass_actors=[{'actor_id': 1}]),
            'wrong target': lambda r: r['rulesets'][0].update(target='tag'),
            'wrong repository': lambda r: r['rulesets'][0].update(source='synthetic/other'),
            'wrong branch': lambda r: r['rulesets'][0]['conditions']['ref_name'].update(include=['refs/heads/other']),
            'excluded main': lambda r: r['rulesets'][0]['conditions']['ref_name'].update(exclude=['~DEFAULT_BRANCH']),
            'missing environment': lambda r: r['environments'].pop(),
            'no reviewer': lambda r: r['environments'][0].update(required_reviewers=[]),
            'self review': lambda r: r['environments'][0]['required_reviewers'][0].update(prevent_self_review=False),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.reject(lambda d: mutation(d['repositories'][0]))

    def test_required_review_and_check_controls(self):
        for field, value in [('required_approving_review_count', 0),
                             ('require_code_owner_review', False),
                             ('require_last_push_approval', False),
                             ('dismiss_stale_reviews_on_push', False),
                             ('required_review_thread_resolution', False)]:
            with self.subTest(field=field):
                def mutate(d):
                    rules = d['repositories'][0]['rulesets'][0]['rules']
                    next(r for r in rules if r['type'] == 'pull_request')['parameters'][field] = value
                self.reject(mutate)
        def change_check(d):
            rules = d['repositories'][0]['rulesets'][0]['rules']
            next(r for r in rules if r['type'] == 'required_status_checks')['parameters']['required_status_checks'][0]['integration_id'] = 999
        self.reject(change_check)

    def test_ci_and_bootstrap_evidence(self):
        for field, value in [('head_sha', '0' * 40), ('app_id', 999),
                             ('conclusion', 'failure'), ('name', 'unrelated'),
                             ('status', 'in_progress')]:
            with self.subTest(field=field):
                self.reject(lambda d: d['repositories'][0]['ci'][0].update({field: value}))
        self.reject(lambda d: d['repositories'][0]['bootstrap'].update(merge_sha='0' * 40))
        self.reject(lambda d: d['repositories'][0]['bootstrap'].update(review_rule_restored=False))

    def test_project_identity_and_mapping_evidence(self):
        self.reject(lambda d: d['project'].update(visibility='PUBLIC'))
        self.reject(lambda d: d['project']['automation_readback'].update(public=True))
        self.reject(lambda d: d['project']['verified_issue_mappings'].pop())
        for field in ('key', 'node_id', 'number'):
            with self.subTest(field=field):
                self.reject(lambda d: d['project']['verified_issue_mappings'][1].update(
                    {field: d['project']['verified_issue_mappings'][0][field]}))

    def test_repository_identity_and_mapping_types(self):
        def rename_repository(d):
            repository = d['repositories'][0]
            repository['repository'] = 'unapproved/repository'
            for ruleset in repository['rulesets']:
                ruleset['source'] = repository['repository']
        for optimized in (False, True):
            self.reject(rename_repository, optimized=optimized)
            for value in (True, False, 0, -1, '1', 1.5, None, [], {}):
                with self.subTest(number=value, optimized=optimized):
                    self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(number=value), optimized=optimized)
            self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(repository='unapproved/repository'), optimized=optimized)

    def test_mapping_keys_follow_approved_configuration(self):
        configuration = json.loads(self.configuration)
        for optimized in (False, True):
            for key in (None, True, 0, [], {}, '', 'UNKNOWN-ISSUE-KEY'):
                with self.subTest(key=key, optimized=optimized):
                    self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(key=key),
                                optimized=optimized)
            self.reject(lambda d: d['project']['verified_issue_mappings'][0].pop('key'),
                        optimized=optimized)
            mapping = self.document['project']['verified_issue_mappings'][0]
            expected = configuration['owner'] + '/' + configuration['issue_repositories'][mapping['key']]
            wrong = next(configuration['owner'] + '/' + r['name']
                         for r in configuration['repositories']
                         if configuration['owner'] + '/' + r['name'] != expected)
            self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(repository=wrong),
                        optimized=optimized)
            # A known key routed to another repository must also be rejected.
            other_key = next(key for key, repo in configuration['issue_repositories'].items()
                             if configuration['owner'] + '/' + repo != mapping['repository'])
            self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(key=other_key),
                        optimized=optimized)

    def test_mapping_node_ids_are_nonblank_strings(self):
        for optimized in (False, True):
            self.reject(lambda d: d['project']['verified_issue_mappings'][0].pop('node_id'),
                        optimized=optimized)
            for value in (None, True, False, 0, 1, 1.5, [], {}, '', ' ', '\t\n'):
                with self.subTest(node_id=value, optimized=optimized):
                    self.reject(lambda d: d['project']['verified_issue_mappings'][0].update(node_id=value),
                                optimized=optimized)

    def test_boolean_types_are_exact(self):
        paths = [
            ('bootstrap', 'review_rule_restored'),
            ('environments', 0, 'can_admins_bypass'),
            ('environments', 0, 'deployment_branch_policy', 'protected_branches'),
            ('environments', 0, 'required_reviewers', 0, 'prevent_self_review'),
        ]
        for optimized in (False, True):
            for value in ('true', 'false', 1, 0, None, [], {}):
                for path in paths:
                    def mutate(d):
                        target = d['repositories'][0]
                        for key in path[:-1]:
                            target = target[key]
                        target[path[-1]] = value
                    with self.subTest(path=path, value=value, optimized=optimized):
                        self.reject(mutate, optimized=optimized)
                for field in ('require_code_owner_review', 'require_last_push_approval',
                              'dismiss_stale_reviews_on_push', 'required_review_thread_resolution',
                              'strict_required_status_checks_policy'):
                    def mutate(d):
                        kind = 'required_status_checks' if field == 'strict_required_status_checks_policy' else 'pull_request'
                        rules = d['repositories'][0]['rulesets'][0]['rules']
                        next(r for r in rules if r['type'] == kind)['parameters'][field] = value
                    with self.subTest(field=field, value=value, optimized=optimized):
                        self.reject(mutate, optimized=optimized)
            self.reject(lambda d: d['repositories'][0]['token_policy'].update(can_approve_pull_request_reviews=0), optimized=optimized)

    def test_sole_numeric_reviewer_identity(self):
        for optimized in (False, True):
            for reviewers in (['CompleteDotTech'], [],
                              [{'login': 'CompleteDotTech', 'id': '5861166', 'type': 'User'}],
                              [{'login': 'CompleteDotTech', 'id': True, 'type': 'User'}],
                              [{'login': 'CompleteDotTech', 'id': 999, 'type': 'User'}],
                              [{'login': 'Other', 'id': 5861166, 'type': 'User'}],
                              [{'login': 'CompleteDotTech', 'id': 5861166, 'type': 'Team'}],
                              [{'login': 'CompleteDotTech', 'type': 'User'}],
                              [{'login': 'CompleteDotTech', 'id': 5861166, 'type': 'User'},
                               {'login': 'Other', 'id': 999, 'type': 'User'}]):
                with self.subTest(reviewers=reviewers, optimized=optimized):
                    self.reject(lambda d: d['repositories'][0]['environments'][0]['required_reviewers'][0].update(reviewers=reviewers), optimized=optimized)
            self.reject(lambda d: d['repositories'][0]['environments'][0]['required_reviewers'].append(
                copy.deepcopy(d['repositories'][0]['environments'][0]['required_reviewers'][0])), optimized=optimized)


    def test_main_sha_requires_exact_lowercase_commit(self):
        for optimized in (False, True):
            for value in (None, True, 0, [], {}, '', ' ', '\t\n', 'a' * 39, 'a' * 41,
                          'A' * 40, 'g' * 40, 'a' * 40 + '\n', ' ' + 'a' * 40):
                def mutate(d):
                    repo = d['repositories'][0]
                    repo['main_sha'] = value
                    repo['bootstrap']['merge_sha'] = value
                    for check in repo['ci']:
                        check['head_sha'] = value
                with self.subTest(main_sha=value, optimized=optimized):
                    self.reject(mutate, optimized=optimized)

    def test_duplicate_environment_records_rejected(self):
        for optimized in (False, True):
            for environment_name in ('staging', 'production'):
                def mutate(d):
                    repo = d['repositories'][0]
                    duplicate = next(e for e in repo['environments'] if e['name'] == environment_name)
                    repo['environments'].append(copy.deepcopy(duplicate))
                with self.subTest(environment=environment_name, optimized=optimized):
                    self.reject(mutate, optimized=optimized)

if __name__ == '__main__':
    unittest.main()
