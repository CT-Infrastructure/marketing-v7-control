"""Synthetic host facts + real disposable exports; no live authority or effects.

Defined for ROOT's separately admitted isolated Linux executor. Author does not
run this suite. A positive is consistency only and still HOLD/NONE.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from orchestration.integrator import policy_guard as g

POLICY = json.loads(Path(g.__file__).with_name('reviewed-policy.v1.json').read_text())
OWNED = 'orchestration/integrator/README.md'


def page(binding, records, number=1, next_page=None):
    raw = json.dumps(records, sort_keys=True)
    return dict(page=number, next_page=next_page, raw_utf8=raw,
                raw_sha256=hashlib.sha256(raw.encode()).hexdigest(), binding=copy.deepcopy(binding),
                records=[dict(id=str(x['id']), sha256=g.digest(x)) for x in records])


class _BoundedScan:
    """Finite lazy stand-in for an enormous hostile directory, no allocation."""
    def __init__(self, sentinel_count):
        self.sentinel_count=sentinel_count;self.consumed=0;self.closed=False
    def __enter__(self):return self
    def __exit__(self,*args):self.closed=True
    def __iter__(self):return self
    def __next__(self):
        if self.consumed>=self.sentinel_count:
            raise AssertionError('Enumeration continued after refusal sentinel')
        self.consumed+=1
        entry=type('SyntheticEntry',(),{})();entry.name='synthetic-'+str(self.consumed)
        return entry


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name)/'base'
        self.candidate = Path(self.scratch.name)/'candidate'
        for root, content in ((self.base, b'old policy\n'), (self.candidate, b'new policy\n')):
            target = root/OWNED
            target.parent.mkdir(parents=True)
            target.write_bytes(content)
        self.binding = dict(repository='synthetic/repository', task='F13', fence=1,
                            input_sha256='a'*64, base='b'*40, head='c'*40, tree='d'*40)
        tests = [dict(command='synthetic independent test command', exit_code=0,
                      output_sha256='1'*64, binding=copy.deepcopy(self.binding))]
        self.result = dict(task_key='F13', fence=1, input_sha256='a'*64,
                           base_revision='b'*40, status='ready_for_review', summary='Synthetic unit fixture',
                           changed_paths=[OWNED], artifacts=[dict(path=OWNED, sha256=g.raw_digest(b'new policy\n'))],
                           tests=copy.deepcopy(tests), blockers=[])
        self.facts = dict(binding=copy.deepcopy(self.binding), policy_sha256=g.digest(POLICY),
                          result_sha256='', manifest_sha256=g.digest(g.observe(self.candidate, POLICY['limits'])),
                          test_sha256='', review_sha256='', checks_sha256='', source_sha256='',
                          author='synthetic-author', reviewer='synthetic-independent-reviewer', tests=tests,
                          review=dict(binding=copy.deepcopy(self.binding),author='synthetic-author',
                                      reviewer='synthetic-independent-reviewer', model='gpt-6.1-sol',effort='max',
                                      complete=True,open_findings=[],reviewed_at=10,expires_at=20),
                          checks=[dict(id=1,name='required-test',app_id=123,head='c'*40,status='completed',conclusion='success')],
                          required_checks={'required-test':123}, sources={}, findings=[], now=15)
        for kind in POLICY['required_sources']:
            self.facts['sources'][kind]=[page(self.binding, [])]
        self.raw_review = dict(copy.deepcopy(self.facts['review']), id='synthetic-review')
        self.facts['review'].update(source_id='synthetic-review', source_sha256=g.digest(self.raw_review))
        self.facts['sources']['reviews']=[page(self.binding,[self.raw_review])]
        self.facts['sources']['checks']=[page(self.binding,copy.deepcopy(self.facts['checks']))]
        self.seal()
        # Every adverse method starts with a full positive through the real guard.
        self.assert_consistent()

    def seal(self):
        self.raw=json.dumps(self.result,sort_keys=True).encode()
        self.facts['result_sha256']=g.raw_digest(self.raw)
        for field, digest in (('tests','test_sha256'),('review','review_sha256'),
                              ('checks','checks_sha256'),('sources','source_sha256')):
            self.facts[digest]=g.digest(self.facts[field])

    def assess(self):
        return g.assess(self.base,self.candidate,self.raw,expected_binding=self.binding,
                        host_facts=self.facts,policy=POLICY)

    def assert_consistent(self):
        answer=self.assess()
        self.assertTrue(answer['consistent'],answer)
        self.assertEqual(answer['decision'],'HOLD')
        self.assertEqual(answer['effect_authority'],'NONE')
        return answer

    def assert_held(self,reason=None,escalate=False):
        before={str(p.relative_to(self.candidate)):p.read_bytes() for p in self.candidate.rglob('*') if p.is_file() and not p.is_symlink()}
        answer=self.assess()
        self.assertFalse(answer['consistent'],answer)
        self.assertEqual(answer['decision'],'HOLD');self.assertEqual(answer['effect_authority'],'NONE')
        if reason:self.assertIn(reason,answer['reasons'])
        if escalate:self.assertTrue(answer['human_escalation'])
        after={str(p.relative_to(self.candidate)):p.read_bytes() for p in self.candidate.rglob('*') if p.is_file() and not p.is_symlink()}
        self.assertEqual(before,after)

    def test_real_file_positive_remains_nonauthoritative(self):
        result=self.assert_consistent()
        self.assertEqual(result['observed_manifest_sha256'],g.digest(g.observe(self.candidate,POLICY['limits'])))
        self.assertNotEqual(g.observe(self.base,POLICY['limits']),g.observe(self.candidate,POLICY['limits']))

    def test_content_edit_invalidates_observed_manifest(self):
        (self.candidate/OWNED).write_bytes(b'late unreviewed content')
        self.assert_held('OBSERVED_MANIFEST_CHANGED')

    def test_fabricated_artifact_hash_rejected_after_result_reseal(self):
        self.result['artifacts'][0]['sha256']='f'*64;self.seal()
        self.assert_held('ACTUAL_CONTENT_HASH_MISMATCH')

    def test_undeclared_actual_file_and_protected_file_escalate(self):
        target=self.candidate/'.github/workflows/unowned.yml';target.parent.mkdir(parents=True);target.write_text('synthetic')
        self.assert_held('UNOWNED_ESCALATION',escalate=True)

    def test_deleted_owned_file_escalates(self):
        (self.candidate/OWNED).unlink()
        self.assert_held('DELETE_OR_RENAME_ESCALATION',escalate=True)

    def test_renamed_owned_file_never_widens_scope(self):
        (self.candidate/OWNED).rename(self.candidate/'orchestration/integrator/renamed.md')
        self.assert_held(escalate=True)

    def test_traversal_and_windows_aliases_refuse(self):
        for name in ('../escape','/absolute','C:drive','a\\b','a//b','a/./b','a/../b','.git/config'):
            with self.subTest(name=name),self.assertRaises(g.Held):g.path_name(name)

    def test_symlink_and_hardlink_actual_files_refuse(self):
        target=self.candidate/'orchestration/integrator/link.md';target.symlink_to(self.candidate/OWNED)
        self.assert_held('LINK_ESCALATION',escalate=True);target.unlink()
        os.link(self.candidate/OWNED,target)
        self.assert_held('SPECIAL_OR_HARDLINK_ESCALATION',escalate=True)

    def test_fifo_special_file_refuses_without_blocking(self):
        fifo=self.candidate/'orchestration/integrator/fifo';os.mkfifo(fifo)
        answer=self.assess();self.assertFalse(answer['consistent']);self.assertEqual(answer['reasons'],['SPECIAL_OR_HARDLINK_ESCALATION']);self.assertTrue(answer['human_escalation'])

    def test_linked_export_ancestor_refuses(self):
        alias=Path(self.scratch.name)/'alias';alias.symlink_to(self.candidate,target_is_directory=True)
        answer=g.assess(self.base,alias,self.raw,expected_binding=self.binding,host_facts=self.facts,policy=POLICY)
        self.assertFalse(answer['consistent']);self.assertEqual(answer['effect_authority'],'NONE')

    def test_content_and_entry_bounds(self):
        limits=copy.deepcopy(POLICY['limits']);limits['file_bytes']=1
        with self.assertRaisesRegex(g.Held,'FILE_BOUND'):g.observe(self.candidate,limits)
        limits=copy.deepcopy(POLICY['limits']);limits['files']=1
        with self.assertRaisesRegex(g.Held,'ENTRY_BOUND'):g.observe(self.candidate,limits)
        limits=copy.deepcopy(POLICY['limits']);limits['total_bytes']=1
        with self.assertRaisesRegex(g.Held,'TOTAL_BOUND'):g.observe(self.candidate,limits)

    def test_actual_export_race_is_rejected(self):
        original_read=g.os.read;original_write=Path.write_bytes
        changed=[0];writes=[];target=self.candidate/OWNED
        injected=b'changed during observation'
        def write(path,data):
            writes.append((path,data));return original_write(path,data)
        def read(fd,count):
            data=original_read(fd,count)
            if data and changed[0]==0:
                changed[0]+=1;target.write_bytes(injected)
            return data
        # This fixture deliberately changes input; the generic no-input-change
        # helper is inappropriate. Assert the policy hold and only that one
        # external write, without permitting guard restoration/additional writes.
        with patch.object(g.os,'read',side_effect=read),patch.object(Path,'write_bytes',new=write):
            answer=self.assess()
        self.assertFalse(answer['consistent'],answer)
        self.assertEqual(answer['decision'],'HOLD')
        self.assertEqual(answer['effect_authority'],'NONE')
        self.assertEqual(answer['reasons'],['OBSERVED_MANIFEST_CHANGED'])
        self.assertEqual(changed,[1])
        self.assertEqual(writes,[(target,injected)])
        self.assertEqual(target.read_bytes(),injected)

    def test_head_base_tree_fence_and_input_changes_invalidate(self):
        for key,value in (('head','e'*40),('base','e'*40),('tree','e'*40),('fence',2),('input_sha256','f'*64)):
            with self.subTest(key=key):
                original=self.binding[key];self.binding[key]=value
                self.assert_held('CURRENT_BINDING_CHANGED');self.binding[key]=original

    def test_stale_review_binding_and_digest_refuse(self):
        self.facts['review']['binding']['head']='e'*40;self.seal()
        self.assert_held('UNVERIFIED_REVIEW_SOURCE')
        self.facts['review']['binding']=copy.deepcopy(self.binding);self.seal();self.facts['review_sha256']='e'*64
        self.assert_held('EVIDENCE_DIGEST_CHANGED')

    def test_author_self_review_and_fabricated_tests_refuse(self):
        self.facts['reviewer']=self.facts['author'];self.assert_held('SELF_REVIEW')
        self.facts['reviewer']='synthetic-independent-reviewer';self.result['tests'][0]['output_sha256']='f'*64;self.seal()
        self.assert_held('INDEPENDENT_TEST_RESULT_MISMATCH')

    def test_failed_pending_wrong_app_head_and_duplicate_checks_refuse(self):
        original=copy.deepcopy(self.facts['checks'])
        for key,value in (('status','queued'),('conclusion','failure'),('app_id',999),('head','e'*40)):
            with self.subTest(key=key):
                self.facts['checks']=copy.deepcopy(original);self.facts['checks'][0][key]=value;self.seal();self.assert_held('UNVERIFIED_OR_AMBIGUOUS_CHECK')
        self.facts['checks']=original*2;self.seal();self.assert_held('CHECK_SET')

    def test_expired_future_nonfinite_review_refuses(self):
        for now in (9,20,float('inf')):
            with self.subTest(now=now):self.facts['now']=now;self.assert_held('STALE_REVIEW')

    def test_incomplete_source_pagination_and_unknown_sources_refuse(self):
        self.facts['sources']['checks'][0]['next_page']=2;self.seal();self.assert_held('INCOMPLETE_PAGINATION')
        self.facts['sources']['checks'][0]['next_page']=None;self.facts['sources']['unknown']=[];self.seal();self.assert_held('SOURCE_SET')

    def test_unverified_raw_source_and_duplicate_ids_refuse(self):
        self.facts['sources']['reviews'][0]['raw_utf8']='[1]';self.seal();self.assert_held('UNVERIFIED_RAW_SOURCE')
        self.facts['sources']['reviews']=[page(self.binding,[{'id':'1'},{'id':'1'}])];self.seal();self.assert_held('DUPLICATE_OR_UNKNOWN_SOURCE')

    def test_complete_multiple_pages_positive(self):
        self.facts['sources']['reviews']=[page(self.binding,[self.raw_review,{'id':'1','body':'untrusted data'}],1,2),page(self.binding,[{'id':'2'}],2)]
        self.seal();self.assert_consistent()

    def test_complete_findings_require_current_regression_and_rereview(self):
        raw={'id':'synthetic-P2','severity':'P2','text':'historical finding'}
        self.facts['sources']['findings']=[page(self.binding,[raw])];self.seal()
        self.assert_held('OMITTED_FINDING_DISPOSITION')
        finding=dict(id='synthetic-P2',source_sha256=g.digest(raw),severity='P2',status='resolved',current_binding=copy.deepcopy(self.binding),regression_sha256=self.facts['test_sha256'],rereview_sha256=self.facts['review_sha256'])
        self.facts['findings']=[finding];self.assert_consistent()
        for key,value in (('status','open'),('regression_sha256','f'*64),('source_sha256','f'*64)):
            with self.subTest(key=key):
                saved=finding[key];finding[key]=value;self.assert_held('UNRESOLVED_OR_STALE_FINDING');finding[key]=saved

    def test_result_unknown_keys_duplicate_json_and_oversize_refuse(self):
        self.result['approve']=True;self.seal();self.assert_held('SANITIZED_RESULT_SCHEMA')
        self.raw=b'{"task_key":"F13","task_key":"F13"}';self.assert_held('DUPLICATE_JSON_KEY')
        self.raw=b'x'*(POLICY['limits']['result_bytes']+1);self.assert_held('RESULT_BOUND')

    def test_policy_and_result_wire_drift_refuse(self):
        self.facts['policy_sha256']='f'*64;self.assert_held('POLICY_DIGEST')
        self.facts['policy_sha256']=g.digest(POLICY);self.raw+=b' ';self.assert_held('RESULT_CHANGED')

    def test_unverified_favorable_review_raw_source_refuses(self):
        # Favorable caller prose cannot replace the independently captured source.
        self.facts['review']['source_sha256']='f'*64;self.seal()
        self.assert_held('UNVERIFIED_REVIEW_SOURCE')

    def test_raw_check_observation_must_match_summary(self):
        raw=copy.deepcopy(self.facts['checks']);raw[0]['conclusion']='failure'
        self.facts['sources']['checks']=[page(self.binding,raw)];self.seal()
        self.assert_held('UNVERIFIED_CHECK_SOURCE')

    def test_forged_caller_facts_can_never_mint_effect_authority(self):
        # The fixture is deliberately forgeable: this API authenticates nobody.
        answer=self.assert_consistent();self.assertEqual(answer['decision'],'HOLD');self.assertEqual(answer['effect_authority'],'NONE')


    def test_initial_enumeration_stops_at_global_cap_plus_one(self):
        self.assert_consistent()
        scan=_BoundedScan(POLICY['limits']['files']+1)
        with patch.object(g.os,'scandir',return_value=scan),patch.object(g.os,'listdir',side_effect=AssertionError('Unbounded listdir forbidden')):
            answer=self.assess()
        self.assertFalse(answer['consistent']);self.assertEqual(answer['decision'],'HOLD');self.assertEqual(answer['effect_authority'],'NONE')
        self.assertEqual(answer['reasons'],['ENTRY_BOUND'])
        self.assertEqual(scan.consumed,POLICY['limits']['files']+1);self.assertTrue(scan.closed)

    def test_nested_enumeration_uses_remaining_global_cap(self):
        self.assert_consistent()
        original=g.os.scandir;calls=[0];scan=_BoundedScan(1)
        limits=copy.deepcopy(POLICY['limits']);limits['files']=2
        def scandir(fd):
            self.assertIs(type(fd),int);calls[0]+=1
            # Existing root/orchestration and integrator entries consume the
            # entire two-entry global budget before the leaf is enumerated.
            return scan if calls[0]==3 else original(fd)
        with patch.object(g.os,'scandir',side_effect=scandir),patch.object(g.os,'listdir',side_effect=AssertionError('Unbounded listdir forbidden')):
            with self.assertRaisesRegex(g.Held,'ENTRY_BOUND'):g.observe(self.candidate,limits)
        self.assertEqual(calls,[3]);self.assertEqual(scan.consumed,1);self.assertTrue(scan.closed)

    def test_final_reread_stops_at_original_count_plus_one(self):
        self.assert_consistent()
        original=g.os.scandir;calls=[0];scan=_BoundedScan(2)
        def scandir(fd):
            self.assertIs(type(fd),int);calls[0]+=1
            # Three initial directory walks precede the first final reread:
            # that leaf originally had exactly one entry. Two is the sentinel.
            return scan if calls[0]==4 else original(fd)
        with patch.object(g.os,'scandir',side_effect=scandir),patch.object(g.os,'listdir',side_effect=AssertionError('Unbounded listdir forbidden')):
            answer=self.assess()
        self.assertFalse(answer['consistent']);self.assertEqual(answer['decision'],'HOLD');self.assertEqual(answer['effect_authority'],'NONE')
        self.assertEqual(answer['reasons'],['ENTRY_BOUND'])
        self.assertEqual(calls,[4]);self.assertEqual(scan.consumed,2);self.assertTrue(scan.closed)

    def test_positive_initial_and_final_reads_never_use_listdir(self):
        self.assert_consistent()
        with patch.object(g.os,'listdir',side_effect=AssertionError('Unbounded listdir forbidden')):
            self.assert_consistent()


if __name__=='__main__':unittest.main()
