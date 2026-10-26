"""F18 synthetic evidence tests; root executes. No runtime acceptance cases run."""
import copy
import json
from pathlib import Path
import unittest
from evidence_policy import LEVELS,evaluate_evidence,validate_register,execution_subject
from synthetic_fixtures import evidence_fixture

ROOT=Path(__file__).resolve().parents[2]

class EvidenceTests(unittest.TestCase):
    def test_all_levels_require_independent_receipts_and_never_award(self):
        for level in LEVELS:
            claim,expected,trusted=evidence_fixture(level)
            result=evaluate_evidence(claim,expected,trusted)
            self.assertIsNone(result['level_awarded']);self.assertFalse(result['production_action_authorized'])
    def test_checksum_render_and_author_assertions_are_not_receipts(self):
        for kind in ('checksum','render_success','author_assertion'):
            c,e,t=evidence_fixture();t['synthetic-merge']['kind']=kind
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_missing_receipts_and_required_level_proofs_fail(self):
        for level in LEVELS:
            c,e,t=evidence_fixture(level)
            for reference in list(t):
                missing=copy.deepcopy(t);del missing[reference]
                with self.subTest(level=level,reference=reference),self.assertRaises(ValueError):evaluate_evidence(c,e,missing)
    def test_commit_locks_environment_must_be_current(self):
        for field,changed in [('commit','e'*40),('dependency_lock_sha256','f'*64),('environment_sha256','1'*64)]:
            c,e,t=evidence_fixture();c['identity'][field]=changed
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
            c,e,t=evidence_fixture();t['synthetic-case-receipt']['identity'][field]=changed
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_unknown_level_missing_extra_and_malformed_values_fail(self):
        for mutate in (lambda c:c.update(level='CHECKSUM_PASSED'),lambda c:c.update(extra=True),lambda c:c.update(cases={}),lambda c:c.update(author_ref=''),lambda c:c['identity'].update(commit='a'*40+'\n')):
            c,e,t=evidence_fixture();mutate(c)
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_not_run_fail_and_unapproved_na_block(self):
        for status in ('NOT_RUN','FAIL','NOT_APPLICABLE','OPEN_SOURCE_BLOCKER'):
            c,e,t=evidence_fixture();c['cases'][0]['status']=status
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_missing_duplicate_and_extra_cases_fail(self):
        for cases in ([],[dict(case_id='unknown',status='PASS',executor_ref='synthetic-executor',evidence_ref='synthetic-case-receipt')]):
            c,e,t=evidence_fixture();c['cases']=cases
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
        c,e,t=evidence_fixture();c['cases']*=2
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_author_self_execution_or_verification_fail(self):
        for field in ('actor_ref','verified_by'):
            c,e,t=evidence_fixture();t['synthetic-case-receipt'][field]=c['author_ref']
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_claim_author_alias_cannot_hide_self_execution(self):
        c,e,t=evidence_fixture()
        c['cases'][0]['executor_ref']=e['author_ref']
        t['synthetic-case-receipt']['actor_ref']=e['author_ref']
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
        c['author_ref']='synthetic-new-alias'
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_missing_or_changed_trusted_author_never_falls_back(self):
        for value in (None,'','synthetic-other-author'):
            c,e,t=evidence_fixture();e['author_ref']=value
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
        c,e,t=evidence_fixture();del e['author_ref']
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_expiry_and_future_proof_fail(self):
        for field,value in [('expires_at','2026-10-25T12:00:00Z'),('issued_at','2026-10-25T12:00:01Z')]:
            c,e,t=evidence_fixture();t['synthetic-case-receipt'][field]=value
            with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_production_scope_and_plan_are_bound(self):
        c,e,t=evidence_fixture('PRODUCTION_APPROVED');c['production']['target_ref']='other-target'
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
        c,e,t=evidence_fixture('PRODUCTION_APPROVED');c['plan_ref']='other-plan'
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
        c,e,t=evidence_fixture();c['production']={}
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_execution_from_another_plan_cannot_be_reused(self):
        c,e,t=evidence_fixture()
        c['plan_ref']=e['plan_ref']='synthetic-plan-b'
        # Reissue all supporting records for B; retain only execution from A.
        for reference in c['supporting'].values():
            t[reference]['subject']='synthetic-plan-b'
        with self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_execution_explicitly_reissued_for_new_plan_is_valid(self):
        c,e,t=evidence_fixture()
        c['plan_ref']=e['plan_ref']='synthetic-plan-b'
        for reference in c['supporting'].values():
            t[reference]['subject']='synthetic-plan-b'
        t['synthetic-case-receipt']['subject']=execution_subject('synthetic-plan-b','synthetic-case')
        self.assertIsNone(evaluate_evidence(c,e,t)['level_awarded'])
    def test_production_approval_must_not_predate_either_prerequisite(self):
        for later in ('synthetic-staging','synthetic-recovery'):
            c,e,t=evidence_fixture('PRODUCTION_APPROVED')
            t['synthetic-staging']['issued_at']='2026-10-25T11:40:00Z'
            t['synthetic-recovery']['issued_at']='2026-10-25T11:40:00Z'
            t[later]['issued_at']='2026-10-25T12:00:00Z'
            t['synthetic-human-approval']['issued_at']='2026-10-25T11:50:00Z'
            with self.subTest(later=later),self.assertRaises(ValueError):evaluate_evidence(c,e,t)
    def test_production_approval_at_or_after_both_receipts_is_valid(self):
        c,e,t=evidence_fixture('PRODUCTION_APPROVED')
        t['synthetic-staging']['issued_at']='2026-10-25T11:20:00Z'
        t['synthetic-recovery']['issued_at']='2026-10-25T11:30:00Z'
        for approved_at in ('2026-10-25T11:30:00Z','2026-10-25T11:50:00Z'):
            t['synthetic-human-approval']['issued_at']=approved_at
            result=evaluate_evidence(c,e,t)
            self.assertIsNone(result['level_awarded']);self.assertFalse(result['production_action_authorized'])
    def test_all_original_ids_mapped_and_annotations_separate(self):
        register=json.loads((ROOT/'policies/evidence/acceptance-register.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(validate_register(register,ROOT),dict(runtime_total=576,runtime_not_run=576,source_open_blockers=12,runtime_pass=0))
    def test_registry_mutations_do_not_promote_or_drop_ids(self):
        original=json.loads((ROOT/'policies/evidence/acceptance-register.json').read_text(encoding='utf-8-sig'))
        for mutate in (lambda r:r['records'].pop(),lambda r:r['records'][0].update(runtime_status='PASS'),lambda r:r['records'][0].update(assigned_person='invented-person'),lambda r:r['records'][0].update(verification_issue='wrong'),lambda r:r['records'][-1].update(source_annotation='NOT_RUN')):
            register=copy.deepcopy(original);mutate(register)
            with self.assertRaises(ValueError):validate_register(register,ROOT)

if __name__=='__main__':unittest.main(verbosity=2)
