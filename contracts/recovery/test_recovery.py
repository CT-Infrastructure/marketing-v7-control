"""Synthetic recovery preconditions, not a restore or credential-access execution."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'policies/evidence'))
from synthetic_fixtures import recovery_fixture
from recovery_policy import evaluate_recovery

class RecoveryTests(unittest.TestCase):
    def test_complete_observations_only_yield_held_eligibility(self):
        record,expected,trusted=recovery_fixture()
        result=evaluate_recovery(record,expected,trusted)
        self.assertTrue(result['release_eligible_for_human_review']);self.assertEqual(result['state'],'HOLD')
        self.assertFalse(result['production_authorized']);self.assertFalse(result['automatic_retry_allowed'])
    def test_restore_never_starts_unheld(self):
        r,e,t=recovery_fixture();r['state']='RUNNING'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_unknown_remote_effect_or_missing_readback_blocks(self):
        r,e,t=recovery_fixture();r['remote_effects'][0]['outcome']='UNKNOWN'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();del t['synthetic-readback']
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_missing_or_extra_effect_is_rejected(self):
        r,e,t=recovery_fixture();r['remote_effects']=[]
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();r['remote_effects']*=2
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_non_authoritative_or_wrong_remote_outcome_rejected(self):
        for key,value in [('kind','cache_observation'),('outcome','OCCURRED')]:
            r,e,t=recovery_fixture();t['synthetic-readback'][key]=value
            with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_post_backup_suppression_must_reach_current_cutoff(self):
        for field,value in [('after_backup','other-generation'),('through','2026-10-25T11:30:00Z')]:
            r,e,t=recovery_fixture();r['suppression'][field]=value
            with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();del t['synthetic-suppression-proof']
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_receipt_cannot_predate_replayed_checkpoint(self):
        r,e,t=recovery_fixture();t['synthetic-suppression-proof']['issued_at']='2026-10-25T11:59:59Z'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_credential_reference_without_observed_access_is_not_usability(self):
        r,e,t=recovery_fixture();del t['synthetic-access-proof']
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();t['synthetic-access-proof']['kind']='checksum'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_access_test_bound_to_restored_environment_and_broker_scope(self):
        r,e,t=recovery_fixture();r['credentials'][0]['broker_ref']='other-broker'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();t['synthetic-access-proof']['issued_at']='2026-10-25T10:59:59Z'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();t['synthetic-access-proof']['identity']['environment_sha256']='1'*64
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_credential_values_and_missing_credentials_rejected(self):
        r,e,t=recovery_fixture();r['credentials'][0]['secret_value']='synthetic-forbidden-value'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();r['credentials'][0]['broker_ref']='https://user:password@example.invalid'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();r['credentials']=[]
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_backup_checksum_or_generation_change_is_not_restore_proof(self):
        r,e,t=recovery_fixture();t['synthetic-restore-proof']['kind']='checksum'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();r['backup']['generation_ref']='other-generation'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();r['backup']['created_at']='2026-10-25T09:00:00Z'
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
    def test_missing_isolation_or_self_attestation_blocks(self):
        r,e,t=recovery_fixture();del t['synthetic-hold-proof']
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)
        r,e,t=recovery_fixture();t['synthetic-restore-proof']['verified_by']=r['author_ref']
        with self.assertRaises(ValueError):evaluate_recovery(r,e,t)

if __name__=='__main__':unittest.main(verbosity=2)
