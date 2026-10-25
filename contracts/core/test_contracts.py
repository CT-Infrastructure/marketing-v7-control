"""Synthetic contract boundary tests; never connects to providers."""
import copy
import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator, ValidationError
import validate as core

class Contracts(unittest.TestCase):
    def fixture(self, name):
        return json.loads((Path(__file__).parent/'fixtures'/(name+'.json')).read_text())
    def test_schema_self_validation(self):
        for schema in core.SCHEMAS.values(): Draft202012Validator.check_schema(schema)
    def test_all_valid_fixtures(self):
        for kind in ('event-envelope','approval-reference','action-receipt','evidence-manifest'):
            core.validate(kind,self.fixture(kind))
    def test_seed_compatible(self):
        core.validate('event-envelope',json.loads((Path(__file__).resolve().parents[2]/'schemas/event-envelope.example.json').read_text()))
    def test_event_invalid(self):
        for key,value in [('schema_version','2.0'),('occurred_at','2026-02-30T12:00:00Z'),('occurred_at','2026-10-25T12:00:00'),('occurred_at','2026-10-25T12:00:00+00:00'),('default_outbound_state','SEND'),('workflow_id','Z99'),('client_id',''),('client_id','bad\nclient'),('unexpected',True)]:
            with self.subTest(key=key,value=value):
                x=self.fixture('event-envelope');x[key]=value
                with self.assertRaises((ValueError,ValidationError)):core.validate('event-envelope',x)
    def test_event_chronology(self):
        x=self.fixture('event-envelope');x['received_at']='2026-10-24T12:00:00Z'
        with self.assertRaises(ValueError):core.validate('event-envelope',x)
    def approval_args(self):
        a=self.fixture('approval-reference')
        return {k:a[k] for k in ('client_id','approved_revision','asset_sha256s','destination','action_scope')}|{'now':'2026-10-25T12:30:00Z'}
    def test_approval_valid(self):core.check_approval(self.fixture('approval-reference'),**self.approval_args())
    def test_approval_bindings(self):
        for key in ('client_id','approved_revision','destination','action_scope','asset_sha256s'):
            args=self.approval_args();args[key]=['b'*64] if key=='asset_sha256s' else 'wrong'
            with self.subTest(key=key),self.assertRaises(ValueError):core.check_approval(self.fixture('approval-reference'),**args)
    def test_approval_stale_future_revoked(self):
        for status,now in [('APPROVED','2026-10-25T13:00:00Z'),('APPROVED','2026-10-25T11:59:59Z'),('REVOKED','2026-10-25T12:30:00Z')]:
            a=self.fixture('approval-reference');a['status']=status;args=self.approval_args();args['now']=now
            with self.subTest(status=status,now=now),self.assertRaises(ValueError):core.check_approval(a,**args)
    def test_action_key_collision_resistance(self):
        i=self.fixture('action-receipt')['action_identity'];base=core.action_key(i)
        for key in core.FIELDS:
            j=dict(i);j[key]+='x';self.assertNotEqual(base,core.action_key(j))
        a=dict(i,client_id='a:b',source_system='c');b=dict(i,client_id='a',source_system='b:c')
        self.assertNotEqual(core.action_key(a),core.action_key(b))
        self.assertEqual(base,core.action_key(dict(reversed(list(i.items())))))
    def test_key_tamper(self):
        r=self.fixture('action-receipt');r['action_identity']['client_id']='wrong'
        with self.assertRaises(ValueError):core.validate('action-receipt',r)
    def test_unknown_fail_closed(self):
        for key,value in [('reservation_retained',False),('outbound_state','CONFIRMED'),('reconciliation_ref','pretend')]:
            r=self.fixture('action-receipt');r[key]=value
            with self.subTest(key=key),self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_unknown_no_retry(self):
        old=self.fixture('action-receipt');new=copy.deepcopy(old);new.update(receipt_id='new',status='SUBMITTED')
        with self.assertRaises(ValueError):core.check_transition(old,new)
    def test_reconciliation_link(self):
        old=self.fixture('action-receipt');new=copy.deepcopy(old);new.update(receipt_id='new',status='RECONCILED',reconciliation_ref='synthetic-readback',reconciliation_outcome='NOT_OCCURRED',reservation_retained=False)
        core.check_transition(old,new)
        new['action_identity']['client_id']='wrong';new['action_key']=core.action_key(new['action_identity'])
        with self.assertRaises(ValueError):core.check_transition(old,new)
    def test_accepted_requires_provider_id(self):
        r=self.fixture('action-receipt');r.update(status='ACCEPTED',outbound_state='CONFIRMED')
        with self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_reconciliation_cannot_release_occurred(self):
        r=self.fixture('action-receipt');r.update(status='RECONCILED',reconciliation_ref='readback',reconciliation_outcome='OCCURRED',provider_object_ref='post-1',outbound_state='CONFIRMED',reservation_retained=False)
        with self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_rejected_requires_hold(self):
        r=self.fixture('action-receipt');r.update(status='REJECTED',outbound_state='CONFIRMED')
        with self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_external_states_require_approval(self):
        for state in ('SUBMITTED','ACCEPTED','REJECTED','UNKNOWN','RECONCILED'):
            r=self.fixture('action-receipt');r.update(status=state,approval_ref=None)
            if state=='ACCEPTED':r.update(outbound_state='CONFIRMED',provider_object_ref='native-1')
            if state=='RECONCILED':r.update(reconciliation_ref='readback',reconciliation_outcome='NOT_OCCURRED',reservation_retained=False)
            with self.subTest(state=state),self.assertRaises(ValidationError):core.validate('action-receipt',r)
        held=self.fixture('action-receipt');held.update(status='HELD',approval_ref=None)
        core.validate('action-receipt',held)
        submitted=dict(held,receipt_id='next',status='SUBMITTED')
        with self.assertRaises(ValidationError):core.check_transition(held,submitted)
    def test_known_provider_identity_is_immutable(self):
        old=self.fixture('action-receipt');old.update(status='ACCEPTED',outbound_state='CONFIRMED',provider_object_ref='native-1')
        new=dict(old,receipt_id='next',status='RECONCILED',reconciliation_ref='readback',reconciliation_outcome='OCCURRED')
        core.check_transition(old,new)
        for changed in ('native-2',None):
            with self.subTest(changed=changed),self.assertRaises((ValueError,ValidationError)):
                core.check_transition(old,dict(new,provider_object_ref=changed))
    def test_unknown_can_discover_provider_identity(self):
        old=self.fixture('action-receipt')
        new=dict(old,receipt_id='next',status='RECONCILED',reconciliation_ref='readback',reconciliation_outcome='OCCURRED',provider_object_ref='native-1',outbound_state='CONFIRMED')
        core.check_transition(old,new)
    def test_digest_exact_lengths(self):
        for digest in ('a'*64+'\n','a'*63,'a'*65):
            a=self.fixture('approval-reference');a['asset_sha256s']=[digest]
            with self.subTest(digest=digest),self.assertRaises(ValidationError):core.validate('approval-reference',a)
            e=self.fixture('evidence-manifest');e['artifact_hashes']={'file':digest}
            with self.assertRaises(ValidationError):core.validate('evidence-manifest',e)
        r=self.fixture('action-receipt');r['action_key']+='\n'
        with self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_receipt_event_matches_hashed_identity(self):
        r=self.fixture('action-receipt');r['event_id']='unrelated-event'
        with self.assertRaises(ValueError):core.validate('action-receipt',r)
    def test_absence_has_no_provider_object(self):
        r=self.fixture('action-receipt');r.update(status='RECONCILED',reconciliation_ref='readback',reconciliation_outcome='NOT_OCCURRED',reservation_retained=False,provider_object_ref='native-1')
        with self.assertRaises(ValidationError):core.validate('action-receipt',r)
    def test_money(self):
        v=Draft202012Validator(core.SCHEMAS['common']['$defs']['money'])
        v.validate({'amount':'12.30','currency':'USD'})
        for x in ({'amount':12.3,'currency':'USD'},{'amount':'NaN','currency':'USD'},{'amount':'12','currency':'usd'},{'amount':'1e3','currency':'USD'}):
            with self.assertRaises(ValidationError):v.validate(x)
    def test_evidence_paths_and_case_uniqueness(self):
        for path in ('../secret','/absolute','C:/secret','x\\y'):
            e=self.fixture('evidence-manifest');e['artifact_hashes']={path:'b'*64}
            with self.subTest(path=path),self.assertRaises(ValueError):core.validate('evidence-manifest',e)
        e=self.fixture('evidence-manifest');e['cases'].append(e['cases'][0])
        with self.assertRaises(ValueError):core.validate('evidence-manifest',e)
    def test_production_requires_authorization_ref(self):
        e=self.fixture('evidence-manifest');e['evidence_level']='PRODUCTION_APPROVED'
        with self.assertRaises(ValidationError):core.validate('evidence-manifest',e)

if __name__=='__main__':unittest.main(verbosity=2)
