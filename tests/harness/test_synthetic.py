"""Authored offline F07 tests. Run only in the approved isolated test runner."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import synthetic as s

class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.parent = tempfile.TemporaryDirectory(prefix='f07-test-')
        self.root = Path(self.parent.name)
        self.identity = s.scenario()['identity']
    def tearDown(self):
        self.parent.cleanup()
    def harness(self, **kwargs):
        return s.Harness(self.root, **kwargs)
    def resign(self, doc):
        body=s.encoded(doc)
        return body,hmac.new(s.SYNTHETIC_CALLBACK_KEY,body,hashlib.sha256).hexdigest()

    def test_accepted_contract_and_single_effect(self):
        with self.harness() as h:
            r=h.submit(self.identity,'synthetic-approval')
            s.core.validate('action-receipt',r)
            self.assertEqual(r['status'],'ACCEPTED')
            self.assertEqual(r['outbound_state'],'CONFIRMED')
            self.assertEqual(len(h.provider.calls),1)
            self.assertEqual(h.db.execute('SELECT count(*) FROM actions').fetchone()[0],1)
            self.assertEqual(h.db.execute('SELECT count(*) FROM history').fetchone()[0],3)

    def test_initial_null_approval_binds_once(self):
        with self.harness() as h:
            h.submit(self.identity,'synthetic-approval')
            rows=h.db.execute('SELECT receipt FROM history ORDER BY rowid').fetchall()
            held,submitted=[json.loads(row[0]) for row in rows[:2]]
            self.assertIsNone(held['approval_ref'])
            self.assertEqual(submitted['approval_ref'],'synthetic-approval')
            self.assertTrue(s.core.check_transition(held,submitted))

    def test_accepted_replay_never_resubmits_even_after_expiry(self):
        with self.harness() as h:
            first=h.submit(self.identity,'synthetic-approval')
            h.clock.advance(7200)
            self.assertEqual(h.submit(self.identity,'synthetic-approval'),first)
            self.assertEqual(len(h.provider.calls),1)

    def test_unknown_timeout_replay_retains_reservation(self):
        for mode in ('TIMEOUT_AFTER_ACCEPT','TIMEOUT_BEFORE_ACCEPT'):
            with self.subTest(mode=mode),self.harness(provider=s.FakeProvider(mode)) as h:
                first=h.submit(self.identity,'synthetic-approval')
                self.assertEqual(first['status'],'UNKNOWN')
                self.assertTrue(first['reservation_retained'])
                self.assertEqual(first['outbound_state'],'HOLD')
                self.assertEqual(h.submit(self.identity,'synthetic-approval'),first)
                self.assertEqual(len(h.provider.calls),1)

    def test_readback_occurrence_and_absence_do_not_replay(self):
        for mode,outcome in [('TIMEOUT_AFTER_ACCEPT','OCCURRED'),('TIMEOUT_BEFORE_ACCEPT','NOT_OCCURRED')]:
            with self.subTest(mode=mode),self.harness(provider=s.FakeProvider(mode)) as h:
                first=h.submit(self.identity,'synthetic-approval')
                result=h.reconcile(first['action_key'])
                self.assertEqual(result['status'],'RECONCILED')
                self.assertEqual(result['reconciliation_outcome'],outcome)
                self.assertEqual(result['reservation_retained'],outcome=='OCCURRED')
                self.assertEqual(h.submit(self.identity,'synthetic-approval'),result)
                self.assertEqual(len(h.provider.calls),1)

    def test_provider_rejection_is_held(self):
        with self.harness(provider=s.FakeProvider('REJECT')) as h:
            result=h.submit(self.identity,'synthetic-approval')
            self.assertEqual(result['status'],'REJECTED')
            self.assertEqual(result['outbound_state'],'HOLD')
            self.assertIsNone(result['provider_object_ref'])

    def test_authority_stale_revoked_unavailable_and_unknown_hold_before_effect(self):
        for case in ('expired','revoked','unavailable','unknown'):
            with self.subTest(case=case),self.harness() as h:
                approval='synthetic-approval'
                if case=='expired':h.clock.advance(3600)
                if case=='revoked':h.authority.revoke(approval)
                if case=='unavailable':h.authority.available=False
                if case=='unknown':approval='synthetic-missing'
                with self.assertRaises(ValueError):h.submit(self.identity,approval)
                self.assertEqual(h.provider.calls,[])
                self.assertEqual(h.db.execute('SELECT count(*) FROM actions').fetchone()[0],0)

    def test_wrong_client_revision_scope_asset_and_destination(self):
        mutations=[('client_id','synthetic-other'),('approved_revision','revision-other'),
                   ('action_scope','publish:synthetic-other')]
        for field,value in mutations:
            with self.subTest(field=field),self.harness() as h:
                identity=dict(self.identity,**{field:value})
                with self.assertRaises(ValueError):h.submit(identity,'synthetic-approval')
                self.assertEqual(h.provider.calls,[])
        for field,value in [('asset_sha256s',['b'*64]),('destination','synthetic-other')]:
            with self.subTest(approval_field=field),self.harness() as h:
                h.authority._approvals['synthetic-approval'][field]=value
                with self.assertRaises(ValueError):h.submit(self.identity,'synthetic-approval')
                self.assertEqual(h.provider.calls,[])

    def test_fake_authority_returns_detached_snapshots(self):
        with self.harness() as h:
            snapshot=h.authority.get('synthetic-approval')
            snapshot['status']='REVOKED'
            self.assertEqual(h.authority.get('synthetic-approval')['status'],'APPROVED')

    def test_signed_callback_and_replay_are_bound_to_object(self):
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            pending=h.submit(self.identity,'synthetic-approval')
            body,signature=h.provider.callback(pending['action_key'],h.clock)
            result=h.consume_callback(body,signature)
            self.assertEqual(result['reconciliation_outcome'],'OCCURRED')
            self.assertEqual(h.consume_callback(body,signature),result)
            self.assertEqual(len(h.provider.calls),1)
            self.assertEqual(h.db.execute('SELECT count(*) FROM callbacks').fetchone()[0],1)

    def test_static_signed_fixture_matches_fake_provider(self):
        fixture=json.loads((s.FIXTURES/'signed-callback.json').read_text(encoding='utf-8-sig'))
        self.assertTrue(fixture['synthetic_only'])
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            pending=h.submit(self.identity,'synthetic-approval')
            body,signature=h.provider.callback(pending['action_key'],h.clock)
            self.assertEqual(body,fixture['body_utf8'].encode('utf-8'))
            self.assertEqual(signature,fixture['signature'])
            result=h.consume_callback(body,signature)
            self.assertEqual(result['status'],'RECONCILED')

    def test_callback_event_cannot_be_reused_for_another_action(self):
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            first=h.submit(self.identity,'synthetic-approval')
            h.consume_callback(*h.provider.callback(first['action_key'],h.clock))
            second=h.submit(dict(self.identity,source_event_id='synthetic-event-0002'),'synthetic-approval')
            with self.assertRaises(ValueError):
                h.consume_callback(*h.provider.callback(second['action_key'],h.clock))
            self.assertEqual(h.receipt(second['action_key'])['status'],'UNKNOWN')

    def test_callback_bad_signature_body_and_cross_identity_rejected(self):
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            pending=h.submit(self.identity,'synthetic-approval')
            body,signature=h.provider.callback(pending['action_key'],h.clock)
            with self.assertRaises(ValueError):h.consume_callback(body,'0'*64)
            with self.assertRaises(ValueError):h.consume_callback(body+b' ',signature)
            for field in ('client_id','destination','provider','provider_object_ref','action_key'):
                doc=json.loads(body);doc[field]='synthetic-wrong'
                with self.subTest(field=field),self.assertRaises(ValueError):h.consume_callback(*self.resign(doc))
            self.assertEqual(h.receipt(pending['action_key'])['status'],'UNKNOWN')

    def test_callback_expired_future_and_extra_field_rejected(self):
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            pending=h.submit(self.identity,'synthetic-approval')
            body,signature=h.provider.callback(pending['action_key'],h.clock)
            for field,value in [('occurred_at','2026-10-25T11:00:00Z'),('occurred_at','2026-10-25T13:00:00Z'),('extra','field')]:
                doc=json.loads(body);doc[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):h.consume_callback(*self.resign(doc))

    def test_duplicate_signed_callback_fields_rejected(self):
        with self.harness(provider=s.FakeProvider('TIMEOUT_AFTER_ACCEPT')) as h:
            pending=h.submit(self.identity,'synthetic-approval')
            body,signature=h.provider.callback(pending['action_key'],h.clock)
            malformed=body[:-1]+b',"event_id":"synthetic-other"}'
            signature=hmac.new(s.SYNTHETIC_CALLBACK_KEY,malformed,hashlib.sha256).hexdigest()
            with self.assertRaises(ValueError):h.consume_callback(malformed,signature)
            self.assertEqual(h.receipt(pending['action_key'])['status'],'UNKNOWN')

    def test_known_provider_id_cannot_change_on_readback(self):
        with self.harness() as h:
            accepted=h.submit(self.identity,'synthetic-approval')
            h.provider._objects[accepted['action_key']]['provider_object_ref']='synthetic-other-object'
            with self.assertRaises(ValueError):h.reconcile(accepted['action_key'])
            self.assertEqual(h.receipt(accepted['action_key']),accepted)

    def test_network_gate_denies_real_schemes_without_socket_calls(self):
        blocked=['https://example.invalid','http://192.0.2.1','smtp://example.invalid',
                 'tel:+15550100000','fake://wordpress/publish?url=https://example.invalid',
                 'fake://user:password@wordpress/publish','file:///etc/passwd','fake://unknown/send']
        with patch('socket.create_connection',side_effect=AssertionError('must never call a socket')):
            with self.harness() as h:
                for endpoint in blocked:
                    with self.subTest(endpoint=endpoint),self.assertRaises(s.NetworkDenied):
                        h.submit(self.identity,'synthetic-approval',endpoint)
                self.assertEqual(h.provider.calls,[])

    def test_all_endpoints_are_in_process_synthetic(self):
        provider=s.FakeProvider()
        for endpoint,(owner,destination) in s.ENDPOINTS.items():
            obj=provider.request(endpoint,'synthetic-key-'+owner,'synthetic-client',{})
            self.assertEqual(obj['destination'],destination)
            self.assertEqual(obj['provider'],owner)

    def test_model_responses_are_deterministic_detached_and_untrusted(self):
        model=s.FakeModel();first=model.respond('valid-draft');first['text']='changed'
        self.assertNotEqual(first,model.respond('valid-draft'))
        self.assertEqual(model.respond('valid-draft'),model.respond('valid-draft'))
        self.assertIsNone(model.respond('missing-data')['value'])
        self.assertEqual(model.respond('missing-data')['status'],'UNKNOWN')
        with self.assertRaises(json.JSONDecodeError):json.loads(model.respond('malformed-json'))
        with self.assertRaises(ValueError):model.respond('unspecified')
        self.assertEqual(model.respond('prompt-injection')['external_effects'],'HOLD')

    def test_disposable_database_is_removed_and_does_not_touch_siblings(self):
        sentinel=self.root/'synthetic-sibling.txt';sentinel.write_text('preserve')
        with self.harness() as h:
            directory=h.directory
            h.submit(self.identity,'synthetic-approval')
            self.assertTrue((directory/'synthetic.sqlite').is_file())
        self.assertFalse(directory.exists())
        self.assertEqual(sentinel.read_text(),'preserve')
        with self.harness() as fresh:
            self.assertEqual(fresh.db.execute('SELECT count(*) FROM actions').fetchone()[0],0)

    def test_clock_is_deterministic_and_never_moves_backwards(self):
        clock=s.FakeClock();before=clock.now();clock.advance(30)
        self.assertGreater(clock.now(),before)
        for value in (-1,True,'1'):
            with self.assertRaises(ValueError):clock.advance(value)

    def test_retention_policy_is_bounded_and_has_no_production_inputs(self):
        policy=json.loads((s.FIXTURES/'retention.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(policy['fixture_database'],'delete_on_context_exit')
        self.assertEqual(policy['exported_test_artifact_max_age_days'],7)
        self.assertFalse(policy['production_credentials_allowed'])
        self.assertFalse(policy['raw_payload_export_allowed'])

if __name__=='__main__':
    unittest.main(verbosity=2)



