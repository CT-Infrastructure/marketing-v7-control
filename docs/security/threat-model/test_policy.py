"""Synthetic-only executable negative/positive policy examples; no network."""
import hashlib
import hmac
import json
import unittest
import policy_checks as p

class PolicyTests(unittest.TestCase):
    def test_policy_explicitly_disables_production(self):
        self.assertIs(p.POLICY['production_enabled'], False)
        self.assertEqual(p.POLICY['evidence_level'], 'offline_synthetic_policy_only')

    def test_coding_positive_scope(self):
        self.assertTrue(p.capability('coding_agent', 'write_owned_candidate', 'trusted_packet'))

    def test_untrusted_prompt_cannot_grant_authority(self):
        for authority in ('issue_text', 'retrieved_document', 'model_output', 'agent_result', '', None):
            self.assertFalse(p.capability('coding_agent', 'write_owned_candidate', authority))

    def test_arbitrary_build_and_malicious_agent_denied_capabilities(self):
        for role in ('coding_agent', 'build_job', 'model', 'unknown', None):
            for action in ('production_send', 'host_socket', 'coordinator_read', 'fetch_mock', 'accept_task', 'launch_model'):
                self.assertFalse(p.capability(role, action, 'trusted_packet'), (role, action))

    def test_public_export_requires_approval(self):
        self.assertTrue(p.export_allowed('public', 'public_issue', approved=True))
        self.assertFalse(p.export_allowed('public', 'public_issue'))

    def test_internal_synthetic_export(self):
        self.assertTrue(p.export_allowed('internal', 'shared_log', approved=True, synthetic=True))
        self.assertFalse(p.export_allowed('internal', 'shared_log', approved=True))

    def test_unknown_and_private_data_denied_export(self):
        for label in (None, '', 'unknown', 'confidential', 'restricted'):
            for sink in ('shared_log', 'public_issue', 'model_prompt', 'private_store'):
                self.assertFalse(p.export_allowed(label, sink, approved=True, synthetic=True))

    def test_truthy_strings_do_not_approve_export(self):
        self.assertFalse(p.export_allowed('public', 'public_issue', approved='true'))
        self.assertFalse(p.export_allowed('internal', 'shared_log', approved=True, synthetic='true'))

    def test_tenant_positive_and_crossing(self):
        self.assertTrue(p.private_read('scoped_app', 'confidential', 'synthetic-a', 'synthetic-a'))
        for actor, owner in [('synthetic-a', 'synthetic-b'), ('', ''), (None, None)]:
            self.assertFalse(p.private_read('scoped_app', 'confidential', actor, owner))
        self.assertFalse(p.private_read('coding_agent', 'confidential', 'synthetic-a', 'synthetic-a'))
        self.assertFalse(p.private_read('scoped_app', 'restricted', 'synthetic-a', 'synthetic-a'))

    def test_mock_egress_positive(self):
        self.assertTrue(p.fetch_mock('egress_broker', 'https://fixture.example.invalid:443/approved'))

    def test_ssrf_and_exfiltration_targets_denied(self):
        for url in ('http://127.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/',
                    'http://10.0.0.1/', 'file:///synthetic-secret', 'https://evil.example.invalid/',
                    'https://fixture.example.invalid@evil.example.invalid/approved',
                    'https://fixture.example.invalid:443/approved?redirect=http://10.0.0.1',
                    'https://fixture.example.invalid:443/approved/../private'):
            self.assertFalse(p.fetch_mock('egress_broker', url), url)
        self.assertFalse(p.fetch_mock('coding_agent', p.POLICY['mock_targets'][0]))

    def setUp(self):
        self.req = dict(tenant='synthetic-a', revision='synthetic-r1', destination='synthetic-d', channel='voice', asset_set_hash='synthetic-assets-a', action_scope='synthetic-call')
        self.approval = dict(self.req, human_verified=True, expired=False)
        self.body = b'{"synthetic":true}'
        self.key = b'synthetic-test-only-not-a-real-credential'
        self.args = dict(role='event_adapter', body=self.body, timestamp=1000, now=1001,
                         event_id='synthetic-event', authenticated_tenant='synthetic-a',
                         payload_tenant='synthetic-a', seen=set(), key=self.key)
        raw = json.dumps(['synthetic-event', 1000, 'synthetic-a'], separators=(',', ':')).encode() + b'\n' + self.body
        self.args['signature'] = hmac.new(self.key, raw, hashlib.sha256).hexdigest()

    def allowed_dispatch(self, **kw):
        state = dict(eligible=True, reconciled=True, outcome='confirmed', eligibility_channel='voice')
        state.update(kw)
        return p.dispatch('dispatch_guard', self.req, self.approval, **state)

    def test_dispatch_positive(self):
        self.assertTrue(self.allowed_dispatch())

    def test_exact_approval_binding(self):
        for field in ('tenant', 'revision', 'destination', 'channel', 'asset_set_hash', 'action_scope'):
            request = dict(self.req, **{field: 'different'})
            self.assertFalse(p.dispatch('dispatch_guard', request, self.approval, eligible=True, reconciled=True, outcome='confirmed', eligibility_channel='voice'))
        self.assertFalse(p.dispatch('coding_agent', self.req, self.approval, eligible=True, reconciled=True, outcome='confirmed', eligibility_channel='voice'))

    def test_recovery_unknown_and_missing_permission_hold(self):
        for state in (dict(reconciled=False), dict(outcome='UNKNOWN'), dict(eligible=False), dict(eligible='true')):
            self.assertFalse(self.allowed_dispatch(**state))
        self.assertFalse(p.dispatch('dispatch_guard', self.req, self.approval))

    def test_unverified_expired_missing_approvals_hold(self):
        for approval in (None, {}, dict(self.approval, expired=True), dict(self.approval, human_verified=False)):
            self.assertFalse(p.dispatch('dispatch_guard', self.req, approval, eligible=True, reconciled=True, outcome='confirmed', eligibility_channel='voice'))

    def test_material_binding_missing_is_denied(self):
        for field in ('asset_set_hash', 'action_scope'):
            saved = self.req.pop(field)
            self.assertFalse(self.allowed_dispatch())
            self.req[field] = saved

    def test_matching_unknown_channel_is_denied(self):
        self.req['channel'] = self.approval['channel'] = 'unknown'
        self.assertFalse(self.allowed_dispatch(eligibility_channel='unknown'))

    def test_channel_specific_eligibility_is_required(self):
        self.assertFalse(self.allowed_dispatch(eligibility_channel=None))
        self.assertFalse(self.allowed_dispatch(eligibility_channel='email'))

    def test_replay_scope_separates_tenants_and_sources(self):
        self.assertTrue(p.webhook(**self.args))
        other_source = dict(self.args, source_system='synthetic-other', authenticated_source='synthetic-other')
        self.assertTrue(p.webhook(**other_source))
        self.assertFalse(p.webhook(**other_source))
        other = dict(self.args, payload_tenant='synthetic-b', authenticated_tenant='synthetic-b')
        raw = json.dumps(['synthetic-event', 1000, 'synthetic-b'], separators=(',', ':')).encode() + b'\n' + self.body
        other['signature'] = hmac.new(self.key, raw, hashlib.sha256).hexdigest()
        self.assertTrue(p.webhook(**other))
        self.assertFalse(p.webhook(**other))

    def test_source_identity_must_match(self):
        self.assertFalse(p.webhook(**dict(self.args, source_system='wrong')))
        self.assertFalse(p.webhook(**dict(self.args, source_system='', authenticated_source='')))
        self.assertFalse(p.webhook(**dict(self.args, source_system=None, authenticated_source=None)))
        self.assertEqual(self.args['seen'], set())

    def test_inheritance_preserves_most_restrictive_input(self):
        self.assertEqual(p.inherit_classification(['public', 'restricted']), 'restricted')
        self.assertEqual(p.inherit_classification(['confidential', 'internal']), 'confidential')
        for labels in ([], None, ['unknown'], ['public', None]):
            self.assertIsNone(p.inherit_classification(labels))

    def test_downgrade_fails_closed_pending_owner_workflow(self):
        self.assertIsNone(p.reclassify(['restricted', 'public'], 'public'))
        self.assertIsNone(p.reclassify(['confidential'], 'internal'))
        self.assertEqual(p.reclassify(['internal'], 'confidential'), 'confidential')
        self.assertEqual(p.reclassify(['public'], 'public'), 'public')
        self.assertIsNone(p.reclassify(['unknown'], 'public'))

    def test_webhook_valid_then_replay_denied(self):
        self.assertTrue(p.webhook(**self.args))
        self.assertFalse(p.webhook(**self.args))

    def test_webhook_forged_modified_and_wrong_tenant_denied(self):
        for changed in (dict(signature='0'*64), dict(body=b'changed'), dict(payload_tenant='synthetic-b'),
                        dict(authenticated_tenant='synthetic-b'), dict(event_id='changed'), dict(role='coding_agent')):
            self.assertFalse(p.webhook(**dict(self.args, **changed)))
            self.assertEqual(self.args['seen'], set())

    def test_webhook_stale_future_missing_and_oversized_denied(self):
        for changed in (dict(now=1301), dict(now=999), dict(timestamp=None), dict(event_id=''),
                        dict(body=b'x'*2049), dict(signature=None), dict(signature='é'*64), dict(key=b'')):
            self.assertFalse(p.webhook(**dict(self.args, **changed)))
            self.assertEqual(self.args['seen'], set())

if __name__ == '__main__':
    unittest.main(verbosity=2)

