import copy
import unittest
from check_dispatch_inputs import blockers, measurement_blockers


class InputChecks(unittest.TestCase):
    def valid(self):
        return dict(provider='codex-cli', agent_image_digest='sha256:fixture', credential_broker_ref='fixture', g02_approval_ref='fixture', provider_rpm=1, provider_tpm=1, provider_concurrency=1, task_timeout_seconds=1, total_spend_usd=0, per_task_spend_usd=0, approved_headroom=dict(cpu=1, memory_mib=1, disk_gib=1, gpu_vram_mib=0), **{k: True for k in ('capacity_approved', 'egress_qualified', 'disk_quota_qualified', 'cancellation_qualified', 'provider_limits_enforced', 'cross_repository_source_qualified', 'identity_qualified', 'adapter_qualified', 'subscription_entitlement_verified', 'worker_environment_qualified')}, production_actions_allowed=False, api_key_auth_allowed=False, extra_usage_purchase_allowed=False, billing_mode='ChatGPT subscription', implementation_model='GPT-6.1-Sol', implementation_reasoning_effort='low', review_provider='GitHub Copilot')

    def test_valid_is_only_input_validation(self):
        self.assertEqual(blockers(self.valid()), [])

    def test_wrong_container(self):
        for value in (None, [], 'x', 1):
            self.assertTrue(blockers(value))

    def test_invalid_numbers(self):
        for key in ('provider_rpm', 'provider_tpm', 'provider_concurrency', 'task_timeout_seconds', 'total_spend_usd', 'per_task_spend_usd'):
            for value in (-1, float('nan'), float('inf'), True, '1', [], None):
                with self.subTest(key=key, value=value):
                    record = self.valid(); record[key] = value
                    self.assertIn(key, blockers(record))

    def test_budget_order(self):
        record = self.valid(); record['per_task_spend_usd'] = 1
        self.assertIn('per_task_spend_exceeds_total', blockers(record))

    def test_headroom_and_boolean_types(self):
        record = self.valid(); record['approved_headroom']['memory_mib'] = -1
        record['adapter_qualified'] = 1
        self.assertIn('approved_headroom', blockers(record))
        self.assertIn('adapter_qualified', blockers(record))

    def test_measurements(self):
        import json
        from pathlib import Path
        record = json.loads(Path(__file__).with_name('measurements.json').read_text())
        self.assertEqual(measurement_blockers(record), [])
        for value in (-1, float('nan'), '10', True):
            changed = copy.deepcopy(record); changed['windows']['available_memory_mib'] = value
            self.assertTrue(measurement_blockers(changed))
        record['wsl']['memory_available_mib'] = record['wsl']['memory_total_mib'] + 1
        self.assertTrue(measurement_blockers(record))


if __name__ == '__main__':
    unittest.main()
