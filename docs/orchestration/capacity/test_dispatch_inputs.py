import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from check_dispatch_inputs import blockers, measurement_blockers, number


class InputChecks(unittest.TestCase):
    def valid(self):
        return dict(provider='codex-cli', agent_image_digest='sha256:fixture', credential_broker_ref='fixture', g02_approval_ref='fixture', provider_rpm=1, provider_tpm=1, provider_concurrency=1, task_timeout_seconds=1, total_spend_usd=0, per_task_spend_usd=0, approved_headroom=dict(cpu=1, memory_mib=1, disk_gib=1, gpu_vram_mib=0), **{k: True for k in ('capacity_approved', 'egress_qualified', 'disk_quota_qualified', 'cancellation_qualified', 'provider_limits_enforced', 'cross_repository_source_qualified', 'identity_qualified', 'adapter_qualified', 'subscription_entitlement_verified', 'worker_environment_qualified')}, production_actions_allowed=False, api_key_auth_allowed=False, extra_usage_purchase_allowed=False, billing_mode='ChatGPT subscription', implementation_model='GPT-6.1-Sol', implementation_reasoning_effort='low', review_provider='GitHub Copilot')

    def test_valid_is_only_input_validation(self):
        self.assertEqual(blockers(self.valid()), [])

    def run_cli(self, measurements, record=None):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / 'dispatch.json'
            measurements_path = Path(directory) / 'measurements.json'
            input_path.write_text(json.dumps(self.valid() if record is None else record))
            measurements_path.write_text(json.dumps(measurements))
            result = subprocess.run(
                [sys.executable, '-B', str(Path(__file__).with_name('check_dispatch_inputs.py')),
                 '--input', str(input_path), '--measurements', str(measurements_path)],
                capture_output=True, text=True, check=False)
        self.assertEqual(result.stderr, '')
        return result.returncode, json.loads(result.stdout)

    def test_cli_rejects_nonobject_measurements(self):
        for value in (None, [], 'snapshot', 1, 1.5, True, False):
            with self.subTest(value=value):
                code, result = self.run_cli(value)
                self.assertEqual(code, 2)
                self.assertEqual(result, {
                    'live_dispatch': 'HOLD', 'missing': ['measurements_must_be_object']})

    def test_cli_valid_measurements_require_qualification(self):
        measurements = json.loads(Path(__file__).with_name('measurements.json').read_text())
        code, result = self.run_cli(measurements)
        self.assertEqual(code, 0)
        self.assertEqual(result, {
            'live_dispatch': 'INPUTS_PRESENT_QUALIFICATION_STILL_REQUIRED', 'missing': []})

    def test_numeric_range(self):
        for value in (10 ** 400, -(10 ** 400), int(sys.float_info.max) + 1):
            for positive in (False, True):
                with self.subTest(value=value, positive=positive):
                    self.assertFalse(number(value, positive=positive))
        for value in (1, 1.5, sys.float_info.max, int(sys.float_info.max)):
            self.assertTrue(number(value, positive=True))
        self.assertTrue(number(0))
        self.assertFalse(number(0, positive=True))

    def test_cli_rejects_huge_integers(self):
        measurements = json.loads(Path(__file__).with_name('measurements.json').read_text())
        for location in ('provider_rpm', 'approved_headroom', 'measurements.windows.logical_cpu'):
            with self.subTest(location=location):
                record = self.valid()
                snapshot = copy.deepcopy(measurements)
                if location == 'provider_rpm':
                    record['provider_rpm'] = 10 ** 400
                elif location == 'approved_headroom':
                    record['approved_headroom']['cpu'] = 10 ** 400
                else:
                    snapshot['windows']['logical_cpu'] = 10 ** 400
                code, result = self.run_cli(snapshot, record)
                self.assertEqual(code, 2)
                self.assertEqual(result, {'live_dispatch': 'HOLD', 'missing': [location]})

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
        record = json.loads(Path(__file__).with_name('measurements.json').read_text())
        self.assertEqual(measurement_blockers(record), [])
        for value in (-1, float('nan'), '10', True):
            changed = copy.deepcopy(record); changed['windows']['available_memory_mib'] = value
            self.assertTrue(measurement_blockers(changed))
        record['wsl']['memory_available_mib'] = record['wsl']['memory_total_mib'] + 1
        self.assertTrue(measurement_blockers(record))


if __name__ == '__main__':
    unittest.main()
