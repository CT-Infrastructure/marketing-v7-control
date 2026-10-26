"""Regression checks on an observed generator snapshot, never service execution."""
import configparser
from pathlib import Path
import shlex
import unittest

class ObservedGeneratorTests(unittest.TestCase):
    def setUp(self):
        text=(Path(__file__).parent/'fixtures/quadlet-4.9.3.service.txt').read_text(encoding='utf-8')
        self.assertTrue(text.startswith('---synthetic.service---'))
        self.config=configparser.ConfigParser(interpolation=None,strict=True)
        self.config.optionxform=str
        self.config.read_string(text.split('\n',1)[1])
        self.argv=shlex.split(self.config['Service']['ExecStart'])
    def test_observed_command_has_expected_hardening(self):
        for item in ('--network=none','--security-opt=no-new-privileges','--cap-drop=all','--read-only','--read-only-tmpfs=false','--image-volume=ignore','--cgroups=split'):
            self.assertIn(item,self.argv)
        for flag,value in (('--user','10001:10001'),('--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m'),('--env','OUTBOUND_EFFECTS=HOLD')):
            self.assertEqual(self.argv[self.argv.index(flag)+1],value)
        self.assertEqual(self.argv.count('--image-volume=ignore'),1)
        self.assertFalse(any(arg.startswith('--image-volume') and arg!='--image-volume=ignore' for arg in self.argv))
        self.assertEqual(self.argv[-1],'fixture.example.invalid/synthetic-app@sha256:'+'a'*64)
    def test_observed_command_has_no_host_escape_flags(self):
        for item in self.argv:
            self.assertFalse(item in ('--privileged','--volume','-v','--mount') or 'unconfined' in item or '=host' in item)
        self.assertNotIn('User',self.config['Service'])
        self.assertNotIn('Install',self.config.sections())
    def test_observed_resource_lifecycle_and_health_settings(self):
        service=self.config['Service']
        for key,value in {'Restart':'no','RestartSec':'10','TimeoutStartSec':'180','TimeoutStopSec':'60','MemoryMax':'512M','CPUQuota':'100%','TasksMax':'128','RuntimeMaxSec':'3600','Delegate':'yes'}.items():
            self.assertEqual(service[key],value)
        for key,value in {'StartLimitIntervalSec':'300','StartLimitBurst':'3'}.items():
            self.assertEqual(self.config['Unit'][key],value)
        for flag,value in (('--health-cmd','["/app/synthetic-health"]'),('--health-interval','30s'),('--health-timeout','5s'),('--health-retries','3'),('--health-start-period','30s')):
            self.assertEqual(self.argv[self.argv.index(flag)+1],value)

if __name__=='__main__': unittest.main(verbosity=2)

