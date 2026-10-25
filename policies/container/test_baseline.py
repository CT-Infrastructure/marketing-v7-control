"""Constructed, offline F06 tests; no container runtime, network or site data."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
import validate as v

ROOT=Path(__file__).resolve().parents[2]

def fixture():
    # Deliberately fictitious digest/identities. Never pull or deploy this fixture.
    return dict(schema_version='1.0',component_id='synthetic-app',
        image='fixture.example.invalid/synthetic-app@sha256:'+'a'*64,rootless=True,
        process=dict(uid=10001,gid=10001),
        filesystem=dict(read_only=True,read_only_tmpfs=False,mounts=[dict(type='named_volume',name='synthetic-state',target='/var/lib/synthetic',uid=10001,gid=10001,mode='0700',backup_ref='synthetic-backup',restore_ref='synthetic-held-restore')],tmpfs=[dict(target='/tmp',size_mib=64,noexec=True,nosuid=True,nodev=True)]),
        isolation=dict(privileged=False,network='none',pid='private',ipc='private',capabilities=[],no_new_privileges=True,seccomp='runtime-default',lsm='host-enforcing-default',devices=[],sockets=[]),
        resources=dict(memory_mib=512,cpu_percent=100,pids=128,disk_mib=512,runtime_seconds=3600),
        lifecycle=dict(restart='no',restart_seconds=10,start_seconds=180,stop_seconds=60,start_limit_interval_seconds=300,start_limit_burst=3,health=dict(argv=['/app/synthetic-health'],interval_seconds=30,timeout_seconds=5,retries=3,start_seconds=30),readiness_ref='synthetic-readiness',drain_ref='synthetic-drain',rollback_ref='synthetic-rollback'),
        dependencies=[],secret_refs=[],environment={'OUTBOUND_EFFECTS':'HOLD'},external_effects='disabled')

def quadlet():
    text=(ROOT/'deploy/base/app.container.in').read_text(encoding='utf-8-sig')
    substitutions={'UNRESOLVED_COMPONENT_HELD':'synthetic held','UNRESOLVED_REGISTRY':'fixture.example.invalid','UNRESOLVED_IMAGE':'synthetic-app','UNRESOLVED_DIGEST':'a'*64,'UNRESOLVED_COMPONENT':'synthetic-app','UNRESOLVED_UID':'10001','UNRESOLVED_GID':'10001','UNRESOLVED_HEALTH_EXECUTABLE':'synthetic-health'}
    for a,b in substitutions.items():
        text=text.replace(a,b)
    return text

class BaselineTests(unittest.TestCase):
    def reject(self,m):
        with self.assertRaises((v.PolicyError,TypeError)):
            v.validate_manifest(m)
    def changed(self,group,key,value):
        m=fixture()
        if group:
            m[group][key]=value
        else:
            m[key]=value
        self.reject(m)
    def test_constructed_manifest_is_policy_valid_not_qualified(self):
        r=v.validate_manifest(fixture())
        self.assertTrue(r['valid']); self.assertFalse(r['launch_authorized']); self.assertEqual(r['qualification'],'NOT_RUN')
    def test_unknown_and_missing_fields_rejected_at_every_group(self):
        for group in (None,'process','filesystem','isolation','resources','lifecycle'):
            for mode in ('extra','missing'):
                m=fixture(); obj=m if group is None else m[group]
                if mode=='extra': obj['extra']='unsafe'
                else: del obj[next(iter(obj))]
                self.reject(m)
    def test_mutable_or_unresolved_image_rejected(self):
        for image in ('app:latest','registry/app','UNRESOLVED','fixture.example.invalid/app@sha256:abc','fixture.example.invalid/app@sha256:'+'A'*64):
            self.changed(None,'image',image)
    def test_root_and_bool_uid_rejected(self):
        for key in ('uid','gid'):
            for value in (0,-1,True,'10001',None): self.changed('process',key,value)
        for value in (False,1,'true'): self.changed(None,'rootless',value)
    def test_privilege_namespace_seccomp_and_lsm_escape_rejected(self):
        for key,value in [('privileged',True),('no_new_privileges',False),('network','host'),('network','bridge'),('pid','host'),('ipc','host'),('capabilities',['CAP_SYS_ADMIN']),('seccomp','unconfined'),('lsm','disabled'),('devices',['/dev/kvm']),('sockets',['/run/podman/podman.sock'])]:
            self.changed('isolation',key,value)
    def test_raw_environment_and_external_effects_rejected(self):
        self.changed(None,'environment',{'OUTBOUND_EFFECTS':'HOLD','TOKEN':'synthetic-forbidden'})
        self.changed(None,'environment',{'OUTBOUND_EFFECTS':'ENABLE'})
        self.changed(None,'external_effects','enabled')
    def test_read_write_root_rejected(self): self.changed('filesystem','read_only',False)
    def test_host_and_traversal_mounts_rejected(self):
        for value in ('bind','host_socket'):
            m=fixture(); m['filesystem']['mounts'][0]['type']=value; self.reject(m)
        for target in ('/','/home','/run/podman/podman.sock','/var/lib/../../run','/var/lib//app','/proc','/dev','/sys'):
            m=fixture(); m['filesystem']['mounts'][0]['target']=target; self.reject(m)
    def test_volume_ownership_permissions_and_missing_recovery_rejected(self):
        for key,value in [('uid',0),('gid',1),('mode','0777'),('backup_ref',''),('restore_ref',''),('name','../../state')]:
            m=fixture(); m['filesystem']['mounts'][0][key]=value; self.reject(m)
    def test_overlapping_or_duplicate_mounts_rejected(self):
        for target in ('/var/lib/synthetic','/var/lib/synthetic/child'):
            m=fixture(); extra=copy.deepcopy(m['filesystem']['mounts'][0]); extra['target']=target; m['filesystem']['mounts'].append(extra); self.reject(m)
    def test_tmpfs_hardening_and_memory_budget_rejected(self):
        for key,value in [('target','/run'),('noexec',False),('nosuid',False),('nodev',False),('size_mib',0),('size_mib',True),('size_mib',257)]:
            m=fixture(); m['filesystem']['tmpfs'][0][key]=value; self.reject(m)
        m=fixture(); m['resources']['memory_mib']=16; self.reject(m)
    def test_limits_are_positive_typed_and_bounded(self):
        for key in fixture()['resources']:
            for value in (0,-1,True,'100',None,10000000): self.changed('resources',key,value)
    def test_bounded_restart_and_lifecycle_required(self):
        self.changed('lifecycle','restart','always')
        for key in ('start_seconds','stop_seconds','start_limit_burst','start_limit_interval_seconds','restart_seconds'):
            self.changed('lifecycle',key,0)
        for key in ('readiness_ref','drain_ref','rollback_ref'): self.changed('lifecycle',key,'')
    def test_health_shell_or_infinite_checks_rejected(self):
        for argv in ([],['/bin/sh','-c','echo'],['/app/health;curl'],['/app/../bin/sh']):
            m=fixture(); m['lifecycle']['health']['argv']=argv; self.reject(m)
        m=fixture(); m['lifecycle']['health']['timeout_seconds']=30; self.reject(m)
    def test_dependencies_and_secrets_are_references(self):
        for deps in (['synthetic-app'],['one','one'],['../../state']): self.changed(None,'dependencies',deps)
        self.changed(None,'secret_refs',['token=value'])
    def test_unresolved_nested_reference_rejected(self):
        self.changed('lifecycle','readiness_ref','UNRESOLVED_READINESS')

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'x.json'; p.write_text('{"rootless":true,"rootless":false}')
            with self.assertRaises(v.PolicyError): v.load_json(p)
    def test_inert_template_is_rejected(self):
        with self.assertRaises(v.PolicyError): v.validate_quadlet((ROOT/'deploy/base/app.container.in').read_text(encoding='utf-8-sig'))
    def test_synthetic_quadlet_policy_not_generator_qualification(self):
        r=v.validate_quadlet(quadlet()); self.assertTrue(r['valid']); self.assertEqual(r['installed_generator'],'NOT_RUN'); self.assertFalse(r['launch_authorized'])
    def test_unknown_duplicate_and_bypass_quadlet_keys_rejected(self):
        for line in ('PodmanArgs=--privileged','Volume=/run/podman/podman.sock:/run/podman/podman.sock','SecurityLabelDisable=true','User=0','Network=host','NewUnknownOption=true'):
            with self.assertRaises(v.PolicyError): v.validate_quadlet(quadlet().replace('[Service]',line+'\n[Service]'))
        with self.assertRaises(v.PolicyError): v.validate_quadlet(quadlet()+'\n[Install]\nWantedBy=default.target\n')
    def test_quadlet_hardening_mutations_rejected(self):
        for before,after in [('ReadOnly=true','ReadOnly=false'),('NoNewPrivileges=true','NoNewPrivileges=false'),('Network=none','Network=host'),('User=10001:10001','User=0:0'),('DropCapability=all','DropCapability=none'),('Restart=no','Restart=always'),('TasksMax=128','TasksMax=infinity'),('MemoryMax=512M','MemoryMax=infinity'),('HealthTimeout=5s','HealthTimeout=0'),('RuntimeMaxSec=3600','RuntimeMaxSec=infinity'),('Environment=OUTBOUND_EFFECTS=HOLD','Environment=OUTBOUND_EFFECTS=ENABLE')]:
            with self.assertRaises(v.PolicyError): v.validate_quadlet(quadlet().replace(before,after))
    def test_native_exceptions_are_placement_not_approval(self):
        doc=json.loads((ROOT/'policies/container/native-exceptions.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(doc['qualification'],'NOT_RUN')
        self.assertFalse(doc['container_privilege_exception'])
        self.assertEqual(len(doc['placements']),5)
        for row in doc['placements']:
            self.assertFalse(row['deployment_authorized'])
            self.assertTrue(row['required_evidence'])

    def check_image_in_both_formats(self, reference, valid):
        m = fixture()
        old = m['image']
        m['image'] = reference
        source = quadlet().replace(old, reference)
        if valid:
            manifest_result = v.validate_manifest(m)
            quadlet_result = v.validate_quadlet(source)
            self.assertFalse(manifest_result['launch_authorized'])
            self.assertEqual(manifest_result['qualification'], 'NOT_RUN')
            self.assertFalse(quadlet_result['launch_authorized'])
            self.assertEqual(quadlet_result['installed_generator'], 'NOT_RUN')
        else:
            with self.assertRaises(v.PolicyError):
                v.validate_manifest(m)
            with self.assertRaises(v.PolicyError):
                v.validate_quadlet(source)

    def test_image_repository_and_registry_adversarial_cases(self):
        for repository in ('/app', 'a//b', 'a/../b', 'a/./b', 'a/',
                           '.', '..', '...', '-app', 'app-', '_app',
                           'app_', 'a..b', 'a___b', 'a.-b', 'A'):
            with self.subTest(repository=repository):
                self.check_image_in_both_formats(
                    'fixture.example.invalid/' + repository + '@sha256:' + 'a'*64, False)
        for registry in ('.', '..', '.invalid', 'invalid.', 'a..invalid',
                         '-a.invalid', 'a-.invalid', 'a_b.invalid',
                         'a'*64 + '.invalid', 'fixture.invalid:',
                         'fixture.invalid:0', 'fixture.invalid:65536',
                         'fixture.invalid:999999', 'fixture.invalid:abc'):
            with self.subTest(registry=registry):
                self.check_image_in_both_formats(
                    registry + '/app@sha256:' + 'a'*64, False)

    def test_supported_pinned_image_controls(self):
        for registry in ('fixture.example.invalid', 'localhost', 'r-1.invalid:5000',
                         'fixture.invalid:1', 'fixture.invalid:65535'):
            for repository in ('app', 'team/app', 'team/app.v1',
                               'team/app_v1', 'team/app__v1', 'team/app---v1'):
                with self.subTest(registry=registry, repository=repository):
                    self.check_image_in_both_formats(
                        registry + '/' + repository + '@sha256:' + 'a'*64, True)

    def test_quadlet_identity_bounds_match_manifest(self):
        for key in ('uid', 'gid'):
            for value in (0, -1, 2147483648, 4294967296, 999999999999999999999):
                with self.subTest(key=key, value=value):
                    self.changed('process', key, value)
                    identity = [10001, 10001]
                    identity[0 if key == 'uid' else 1] = value
                    source = quadlet().replace('User=10001:10001',
                                               'User=%s:%s' % tuple(identity))
                    with self.assertRaises(v.PolicyError):
                        v.validate_quadlet(source)
        for value in (1, 2147483647):
            m = fixture()
            m['process'] = dict(uid=value, gid=value)
            m['filesystem']['mounts'][0].update(uid=value, gid=value)
            self.assertFalse(v.validate_manifest(m)['launch_authorized'])
            source = quadlet().replace('User=10001:10001',
                                       'User=%s:%s' % (value, value))
            self.assertFalse(v.validate_quadlet(source)['launch_authorized'])
    def test_implicit_writable_tmpfs_rejected(self):
        self.changed('filesystem','read_only_tmpfs',True)
        self.changed('filesystem','read_only_tmpfs',None)
        for source in (quadlet().replace('ReadOnlyTmpfs=false','ReadOnlyTmpfs=true'),
                       quadlet().replace('ReadOnlyTmpfs=false\n','')):
            with self.assertRaises(v.PolicyError):v.validate_quadlet(source)

    def test_json_exec_health_only(self):
        for command in ('/app/synthetic-health', '"/app/synthetic-health"',
                        '["CMD-SHELL", "/app/synthetic-health"]',
                        '["/bin/sh", "-c", "true"]', '["/app/synthetic-health", "extra"]',
                        '[]', '{"cmd":"/app/synthetic-health"}'):
            source=quadlet().replace('["/app/synthetic-health"]',command)
            with self.subTest(command=command),self.assertRaises(v.PolicyError):v.validate_quadlet(source)
        self.assertTrue(v.validate_quadlet(quadlet())['valid'])

    def test_runtime_timeout_cannot_restart_forever(self):
        for restart in ('on-failure','always','on-abnormal','on-watchdog'):
            self.changed('lifecycle','restart',restart)
            with self.subTest(restart=restart),self.assertRaises(v.PolicyError):
                v.validate_quadlet(quadlet().replace('Restart=no','Restart='+restart))

    def test_unqualified_registry_rejected_by_both_entrypoints(self):
        for host in ('team','registry','docker','example'):
            with self.subTest(host=host):
                self.check_image_in_both_formats(host+'/app@sha256:'+'a'*64,False)
        for host in ('localhost','localhost:5000','registry:5000','registry.example'):
            with self.subTest(host=host):
                self.check_image_in_both_formats(host+'/app@sha256:'+'a'*64,True)

    def test_nonphysical_separator_smuggling_rejected(self):
        for separator in ('\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029','\r'):
            source=quadlet().replace('Network=none','#'+separator+'Network=none')
            with self.subTest(separator=repr(separator)),self.assertRaises(v.PolicyError):v.validate_quadlet(source)
        self.assertTrue(v.validate_quadlet(quadlet().replace('\n','\r\n'))['valid'])
        self.assertTrue(v.validate_quadlet(quadlet().replace('Network=none','\tNetwork=none'))['valid'])

    def test_cli_preserves_raw_separators(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'synthetic.container'
            for separator in ('\r','\v','\f','\x85','\u2028','\u2029'):
                source=quadlet().replace('Network=none','#'+separator+'Network=none')
                path.write_bytes(source.encode('utf-8'))
                self.assertEqual(v.load_quadlet(path),source)
                result=subprocess.run([sys.executable,'-B',str(ROOT/'policies/container/validate.py'),'--quadlet',str(path)],capture_output=True,text=True,timeout=15)
                with self.subTest(separator=repr(separator)):
                    self.assertEqual(result.returncode,2,result.stdout)
                    self.assertFalse(json.loads(result.stdout)['valid'])
            path.write_bytes(quadlet().replace('\n','\r\n').encode('utf-8'))
            self.assertIn('\r\n',v.load_quadlet(path))
            result=subprocess.run([sys.executable,'-B',str(ROOT/'policies/container/validate.py'),'--quadlet',str(path)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout)

if __name__=='__main__': unittest.main(verbosity=2)
