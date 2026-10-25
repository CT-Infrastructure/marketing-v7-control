"""Offline synthetic checks. Scanner fixtures are not scanner execution evidence."""
import copy
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
from jsonschema import ValidationError,Draft202012Validator
import validate as lock

NOW='2026-10-25T12:30:00Z'
class SupplyChain(unittest.TestCase):
    def manifest(self):return json.loads((lock.ROOT/'locks/supply-chain.lock.json').read_text())
    def entry(self):return json.loads((Path(__file__).parent/'fixtures/synthetic-entry.json').read_text())
    def candidate(self):
        m=self.manifest();m['entries']=[self.entry() if e['id']=='CP033' else e for e in m['entries']];return m
    def exception(self):return {'id':'synthetic-exception','entry_id':'CP033','subject_digest':self.entry()['digest'],'scanner_kind':'vulnerability','finding_id':'synthetic-finding','owner_ref':'synthetic-owner','independent_reviewer_ref':'synthetic-reviewer','issued_at':'2026-10-25T12:00:00Z','expires_at':'2026-10-26T12:00:00Z','reason':'Synthetic fixture only','compensating_controls':['synthetic network deny'],'evidence_ref':'synthetic-evidence','approval_ref':'synthetic-approval','status':'APPROVED'}
    def test_schemas(self):
        for name in ('lock-manifest','exceptions'):Draft202012Validator.check_schema(json.loads((lock.HERE/(name+'.schema.json')).read_text()))
    def test_inventory_all_held_and_no_scans_claimed(self):
        m=lock.validate_manifest(self.manifest());self.assertEqual(len(m['entries']),149)
        for e in m['entries']:
            self.assertTrue(lock.adoption_blockers(e,NOW))
            self.assertTrue(all(s['status']=='NOT_RUN' for s in e['scans']))
    def test_engineering_observations_exact_and_not_adoptable(self):
        entries={e['id']:e for e in self.manifest()['entries']}
        self.assertEqual(entries['engineering-checkout']['release'],'3d3c42e5aac5ba805825da76410c181273ba90b1')
        self.assertEqual(entries['engineering-codex']['digest']['value'],'6f267830b029ee25d9339864aa867cd45de9f8fd4c5ea007d2e63c13a0c66d36')
        for key in ('engineering-checkout','engineering-codex'):
            self.assertIn('engineering_or_synthetic_only',lock.adoption_blockers(entries[key],NOW))
    def test_synthetic_complete_candidate_has_no_structural_blockers(self):
        lock.validate_manifest(self.candidate());self.assertEqual(lock.adoption_blockers(self.entry(),NOW),[])
    def test_negative_fixture_mutations(self):
        mutations=json.loads((lock.HERE/'fixtures/negative-mutations.json').read_text())
        for case in mutations:
            with self.subTest(case=case['id']):
                m=self.candidate();e=next(e for e in m['entries'] if e['id']=='CP033');target=e
                for p in case['path'][:-1]:target=target[p]
                target[case['path'][-1]]=case['value']
                try:lock.validate_manifest(m)
                except (ValueError,ValidationError):continue
                self.assertTrue(lock.adoption_blockers(e,NOW))
    def test_registry_drift_missing_duplicate_and_unknown(self):
        for kind in ('name','classification','missing','duplicate','unknown','hash'):
            with self.subTest(kind=kind):
                m=self.manifest()
                if kind=='name':m['entries'][0]['name']='Invented'
                if kind=='classification':m['entries'][0]['source_classification']='CONDITIONAL_NOT_INSTALLED'
                if kind=='missing':m['entries'].pop(0)
                if kind=='duplicate':m['entries'].append(copy.deepcopy(m['entries'][0]))
                if kind=='unknown':m['entries'][0]['component_id']='CP999'
                if kind=='hash':m['source_registry_sha256']='a'*64
                with self.assertRaises((ValueError,ValidationError)):lock.validate_manifest(m)
    def test_registry_lf_and_crlf_materializations(self):
        source=lock.REGISTRY.read_bytes().replace(b'\r\n',b'\n')
        for raw in (source,source.replace(b'\n',b'\r\n')):
            with self.subTest(crlf=b'\r\n' in raw),tempfile.TemporaryDirectory() as directory:
                registry=Path(directory)/'component_registry.json';registry.write_bytes(raw)
                with patch.object(lock,'REGISTRY',registry):
                    self.assertEqual(lock.registry_source_bytes(),source)
                    self.assertEqual(len(lock.validate_manifest(self.manifest())['entries']),149)

    def test_registry_rejects_other_transformations(self):
        source=lock.REGISTRY.read_bytes().replace(b'\r\n',b'\n')
        mutations={'content':source.replace(b'CP001',b'CP999',1),
                   'whitespace':b' '+source,
                   'bom':b'\xef\xbb\xbf'+source,
                   'lone CR':source.replace(b'\n',b'\r'),
                   'mixed endings':source.replace(b'\n',b'\r\n',1),
                   'missing final newline':source.rstrip(b'\n')}
        for name,raw in mutations.items():
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                registry=Path(directory)/'component_registry.json';registry.write_bytes(raw)
                with patch.object(lock,'REGISTRY',registry),self.assertRaises(ValueError):
                    lock.validate_manifest(self.manifest())

    def test_conditional_never_promoted(self):
        m=self.manifest();next(e for e in m['entries'] if e['source_classification']=='CONDITIONAL_NOT_INSTALLED')['state']='CANDIDATE'
        with self.assertRaises(ValueError):lock.validate_manifest(m)
    def test_actions_and_nodes_require_full_commit(self):
        for kind,release in [('ACTION','v7'),('COMFY_NODE','main'),('ACTION','a'*39),('ACTION','a'*40+'\n')]:
            m=self.candidate();e=next(e for e in m['entries'] if e['id']=='CP033');e.update(artifact_type=kind,release=release)
            with self.subTest(kind=kind,release=release),self.assertRaises(ValueError):lock.validate_manifest(m)
    def test_oci_requires_digest_and_no_floating_tag(self):
        for release in ('latest','registry/repo:latest','LATEST','stable','^1.2','1.*'):
            m=self.candidate();next(e for e in m['entries'] if e['id']=='CP033').update(artifact_type='OCI',release=release)
            with self.subTest(release=release),self.assertRaises(ValueError):lock.validate_manifest(m)
    def test_duplicate_scan_kind_and_false_pass(self):
        m=self.candidate();e=next(e for e in m['entries'] if e['id']=='CP033');e['scans'][1]['kind']='vulnerability'
        with self.assertRaises(ValueError):lock.validate_manifest(m)
        m=self.candidate();e=next(e for e in m['entries'] if e['id']=='CP033');e['scans'][0]['findings']=['finding']
        with self.assertRaises(ValueError):lock.validate_manifest(m)
    def test_dependency_missing_and_cycle(self):
        for deps in (['unknown'],['CP033']):
            m=self.candidate();next(e for e in m['entries'] if e['id']=='CP033')['dependencies']=deps
            with self.assertRaises(ValueError):lock.validate_manifest(m)
    def test_future_stale_and_subject_mismatch_scans_block(self):
        for field,value in [('scanned_at','2026-10-26T12:00:00Z'),('scanned_at','2026-10-20T12:00:00Z'),('subject_digest',{'algorithm':'sha256','value':'b'*64})]:
            e=self.entry();e['scans'][0][field]=value
            self.assertTrue(lock.adoption_blockers(e,NOW))
    def test_model_rights_required(self):
        e=self.entry();e['artifact_type']='MODEL'
        self.assertIn('model_rights_UNSET',lock.adoption_blockers(e,NOW))
    def test_exception_exact_scope_and_expiry(self):
        m=self.candidate();e=next(e for e in m['entries'] if e['id']=='CP033');e['scans'][0].update(status='FAIL',findings=['synthetic-finding'])
        ex=self.exception();lock.validate_exceptions({'schema_version':'1.0','exceptions':[ex]},m,NOW)
        self.assertEqual(lock.adoption_blockers(e,NOW,[ex]),[])
        for key,value in [('expires_at',NOW),('issued_at','2026-10-26T12:00:00Z'),('expires_at','2027-01-01T12:00:00Z'),('owner_ref','synthetic-reviewer'),('entry_id','CP034'),('finding_id','another-finding'),('evidence_ref','UNSET'),('scanner_kind','secret'),('compensating_controls',['UNSET']),('compensating_controls',[' '])]:
            bad=dict(ex,**{key:value})
            with self.subTest(key=key),self.assertRaises((ValueError,ValidationError)):lock.validate_exceptions({'schema_version':'1.0','exceptions':[bad]},m,NOW)
    def test_exception_not_global_bypass_or_secret_waiver(self):
        e=self.entry();e['scans'][0].update(status='FAIL',findings=['synthetic-finding']);e['scans'][1].update(status='FAIL',findings=['synthetic-finding'])
        self.assertIn('secret_finding:synthetic-finding',lock.adoption_blockers(e,NOW,[self.exception()]))
        e=self.entry();e['scans'][0].update(status='NOT_RUN');e['license']['expression']='UNSET'
        blockers=lock.adoption_blockers(e,NOW);self.assertIn('license_UNSET',blockers);self.assertIn('vulnerability_NOT_RUN',blockers)
    def test_preview_and_unknown_fields_fail_closed(self):
        for key,value in [('workflow_lockfile_preview','ENABLED'),('unexpected',True)]:
            m=self.manifest();m[key]=value
            with self.assertRaises(ValidationError):lock.validate_manifest(m)
    def test_diagnostics_revalidate_exception_authority_fields(self):
        e=self.entry();e['scans'][0].update(status='FAIL',findings=['synthetic-finding'])
        for key,value in [('evidence_ref','UNSET'),('owner_ref','synthetic-reviewer'),('expires_at','2026-10-25T12:30:00Z')]:
            bad=dict(self.exception(),**{key:value})
            with self.subTest(key=key),self.assertRaises(ValueError):lock.adoption_blockers(e,NOW,[bad])
    def test_scanner_and_rights_disposition_unset_block(self):
        e=self.entry();e['scans'][0]['tool_release']='latest';e['model_rights']['evidence_ref']='UNSET'
        blockers=lock.adoption_blockers(e,NOW)
        self.assertIn('vulnerability_scanner_release_unpinned',blockers)
        self.assertIn('rights_disposition_UNSET',blockers)
    def test_invalid_calendar_exception(self):
        m=self.candidate();ex=self.exception();ex['issued_at']='2026-02-30T12:00:00Z'
        with self.assertRaises((ValueError,ValidationError)):lock.validate_exceptions({'schema_version':'1.0','exceptions':[ex]},m,NOW)

    def assert_rejected_at_both_entry_boundaries(self, entry):
        manifest=self.manifest()
        manifest['entries']=[entry if e['id']=='CP033' else e for e in manifest['entries']]
        with self.assertRaises((ValueError,ValidationError)):
            lock.validate_manifest(manifest)
        with self.assertRaises((ValueError,ValidationError)):
            lock.adoption_blockers(entry,NOW)

    def test_public_diagnostics_share_scan_and_commit_invariants(self):
        for mutation in ('duplicate','empty_fail','false_pass','not_run_findings',
                         'moving_action','mismatched_action','mismatched_node'):
            e=self.entry()
            if mutation=='duplicate':e['scans'][1]=copy.deepcopy(e['scans'][0])
            if mutation=='empty_fail':e['scans'][1]['status']='FAIL'
            if mutation=='false_pass':e['scans'][0]['findings']=['synthetic-finding']
            if mutation=='not_run_findings':
                e['scans'][0].update(status='NOT_RUN',findings=['synthetic-finding'])
            if mutation=='moving_action':e.update(artifact_type='ACTION',release='main')
            if mutation in ('mismatched_action','mismatched_node'):
                e.update(artifact_type='ACTION' if mutation=='mismatched_action' else 'COMFY_NODE',
                         release='a'*40)
            with self.subTest(mutation=mutation):
                self.assert_rejected_at_both_entry_boundaries(e)

    def test_nonblank_evidence_and_identity_at_both_entry_boundaries(self):
        paths=[('id',),('origin',),('release',),('architecture',),('review_ref',),
               ('rollback_ref',),('license','expression'),('license','evidence_ref'),
               ('model_rights','evidence_ref'),('provenance','source_ref'),
               ('provenance','attestation_ref'),('provenance','issuer_ref'),
               ('sbom','document_ref')]
        paths += [('scans',i,key) for i in (0,1)
                  for key in ('tool','tool_release','report_ref')]
        paths += [('scans',0,'findings',0)]
        for path in paths:
            for blank in (' ', '\t\r\n', '\u2003'):
                e=self.entry()
                if path==('scans',0,'findings',0):
                    e['scans'][0].update(status='FAIL',findings=['synthetic-finding'])
                target=e
                for key in path[:-1]:target=target[key]
                target[path[-1]]=blank
                with self.subTest(path=path,blank=repr(blank)):
                    self.assert_rejected_at_both_entry_boundaries(e)

    def test_exception_finding_requires_exact_failed_scan_subject(self):
        for mismatch in ('value','algorithm','not_run','pass'):
            e=self.entry()
            e['scans'][0].update(status='FAIL',findings=['synthetic-finding'])
            if mismatch=='value':
                e['scans'][0]['subject_digest']={'algorithm':'sha256','value':'e'*64}
            if mismatch=='algorithm':
                e['scans'][0]['subject_digest']={'algorithm':'git-sha1','value':'a'*40}
            if mismatch in ('not_run','pass'):
                e['scans'][0].update(status='NOT_RUN' if mismatch=='not_run' else 'PASS',
                                     findings=[])
            m=self.manifest()
            m['entries']=[e if item['id']=='CP033' else item for item in m['entries']]
            lock.validate_manifest(m)
            with self.subTest(mismatch=mismatch):
                with self.assertRaises((ValueError,ValidationError)):
                    lock.validate_exceptions({'schema_version':'1.0','exceptions':[self.exception()]},m,NOW)
                with self.assertRaises((ValueError,ValidationError)):
                    lock.adoption_blockers(e,NOW,[self.exception()])

    def test_exact_native_package_versions_and_ranges(self):
        for version in ('1.2.3~rc1-1','2:1.2.3~deb12u1-1','1.2.3-4+deb12u2'):
            e=self.entry();e.update(artifact_type='OS_PACKAGE',release=version)
            m=self.manifest();m['entries']=[e if x['id']==e['id'] else x for x in m['entries']]
            with self.subTest(version=version):
                lock.validate_manifest(m)
                self.assertEqual(lock.adoption_blockers(e,NOW),[])
        for kind,version in (('OS_PACKAGE','~1.2'),('OS_PACKAGE','^1.2'),
                             ('OS_PACKAGE','1.*'),('OS_PACKAGE','>=1.2'),
                             ('OS_PACKAGE','1.2 || 2.0'),('OS_PACKAGE','UNSET'),
                             ('APPLICATION','1.2.3~rc1-1')):
            e=self.entry();e.update(artifact_type=kind,release=version)
            with self.subTest(kind=kind,version=version):
                if version=='UNSET':self.assertIn('release_UNSET',lock.adoption_blockers(e,NOW))
                else:self.assert_rejected_at_both_entry_boundaries(e)

    def test_shared_exceptions_are_scoped_and_current_bindings_checked(self):
        first=self.entry();first['scans'][0].update(status='FAIL',findings=['synthetic-finding'])
        second=copy.deepcopy(first);second['id']='CP034'
        ex1=self.exception();ex2=dict(ex1,id='other-exception',entry_id='CP034')
        document={'schema_version':'1.0','exceptions':[ex1,ex2]}
        lock.validate_exceptions(document,{'entries':[first,second]},NOW)
        self.assertEqual(lock.adoption_blockers(first,NOW,[ex1,ex2]),[])
        self.assertEqual(lock.adoption_blockers(second,NOW,[ex1,ex2]),[])
        for field,value in (('subject_digest',{'algorithm':'sha256','value':'e'*64}),
                            ('finding_id','not-observed'),('evidence_ref','UNSET'),
                            ('expires_at',NOW)):
            with self.subTest(field=field),self.assertRaises((ValueError,ValidationError)):
                lock.adoption_blockers(first,NOW,[dict(ex1,**{field:value}),ex2])
        malformed=dict(ex1);malformed.pop('entry_id')
        with self.assertRaises(ValidationError):lock.adoption_blockers(first,NOW,[malformed,ex2])
        unknown=dict(ex1,entry_id='unknown-entry')
        with self.assertRaises(ValueError):
            lock.validate_exceptions({'schema_version':'1.0','exceptions':[unknown]},
                                     {'entries':[first,second]},NOW)

    def test_qualified_latest_scanner_releases_stay_held(self):
        for version in ('registry/trivy:latest','registry/trivy:LATEST','latest','trivy/latest'):
            e=self.entry();e['scans'][0]['tool_release']=version
            with self.subTest(version=version):
                self.assertIn('vulnerability_scanner_release_unpinned',lock.adoption_blockers(e,NOW))
        e=self.entry();e['scans'][0]['tool_release']='registry/trivy:0.67.2'
        self.assertNotIn('vulnerability_scanner_release_unpinned',lock.adoption_blockers(e,NOW))

    def test_cli_uses_one_current_utc_instant_for_all_checks(self):
        import io
        from contextlib import redirect_stdout
        from datetime import datetime,timezone
        instant=datetime(2026,11,4,18,12,30,tzinfo=timezone.utc)
        manifest=self.manifest()
        with patch.object(lock,'datetime') as clock, \
             patch.object(lock,'validate_manifest',return_value=manifest), \
             patch.object(lock,'validate_exceptions') as exceptions, \
             patch.object(lock,'adoption_blockers',return_value=['held']) as blockers, \
             redirect_stdout(io.StringIO()):
            clock.now.return_value=instant
            lock.main()
            clock.now.assert_called_once_with(timezone.utc)
            self.assertEqual(exceptions.call_args.args[2],'2026-11-04T18:12:30Z')
            self.assertEqual(blockers.call_count,len(manifest['entries']))
            self.assertTrue(all(call.args[1]=='2026-11-04T18:12:30Z' for call in blockers.call_args_list))
            self.assertIs(exceptions.call_args.args[1],manifest)

if __name__=='__main__':unittest.main(verbosity=2)
