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

    def test_non_package_wildcards_ranges_and_moving_terminal_tags(self):
        for value in ('1.x','1.X','v1.2.x','1.2||2.0','registry/repo:stable',
                      'registry/repo:main','registry/repo:nightly','registry/repo:1.x'):
            e=self.entry();e['release']=value
            with self.subTest(release=value):self.assert_rejected_at_both_entry_boundaries(e)

    def test_each_scanner_rejects_nonexact_releases_at_manifest_and_diagnostics(self):
        for index in (0,1):
            for value in ('1.x','v1.2.x','1.2||2.0','registry/trivy:stable',
                          'registry/trivy:main','main','registry/trivy:latest'):
                e=self.entry();e['scans'][index]['tool_release']=value
                m=self.manifest();m['entries']=[e if x['id']==e['id'] else x for x in m['entries']]
                with self.subTest(kind=e['scans'][index]['kind'],release=value):
                    with self.assertRaises(ValueError):lock.validate_manifest(m)
                    self.assertIn(e['scans'][index]['kind']+'_scanner_release_unpinned',
                                  lock.adoption_blockers(e,NOW))

    def test_exact_prerelease_and_sha_references_remain_valid(self):
        versions=('1.2.3-rc.1','v2.0.0-beta+build.7','registry/repo:1.2.3-rc.1',
                  'a'*40,'registry/repo@sha256:'+'a'*64)
        for value in versions:
            e=self.entry();e['release']=value
            for scan in e['scans']:scan['tool_release']=value
            m=self.manifest();m['entries']=[e if x['id']==e['id'] else x for x in m['entries']]
            with self.subTest(release=value):
                lock.validate_manifest(m)
                self.assertEqual(lock.adoption_blockers(e,NOW),[])

    def test_explicit_branch_namespaces_rejected_at_public_boundaries(self):
        values=('refs/heads/feature','refs/heads/release-1.0',
                'https://example.invalid/repo/refs/heads/feature',
                'refs/remotes/origin/release-1.0')
        for value in values:
            for kind in ('APPLICATION','OCI','TOOL','MODEL'):
                entry=self.entry();entry.update(artifact_type=kind,release=value)
                with self.subTest(kind=kind,release=value):
                    self.assert_rejected_at_both_entry_boundaries(entry)
            for index in (0,1):
                entry=self.entry();entry['scans'][index]['tool_release']=value
                manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
                with self.subTest(scanner=index,release=value):
                    with self.assertRaises(ValueError):lock.validate_manifest(manifest)
                    self.assertIn(entry['scans'][index]['kind']+'_scanner_release_unpinned',lock.adoption_blockers(entry,NOW))

    def test_digest_scanner_refs_require_exact_sha256_at_public_boundaries(self):
        bad=('registry/scanner@sha256:deadbeef','registry/scanner@sha256:release-1.0',
             'registry/scanner@sha256:'+'A'*64,'registry/scanner@sha256:'+'a'*63,
             'registry/scanner@sha512:'+'a'*64,'registry/scanner@sha256:'+'a'*65)
        for value in bad:
            for index in (0,1):
                entry=self.entry();entry['scans'][index]['tool_release']=value
                manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
                with self.subTest(scanner=index,value=value):
                    with self.assertRaises(ValueError):lock.validate_manifest(manifest)
                    self.assertIn(entry['scans'][index]['kind']+'_scanner_release_unpinned',lock.adoption_blockers(entry,NOW))
        entry=self.entry()
        for scan in entry['scans']:scan['tool_release']='registry/scanner@sha256:'+'a'*64
        manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
        lock.validate_manifest(manifest);self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_latest_repository_names_are_not_mutable_selectors(self):
        for origin in ('https://example.invalid/latest-version/repo',
                       'registry.invalid/latest-version/repo:1.2.3',
                       'registry.invalid/latest-version/repo@sha256:'+'a'*64,
                       'https://example.invalid/owner/latest-version'):
            entry=self.entry();entry.update(origin=origin,release='latest-version-1.2.3')
            manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
            with self.subTest(origin=origin):
                lock.validate_manifest(manifest);self.assertEqual(lock.adoption_blockers(entry,NOW),[])
        for origin in ('registry.invalid/latest-version/repo:latest',
                       'registry.invalid/repo@latest'):
            entry=self.entry();entry['origin']=origin
            with self.subTest(origin=origin):self.assert_rejected_at_both_entry_boundaries(entry)

    def test_digest_qualified_release_binds_exact_locked_subject(self):
        for kind in ('APPLICATION','OCI','TOOL','MODEL'):
            entry=self.entry();entry.update(artifact_type=kind,release='registry/repo@sha256:'+'b'*64)
            with self.subTest(kind=kind):self.assert_rejected_at_both_entry_boundaries(entry)
        entry=self.entry();entry['release']='registry/repo@sha256:'+'a'*64
        manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
        lock.validate_manifest(manifest);self.assertEqual(lock.adoption_blockers(entry,NOW),[])
        # Scanner tool identity is separate from the scanned subject identity.
        for scan in entry['scans']:scan['tool_release']='registry/scanner@sha256:'+'b'*64
        manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
        lock.validate_manifest(manifest);self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_explicit_origin_selectors_require_exact_pins(self):
        for selector in ('main','master','head','stable','nightly','latest','1.x','1.*'):
            for separator in (':','@'):
                entry=self.entry();entry['origin']='registry.invalid/repo'+separator+selector
                with self.subTest(selector=selector,separator=separator):
                    self.assert_rejected_at_both_entry_boundaries(entry)
        for origin in ('registry.invalid/latest-version:1.2.3',
                       'registry.invalid/repo@sha256:'+'a'*64,
                       'https://example.invalid/stable-tools/repository',
                       'git@example.invalid:owner/repository'):
            entry=self.entry();entry['origin']=origin
            if origin.startswith(('git@','ssh://')):entry['artifact_type']='APPLICATION'
            manifest=self.manifest();manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
            with self.subTest(origin=origin):
                lock.validate_manifest(manifest);self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_full_origin_branch_namespaces_rejected(self):
        for namespace in ('refs/heads/', 'refs/remotes/origin/',
                          'ReFs/HeAdS/', 'REFS/REMOTES/origin/'):
            for boundary in ('/', '@'):
                for kind in ('APPLICATION','OCI','TOOL','MODEL'):
                    entry=self.entry()
                    entry.update(artifact_type=kind,
                                 origin='https://example.invalid/repo'+boundary+namespace+'release-1.0')
                    with self.subTest(namespace=namespace,boundary=boundary,kind=kind):
                        self.assert_rejected_at_both_entry_boundaries(entry)

    def test_origin_digest_qualifiers_fail_closed(self):
        for qualifier in ('sha512:deadbeef','SHA256:'+'a'*64,'sha256:deadbeef',
                          'sha256:'+'A'*64,'sha256:'+'a'*63,
                          'sha256:'+'a'*65,'sha256:'+'g'*64,'sha256:'):
            for kind in ('APPLICATION','OCI','TOOL','MODEL'):
                entry=self.entry()
                entry.update(artifact_type=kind,origin='registry.invalid/repo@'+qualifier)
                with self.subTest(qualifier=qualifier,kind=kind):
                    self.assert_rejected_at_both_entry_boundaries(entry)

    def test_origin_digest_binds_locked_subject(self):
        for kind in ('APPLICATION','OCI','TOOL','MODEL'):
            entry=self.entry()
            entry.update(artifact_type=kind,origin='registry.invalid/repo@sha256:'+'b'*64)
            with self.subTest(kind=kind):
                self.assert_rejected_at_both_entry_boundaries(entry)

    def test_exact_origin_identity_positive_controls(self):
        origins=('registry.invalid/repo@sha256:'+'a'*64,
                 'https://example.invalid/repository',
                 'registry.invalid:5000/owner/repo',
                 'registry.invalid:5000/repo:1.2.3-rc.1',
                 'registry.invalid/repo@v2.0.0-beta+build.7',
                 'https://example.invalid/latest-version/stable-tools',
                 'git@example.invalid:owner/repository',
                 'git@example.invalid:repository',
                 'ssh://git@example.invalid:2222/owner/repository')
        for origin in origins:
            entry=self.entry();entry['origin']=origin
            if origin.startswith(('git@','ssh://')) or '@v2.0.0-beta+build.7' in origin:
                entry['artifact_type']='APPLICATION'
            for scan in entry['scans']:
                scan['tool_release']='registry/scanner@sha256:'+'b'*64
            manifest=self.manifest()
            manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
            with self.subTest(origin=origin):
                lock.validate_manifest(manifest)
                self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_short_origin_digest_qualifiers_cannot_be_scp_remotes(self):
        for qualifier in ('sha256:'+'b'*64, 'sha256:deadbeef',
                          'SHA256:'+'a'*64, 'sha512:deadbeef',
                          'sha256:'+'A'*64, 'sha256:'+'a'*63,
                          'sha256:'+'a'*65, 'sha256:'+'g'*64, 'sha256:'):
            for kind in ('APPLICATION','OCI','TOOL','MODEL'):
                entry=self.entry()
                entry.update(artifact_type=kind,origin='alpine@'+qualifier)
                with self.subTest(qualifier=qualifier,kind=kind):
                    with self.assertRaises(ValueError):lock.validate_entry(entry)
                    self.assert_rejected_at_both_entry_boundaries(entry)
        for kind in ('APPLICATION','OCI','TOOL','MODEL'):
            entry=self.entry()
            entry.update(artifact_type=kind,origin='alpine@sha256:'+'a'*64)
            if kind=='MODEL':entry['model_rights']['state']='REVIEWED'
            manifest=self.manifest()
            manifest['entries']=[entry if e['id']==entry['id'] else e for e in manifest['entries']]
            with self.subTest(matching_kind=kind):
                lock.validate_entry(entry)
                lock.validate_manifest(manifest)
                self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_scp_repository_branch_namespaces_rejected(self):
        for host in ('host','example.invalid'):
            for namespace in ('refs/heads/', 'refs/remotes/origin/',
                              'ReFs/HeAdS/', 'REFS/REMOTES/origin/'):
                entry=self.entry()
                entry.update(artifact_type='APPLICATION',origin='git@'+host+':'+namespace+'release-1.0')
                with self.subTest(host=host,namespace=namespace):
                    with self.assertRaises(ValueError):lock.validate_entry(entry)
                    self.assert_rejected_at_both_entry_boundaries(entry)


    def test_oci_origin_digest_table_at_entry_and_manifest(self):
        qualifiers=(('md5:deadbeef',False),('blake2:deadbeef',False),
                    ('blake:deadbeef',False),('arbitrary-algorithm:deadbeef',False),
                    ('sha256:'+'b'*64,False),('sha256:'+'a'*64,True),
                    ('sha256:deadbeef',False),('sha256:'+'A'*64,False),
                    ('sha256:'+'a'*63,False),('sha256:'+'a'*65,False))
        for repository in ('alpine','registry.invalid/owner/alpine',
                           'registry.invalid:5000/owner/alpine'):
            for qualifier,valid in qualifiers:
                entry=self.entry()
                entry.update(artifact_type='OCI',origin=repository+'@'+qualifier)
                manifest=self.manifest()
                manifest['entries']=[entry if e['id']==entry['id'] else e
                                     for e in manifest['entries']]
                for validator,value in ((lock.validate_entry,entry),
                                        (lock.validate_manifest,manifest)):
                    with self.subTest(origin=entry['origin'],validator=validator.__name__):
                        if valid:validator(value)
                        else:
                            with self.assertRaises(ValueError):validator(value)

    def test_git_transport_paths_at_entry_and_manifest(self):
        for kind,prefix in (('APPLICATION','git@host:'),
                            ('APPLICATION','git@example.invalid:'),
                            ('APPLICATION','ssh://git@example.invalid:2222/'),
                            ('APPLICATION','https://git@example.invalid/'),
                            ('ACTION','builder@host:')):
            for path,valid in (('owner/repository',True),('repository',True),
                               ('refs/heads/release-1.0',False),
                               ('refs/remotes/origin/release-1.0',False),
                               ('owner/repo@refs/heads/release-1.0',False)):
                entry=self.entry()
                entry.update(artifact_type=kind,origin=prefix+path)
                if kind=='ACTION':
                    entry.update(release='a'*40,digest={'algorithm':'git-sha1','value':'a'*40})
                manifest=self.manifest()
                manifest['entries']=[entry if e['id']==entry['id'] else e
                                     for e in manifest['entries']]
                for validator,value in ((lock.validate_entry,entry),
                                        (lock.validate_manifest,manifest)):
                    with self.subTest(origin=entry['origin'],validator=validator.__name__):
                        if valid:validator(value)
                        else:
                            with self.assertRaises(ValueError):validator(value)


    def test_total_oci_at_grammar_at_all_public_boundaries(self):
        digest='a'*64
        qualifiers=('sha256','sha512','v1.2.3','md5','',
                    'sha256:','sha512:'+digest,'md5:deadbeef',
                    'unknown:'+digest,'SHA256:'+digest,'sha256:'+'A'*64,
                    'sha256:'+'a'*63,'sha256:'+'a'*65,'sha256:'+'g'*64,
                    'sha256:deadbeef','sha256:'+'b'*64,
                    'md5:deadbeef@sha256:'+digest,'@sha256:'+digest,
                    'sha256:'+digest+'@','sha256:'+digest+'\n')
        cases=[(repository+'@'+selector,False)
               for repository in ('alpine','registry.invalid/owner/alpine',
                                  'https://registry.invalid/owner/alpine')
               for selector in qualifiers]
        cases.extend((origin,False) for origin in (
            '@sha256:'+digest,
            'https://u@registry.invalid/path@sha256:'+digest,
            'https://u@registry.invalid/path',
            'git@host:owner/repository',
            'ssh://git@registry.invalid/owner/repository'))
        cases.extend((origin,True) for origin in (
            'alpine@sha256:'+digest,
            'registry.invalid/owner/alpine@sha256:'+digest,
            'https://registry.invalid/owner/alpine@sha256:'+digest,
            'alpine:1.2.3','registry.invalid:5000/owner/alpine:1.2.3-rc.1'))
        for origin,valid in cases:
            entry=self.entry();entry.update(artifact_type='OCI',origin=origin)
            manifest=self.manifest()
            manifest['entries']=[entry if e['id']==entry['id'] else e
                                 for e in manifest['entries']]
            for name,check in (
                ('validate_entry',lambda:lock.validate_entry(entry)),
                ('validate_manifest',lambda:lock.validate_manifest(manifest)),
                ('adoption_blockers',lambda:lock.adoption_blockers(entry,NOW))):
                with self.subTest(origin=origin,boundary=name):
                    if valid:
                        result=check()
                        if name=='adoption_blockers':self.assertEqual(result,[])
                    else:
                        with self.assertRaises(ValueError):check()

    def test_non_oci_git_userinfo_at_all_public_boundaries(self):
        for origin in ('git@host:repository','git@example.invalid:owner/repository',
                       'ssh://git@example.invalid:2222/owner/repository',
                       'https://git@example.invalid/owner/repository',
                       'registry.invalid/repo@v2.0.0-beta+build.7'):
            entry=self.entry();entry.update(artifact_type='APPLICATION',origin=origin)
            manifest=self.manifest()
            manifest['entries']=[entry if e['id']==entry['id'] else e
                                 for e in manifest['entries']]
            with self.subTest(origin=origin):
                lock.validate_entry(entry)
                lock.validate_manifest(manifest)
                self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def git_commit_candidate(self, kind, origin):
        entry=self.entry()
        subject={'algorithm':'git-sha1','value':'a'*40}
        entry.update(artifact_type=kind,origin=origin,release='a'*40,
                     digest=copy.deepcopy(subject))
        entry['model_rights']['state']='REVIEWED'
        entry['sbom']['subject_digest']=copy.deepcopy(subject)
        for scan in entry['scans']:
            scan['subject_digest']=copy.deepcopy(subject)
        manifest=self.manifest()
        manifest['entries']=[entry if e['id']==entry['id'] else e
                             for e in manifest['entries']]
        return entry,manifest

    def git_commit_origins(self, commit):
        return tuple(prefix+commit for prefix in (
            'owner/repository@',
            'https://example.invalid/owner/repository@',
            'https://git@example.invalid/owner/repository@',
            'ssh://git@example.invalid:2222/owner/repository@',
            'git@host:repository@',
            'git@example.invalid:owner/repository@',
            'builder@host:owner/repository@'))

    def test_matching_full_git_origin_commit_at_all_public_boundaries(self):
        for kind in ('ACTION','COMFY_NODE'):
            for origin in self.git_commit_origins('a'*40):
                entry,manifest=self.git_commit_candidate(kind,origin)
                with self.subTest(kind=kind,origin=origin):
                    lock.validate_entry(entry)
                    self.assertIs(lock.validate_manifest(manifest),manifest)
                    self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_mismatched_full_git_origin_commit_at_all_public_boundaries(self):
        # Same complete fixture as the positive control: only origin differs.
        # OLD source accepts it at each boundary; the binding must reject it.
        for kind in ('ACTION','COMFY_NODE'):
            for origin in self.git_commit_origins('b'*40):
                entry,manifest=self.git_commit_candidate(kind,origin)
                for name,check in (
                    ('validate_entry',lambda:lock.validate_entry(entry)),
                    ('validate_manifest',lambda:lock.validate_manifest(manifest)),
                    ('adoption_blockers',lambda:lock.adoption_blockers(entry,NOW))):
                    with self.subTest(kind=kind,origin=origin,boundary=name):
                        with self.assertRaisesRegex(ValueError,'origin digest must match locked subject'):
                            check()


    def assert_git_origin_rejected_at_all_public_boundaries(self, kind, origin, message):
        entry,manifest=self.git_commit_candidate(kind,origin)
        for name,check in (
            ('entry',lambda:lock.validate_entry(entry)),
            ('manifest',lambda:lock.validate_manifest(manifest)),
            ('adoption',lambda:lock.adoption_blockers(entry,NOW))):
            with self.subTest(kind=kind,origin=origin,boundary=name):
                with self.assertRaisesRegex(ValueError,message):check()

    def test_noncanonical_git_origin_commits_at_all_public_boundaries(self):
        # OLDRED/newGREEN expectations only; execution requires root admission.
        # Include matching and contradictory identities: canonical-case policy
        # must reject both rather than treating a case variant as an unbound tag.
        for kind in ('ACTION','COMFY_NODE'):
            for selector in ('A'*40,'B'*40,'aA'*20,'bB'*20):
                for origin in self.git_commit_origins(selector):
                    self.assert_git_origin_rejected_at_all_public_boundaries(
                        kind,origin,'noncanonical origin commit')

    def test_repeated_git_origin_selectors_at_all_public_boundaries(self):
        # OLDRED/newGREEN: the final matching commit previously hid each prefix.
        # @main and @stable are moving branches/tags even without refs/heads/.
        for kind in ('ACTION','COMFY_NODE'):
            for hidden in ('b'*40,'a'*40,'main','stable','v1.2.3',''):
                for origin in self.git_commit_origins(hidden+'@'+'a'*40):
                    self.assert_git_origin_rejected_at_all_public_boundaries(
                        kind,origin,'repeated origin selectors forbidden')

    def test_hidden_git_branch_namespaces_at_all_public_boundaries(self):
        # Preserve the full-origin branch guard as well as the delimiter guard.
        for kind in ('ACTION','COMFY_NODE'):
            for hidden in ('refs/heads/release-1.0',
                           'refs/remotes/origin/release-1.0',
                           'ReFs/HeAdS/release-1.0'):
                for origin in self.git_commit_origins(hidden+'@'+'a'*40):
                    self.assert_git_origin_rejected_at_all_public_boundaries(
                        kind,origin,'floating origin branch forbidden')

    def test_git_transport_authority_positive_controls_at_all_public_boundaries(self):
        # Same complete evidence as the negatives; authority @ is not a selector.
        # Cover no selector and one matching commit for URL, SCP and userinfo.
        for kind in ('ACTION','COMFY_NODE'):
            for repository in ('owner/repository',
                               'https://example.invalid/owner/repository',
                               'https://builder@example.invalid/owner/repository',
                               'ssh://builder@example.invalid:2222/owner/repository',
                               'builder@host:repository',
                               'builder@example.invalid:owner/repository'):
                for suffix in ('','@'+'a'*40):
                    origin=repository+suffix
                    entry,manifest=self.git_commit_candidate(kind,origin)
                    with self.subTest(kind=kind,origin=origin):
                        lock.validate_entry(entry)
                        self.assertIs(lock.validate_manifest(manifest),manifest)
                        self.assertEqual(lock.adoption_blockers(entry,NOW),[])

    def test_git_query_fragment_rejected_before_selector_interpretation(self):
        # Authored OLDRED/newGREEN expectations; execution NOT_RUN.
        # Even a matching commit with URI syntax is unsupported, not unbound.
        for kind in ('ACTION','COMFY_NODE','COMPONENT'):
            for selector in ('a'*40,'b'*40,'A'*40,'B'*40,'main','v1.2.3'):
                for suffix in ('?docs/v1.2.3','#docs/v1.2.3','?','#',
                               '?ref=main#docs/v1.2.3'):
                    for origin in self.git_commit_origins(selector+suffix):
                        self.assert_git_origin_rejected_at_all_public_boundaries(
                            kind,origin,'unsupported Git locator')
            # The same rule applies to locators without an explicit selector.
            for origin in self.git_commit_origins('a'*40):
                repository=origin.rsplit('@',1)[0]
                for suffix in ('?docs/v1.2.3','#docs/v1.2.3'):
                    self.assert_git_origin_rejected_at_all_public_boundaries(
                        kind,repository+suffix,'unsupported Git locator')

    def test_git_selector_grammar_and_binding_in_all_source_contexts(self):
        # COMPONENT + git-sha1 exercises the source-algorithm context, beyond
        # the two special artifact kinds. Existing controls cover transports.
        for kind in ('ACTION','COMFY_NODE','COMPONENT'):
            for selector in ('a'*40,'v1.2.3','tags/v1.2.3'):
                for origin in self.git_commit_origins(selector):
                    entry,manifest=self.git_commit_candidate(kind,origin)
                    with self.subTest(kind=kind,origin=origin):
                        lock.validate_entry(entry)
                        self.assertIs(lock.validate_manifest(manifest),manifest)
                        expected=['artifact_type_UNSET'] if kind=='COMPONENT' else []
                        self.assertEqual(lock.adoption_blockers(entry,NOW),expected)
            for selector,message in (
                ('b'*40,'origin digest must match locked subject'),
                ('A'*40,'noncanonical origin commit'),
                ('main','floating origin selector forbidden'),
                ('main@'+'a'*40,'repeated origin selectors forbidden'),
                ('v1.2.3//tag','unsupported Git origin selector'),
                ('main%23docs/v1.2.3','unsupported Git origin selector'),
                ('main%3Fdocs/v1.2.3','unsupported Git origin selector')):
                for origin in self.git_commit_origins(selector):
                    self.assert_git_origin_rejected_at_all_public_boundaries(
                        kind,origin,message)

    def test_git_user_prefix_context_cannot_escape_commit_binding(self):
        # git@ selects Git parsing even for a SHA-256 application artifact.
        for selector in ('a'*40,'b'*40):
            entry=self.entry()
            entry['origin']='git@host:owner/repository@'+selector
            with self.subTest(selector=selector):
                with self.assertRaisesRegex(ValueError,'origin digest must match locked subject'):
                    lock.validate_entry(entry)
                self.assert_rejected_at_both_entry_boundaries(entry)
        for suffix in ('?docs/v1.2.3','#docs/v1.2.3'):
            entry=self.entry();entry['origin']='git@host:owner/repository@main'+suffix
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError,'unsupported Git locator'):
                    lock.validate_entry(entry)
                self.assert_rejected_at_both_entry_boundaries(entry)


    def assert_generic_pin_case(self, entry, expected, label):
        manifest=self.manifest()
        manifest['entries']=[entry if x['id']==entry['id'] else x
                             for x in manifest['entries']]
        checks=[('manifest',lambda:lock.validate_manifest(manifest)),
                ('adoption',lambda:lock.adoption_blockers(entry,NOW))]
        # validate_entry checks scan structure, not scanner release pinning.
        # Preserve that contract; scanner pins belong to these two callers.
        if expected!='scanner-reject':
            checks.insert(0,('entry',lambda:lock.validate_entry(entry)))
        for boundary,check in checks:
            with self.subTest(case=label,boundary=boundary):
                if expected=='accept':
                    result=check()
                    if boundary=='adoption':self.assertEqual(result,[])
                elif expected=='scanner-reject' and boundary=='adoption':
                    self.assertTrue(any(x.endswith('_scanner_release_unpinned')
                                        for x in check()))
                else:
                    with self.assertRaises((ValueError,ValidationError)):check()
        return len(checks)

    def test_review03_generic_suffix_68_public_boundary_cases(self):
        # Same 68 boundary expectations as the supplied independent probe.
        # OLDRED is evidenced by root's supplied 18/68 normal/-O receipt.
        # Candidate execution remains NOT_RUN pending isolated root admission.
        cases=[]
        for kind in ('APPLICATION','TOOL','MODEL'):
            for tail in ('?docs/v1.2.3','#docs/v1.2.3',
                         '%3Fdocs/v1.2.3','%23docs/v1.2.3'):
                e=self.entry();e['artifact_type']=kind
                e['model_rights']['state']='REVIEWED'
                e['origin']='https://example.invalid/owner/repo@main'+tail
                cases.append((e,'reject','origin-'+kind+'-'+tail))
        for tail in ('?docs/v1.2.3','#docs/v1.2.3'):
            e=self.entry();e['release']='registry/repo:latest'+tail
            cases.append((e,'reject','release-'+tail))
            for i in (0,1):
                e=self.entry()
                e['scans'][i]['tool_release']='registry/scanner:latest'+tail
                cases.append((e,'scanner-reject','scanner-'+str(i)+'-'+tail))
        for origin in ('https://example.invalid/latest-version/repository',
                       'registry/repo@v1.2.3','registry/repo@sha256:'+'a'*64):
            e=self.entry();e['origin']=origin
            cases.append((e,'accept','positive-origin-'+origin))
        for release in ('v1.2.3-rc.1','registry/repo:1.2.3',
                        'registry/repo@sha256:'+'a'*64):
            e=self.entry();e['release']=release
            for scan in e['scans']:scan['tool_release']=release
            cases.append((e,'accept','positive-release-'+release))
        boundaries=0
        for entry,expected,label in cases:
            boundaries+=self.assert_generic_pin_case(entry,expected,label)
        self.assertEqual(boundaries,68)

    def test_generic_origin_whole_selector_grammar(self):
        # URI suffixes are unsupported even when the selected tag is exact.
        # Encodings are not decoded into a different selector grammar.
        for kind in ('APPLICATION','TOOL','MODEL'):
            for selector in ('main','v1.2.3','sha256:'+'a'*64):
                for tail in ('?','#','%3fdocs/v1.2.3','%23docs/v1.2.3',
                             '%253Fdocs/v1.2.3','/bad%2Fsegment/v1.2.3',
                             '/bad!/v1.2.3','//v1.2.3'):
                    e=self.entry();e.update(artifact_type=kind)
                    e['model_rights']['state']='REVIEWED'
                    e['origin']='https://example.invalid/owner/repo@'+selector+tail
                    self.assert_generic_pin_case(e,'reject',e['origin'])
            for origin in ('registry/repo:main/docs/v1.2.3',
                           'repo:latest/docs/v1.2.3',
                           'registry/repo:latest#docs/v1.2.3',
                           'registry/repo:main?docs/v1.2.3',
                           'registry/repo%40main%23docs/v1.2.3',
                           'registry/repo%3Alatest%3Fdocs/v1.2.3',
                           'registry/repo@v1.2.3@v2.0.0'):
                e=self.entry();e.update(artifact_type=kind,origin=origin)
                e['model_rights']['state']='REVIEWED'
                self.assert_generic_pin_case(e,'reject',origin)

    def test_shared_release_and_both_scanner_whole_reference_grammar(self):
        bad=('registry/repo:latest%23docs/v1.2.3',
             'registry/repo:main%3Fdocs/v1.2.3',
             'registry/repo:1.2.3#docs/v2.0.0',
             'registry/repo:1.2.3?docs/v2.0.0',
             'registry/bad!/v1.2.3','registry//v1.2.3',
             'registry/repo:main/docs/v1.2.3',
             'registry/repo%2Fextra/v1.2.3',
             'registry/repo@sha256:'+'a'*64+'#docs/v1.2.3')
        for value in bad:
            self.assertFalse(lock.exact_release(value))
            e=self.entry();e['release']=value
            self.assert_generic_pin_case(e,'reject','release-'+value)
            for index in (0,1):
                e=self.entry();e['scans'][index]['tool_release']=value
                self.assert_generic_pin_case(e,'scanner-reject',
                                             'scanner-'+str(index)+'-'+value)

    def test_generic_pin_matching_controls_preserve_downloads_and_identities(self):
        for kind in ('APPLICATION','TOOL','MODEL'):
            for origin in (
                'https://example.invalid/download/v1.2.3.tar.gz',
                'https://example.invalid/download?file=v1.2.3#checksum',
                'https://example.invalid/files/package%20name.tar.gz',
                'https://builder@example.invalid/owner/repo@v1.2.3',
                'ssh://builder@example.invalid:2222/owner/repo@tags/v1.2.3',
                'git@host:owner/repo@tags/v1.2.3',
                'registry.invalid:5000/latest-version/repo:1.2.3',
                'registry/repo@sha256:'+'a'*64):
                e=self.entry();e.update(artifact_type=kind,origin=origin)
                e['model_rights']['state']='REVIEWED'
                for scan in e['scans']:
                    scan['tool_release']='registry/scanner@sha256:'+'b'*64
                self.assert_generic_pin_case(e,'accept',kind+'-'+origin)
        for release in ('tags/v1.2.3','latest-version/repo:1.2.3',
                        'registry.invalid:5000/repo:1.2.3-rc.1',
                        'https://example.invalid/repo/v1.2.3',
                        'registry/repo@sha256:'+'a'*64):
            self.assertTrue(lock.exact_release(release))
            e=self.entry();e['release']=release
            for scan in e['scans']:scan['tool_release']=release
            self.assert_generic_pin_case(e,'accept','shared-'+release)
        # Exact native revisions bypass non-OS release grammar by design.
        e=self.entry();e.update(artifact_type='OS_PACKAGE',release='2:1.2.3~rc1-1')
        self.assert_generic_pin_case(e,'accept','native-version')

if __name__=='__main__':unittest.main(verbosity=2)
