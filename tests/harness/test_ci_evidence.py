"""Synthetic guard regressions; these tests make no network requests."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import ci_evidence as c

TESTED = 'a'*40
CANDIDATE = 'b'*40


def evidence():
    counts = {'run':54, 'failures':0, 'errors':0, 'skipped':0}
    probe = {'status':'DENY_OBSERVED', 'target':'192.0.2.1:9', 'errno':101,
             'phase':'connect', 'scope':'one TCP TEST-NET probe only'}
    return dict(schema='f07-ci-v1', synthetic_only=True, tested_git_sha=TESTED,
        pr_candidate_sha=CANDIDATE, python='3.12.3', namespace='bwrap-unshare-all',
        original={m:counts.copy() for m in ('normal','optimized')},
        helper={m:dict(counts, run=20) for m in ('normal','optimized')},
        probe={m:probe.copy() for m in ('normal','optimized')},
        retention_days=7, remaining=c.REMAINDER.copy())


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sources = {n:'c'*64 for n in c.SOURCE}

    def bundle(self, doc=None):
        raw = c.encoded(evidence() if doc is None else doc)
        manifest = dict(schema='f07-ci-manifest-v1', tested_git_sha=TESTED,
            pr_candidate_sha=CANDIDATE, retention_days=7,
            files={'evidence.json':dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())},
            source_sha256=self.sources.copy())
        (self.root/'evidence.json').write_bytes(raw)
        (self.root/'manifest.json').write_bytes(c.encoded(manifest))
        return manifest

    def validate(self):
        return c.validate_bundle(self.root, TESTED, CANDIDATE, self.sources)

    def test_valid_closed_bundle(self):
        manifest = self.bundle()
        self.assertEqual(self.validate(), manifest)
        self.assertNotEqual(TESTED, CANDIDATE)

    def test_revision_and_source_binding(self):
        self.bundle()
        for tested,candidate in ((CANDIDATE,CANDIDATE),(TESTED,TESTED),('a'*40+'\n',CANDIDATE)):
            with self.subTest(tested=tested,candidate=candidate),self.assertRaises(ValueError):
                c.validate_bundle(self.root,tested,candidate,self.sources)
        with self.assertRaises(ValueError):
            c.validate_bundle(self.root,TESTED,CANDIDATE,dict(self.sources, extra='d'*64))

    def test_unknown_fields_and_fake_sensitive_text_rejected(self):
        for key,value in (('environment',{'FAKE_TOKEN':'synthetic-not-a-secret'}),
                          ('logs','synthetic-private-log'),('padding','s')):
            doc=evidence();doc[key]=value;self.bundle(doc)
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate()

    def test_schema_type_and_retention_fail_closed(self):
        for field in ('schema','synthetic_only','python','namespace','retention_days','remaining'):
            for value in (None,True,False,[],{},'7',8):
                if field == 'synthetic_only' and value is True:
                    continue
                doc=evidence();doc[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    c.validate_evidence(doc,TESTED,CANDIDATE)

    def test_original_count_and_all_skip_failure_controls(self):
        for key,value in (('run',53),('run',55),('failures',1),('errors',1),('skipped',1),('failures',False)):
            doc=evidence();doc['original']['normal'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                c.validate_evidence(doc,TESTED,CANDIDATE)

    def test_narrow_probe_requires_actual_connect_route_denial(self):
        for key,value in (('phase','socket_creation'),('phase','timeout_setup'),('errno',1),
                          ('errno',13),('status','DENY_FAILED'),('target','example.invalid:9'),('errno',True)):
            doc=evidence();doc['probe']['optimized'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                c.validate_evidence(doc,TESTED,CANDIDATE)

    def test_missing_duplicate_and_noncanonical_bytes(self):
        self.bundle()
        path=self.root/'evidence.json'
        for raw in (b'{"schema":1,"schema":2}\n', b'{} ', b'{', b'[]\n'):
            path.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):self.validate()

    def test_hash_and_manifest_binding(self):
        for field,value in (('retention_days',True),('retention_days',8),('tested_git_sha',CANDIDATE),
                            ('source_sha256',{'../escape':'a'*64}),('files',{})):
            manifest=self.bundle();manifest[field]=value
            (self.root/'manifest.json').write_bytes(c.encoded(manifest))
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
        self.bundle();(self.root/'evidence.json').write_bytes(c.encoded(dict(evidence(),retention_days=8)))
        with self.assertRaises(ValueError):self.validate()

    def test_exact_allowlist_no_extra_or_missing_files(self):
        self.bundle();extra=self.root/'extra';extra.write_text('synthetic')
        with self.assertRaises(ValueError):self.validate()
        extra.unlink();(self.root/'manifest.json').unlink()
        with self.assertRaises(ValueError):self.validate()
        for name in ('../evidence.json','/evidence.json','evidence.json/child','manifest.json:extra'):
            with self.subTest(name=name),self.assertRaises(ValueError):c.read_regular(self.root,name)

    def test_directory_symlink_multilink_and_fifo_rejected(self):
        target=self.root/'evidence.json';target.mkdir()
        with self.assertRaises(ValueError):c.read_regular(self.root,'evidence.json')
        target.rmdir();sibling=self.root/'sibling';sibling.write_text('{}')
        # Hosted Linux capability is required; no skip disguises missing qualification.
        target.symlink_to(sibling)
        with self.assertRaises(ValueError):c.read_regular(self.root,'evidence.json')
        target.unlink();os.link(sibling,target)
        with self.assertRaises(ValueError):c.read_regular(self.root,'evidence.json')
        target.unlink();os.mkfifo(target)
        with self.assertRaises(ValueError):c.read_regular(self.root,'evidence.json')
        target.unlink();self.assertEqual(sibling.read_text(),'{}')

    def test_canonical_root_rejects_parent_traversal_and_links(self):
        for root in (Path('relative'),self.root/'..',self.root/'missing'):
            with self.subTest(root=str(root)),self.assertRaises(ValueError):c.canonical_root(root)
        link=self.root/'linked';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):c.canonical_root(link)

    def test_exact_size_and_one_byte_over_before_parse(self):
        # Exercise byte gate independently of the closed payload schema.
        path=self.root/'evidence.json'
        overhead=len(c.encoded({'padding':''}))
        path.write_bytes(c.encoded({'padding':'s'*(c.MAX_FILE-overhead)}))
        self.assertEqual(len(c.read_regular(self.root,'evidence.json')[0]),c.MAX_FILE)
        path.write_bytes(c.encoded({'padding':'s'*(c.MAX_FILE-overhead+1)}))
        with self.assertRaises(ValueError):c.read_regular(self.root,'evidence.json')

    def test_aggregate_one_byte_over_and_exact_boundary(self):
        self.bundle()
        total=sum((self.root/n).stat().st_size for n in c.FILES)
        with patch.object(c,'MAX_TOTAL',total):self.validate()
        with patch.object(c,'MAX_TOTAL',total-1),self.assertRaises(ValueError):self.validate()

    def test_guard_negative_control_proves_rejection_matters(self):
        doc=evidence();doc['retention_days']=8
        with self.assertRaises(ValueError):c.validate_evidence(doc,TESTED,CANDIDATE)
        # Deliberately broken require lets this invalid evidence through; the
        # control shows the guard assertion is active, not a vacuous fixture.
        with patch.object(c,'require',return_value=None):
            self.assertEqual(c.validate_evidence(doc,TESTED,CANDIDATE)['retention_days'],8)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.doc=dict(id=17,name='f07-synthetic-42-1',digest='sha256:'+'d'*64,
            size_in_bytes=1024,expired=False,created_at='2026-10-01T00:00:00Z',
            expires_at='2026-10-08T00:00:00Z',workflow_run={'id':42,'head_sha':CANDIDATE})
        self.options=dict(artifact_id=17,digest='d'*64,run_id=42,tested=TESTED,candidate=CANDIDATE,
            name='f07-synthetic-42-1',now=datetime(2026,10,1,0,1,tzinfo=timezone.utc))

    def check(self):return c.validate_metadata(self.doc,**self.options)

    def test_actual_metadata_closed_receipt(self):
        receipt=self.check()
        self.assertEqual(receipt['tested_git_sha'],TESTED)
        self.assertEqual(receipt['pr_candidate_sha'],CANDIDATE)
        self.assertEqual(receipt['retention'],'configured-seven-day-expiry')
        self.assertEqual(receipt['remaining']['seven_day_elapsed_deletion'],'NOT_RUN')
        self.assertEqual(receipt['authorization_matrix'],'NOT_RUN')

    def test_id_digest_size_expired_and_name_binding(self):
        for key,value in (('id',True),('id',18),('digest','sha256:'+'e'*64),('size_in_bytes',0),
                          ('size_in_bytes',True),('size_in_bytes',c.MAX_TOTAL+65537),
                          ('expired',True),('expired',0),('name','other')):
            doc=copy.deepcopy(self.doc);doc[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                c.validate_metadata(doc,**self.options)

    def test_run_head_and_required_metadata_binding(self):
        for workflow in ({'id':43,'head_sha':CANDIDATE},{'id':42,'head_sha':TESTED},
                         {'id':True,'head_sha':CANDIDATE},{},None):
            doc=copy.deepcopy(self.doc);doc['workflow_run']=workflow
            with self.subTest(workflow=workflow),self.assertRaises(ValueError):
                c.validate_metadata(doc,**self.options)
        for key in self.doc:
            doc=copy.deepcopy(self.doc);del doc[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):c.validate_metadata(doc,**self.options)

    def test_retention_window_calendar_future_and_stale(self):
        for key,value in (('expires_at','2026-10-09T00:00:00Z'),
                          ('expires_at','2026-10-07T00:00:00Z'),
                          ('created_at','2026-10-01T00:02:00Z'),
                          ('created_at','2026-02-30T00:00:00Z'),
                          ('created_at','2026-10-01T00:00:00'),
                          ('created_at','2026-10-01T00:00:00+00:00')):
            doc=copy.deepcopy(self.doc);doc[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):c.validate_metadata(doc,**self.options)
        self.options['now']=datetime(2026,10,1,1,tzinfo=timezone.utc)
        with self.assertRaises(ValueError):self.check()

    def test_redirect_rejected_without_network(self):
        with self.assertRaises(ValueError):c.NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid')



class NativeBootstrapTests(unittest.TestCase):
    def lock(self):
        return json.loads((Path(c.__file__).parent/'native-ci.lock.json').read_text())

    def test_closed_reviewed_native_lock(self):
        lock=self.lock()
        self.assertEqual(c.validate_native_lock(lock),lock)
        self.assertEqual(lock['max_members'],30)
        self.assertEqual(lock['package']['version'],'0.9.0-1ubuntu0.3')
        self.assertEqual(lock['package']['size'],50436)
        self.assertEqual(c.validate_native_members(lock['members'],lock),lock['members'])

    def test_os_version_architecture_rejects_without_fallback(self):
        c.validate_native_platform('ubuntu','24.04','x86_64','Linux')
        for args in (('ubuntu','22.04','x86_64','Linux'),('debian','24.04','x86_64','Linux'),
                     ('ubuntu','24.04','aarch64','Linux'),('ubuntu','24.04','x86_64','Windows'),
                     ('ubuntu',24.04,'x86_64','Linux')):
            with self.subTest(args=args),self.assertRaises(ValueError):c.validate_native_platform(*args)

    def test_native_url_version_size_hash_pins_are_closed(self):
        for key,value in (('url','https://example.invalid/package.deb'),('version','0.9.0'),
                          ('sha256','a'*64),('binary_sha256','b'*64),('copyright_sha256','c'*64),
                          ('size',50437),('size',True),('architecture','arm64'),('os_version','26.04'),
                          ('binary','../bwrap'),('copyright','/copyright')):
            lock=self.lock();lock['package'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):c.validate_native_lock(lock)
        lock=self.lock();lock['unreviewed']='synthetic'
        with self.assertRaises(ValueError):c.validate_native_lock(lock)

    def test_native_package_size_and_digest_fail_closed(self):
        for raw in (b'',b's'*50435,b's'*50436,b's'*50437,False):
            with self.subTest(size=len(raw) if type(raw) is bytes else None),self.assertRaises(ValueError):
                c.validate_native_bytes(raw,self.lock())

    def test_tar_members_path_link_type_count_size_reject(self):
        lock=self.lock()
        for key,value in (('name','../escape'),('name','/escape'),('name','./usr/../escape'),
                          ('name','./usr//escape'),('name','./usr\\escape'),('type','2'),
                          ('type','1'),('type','6'),('type','3'),('link','/escape'),('size',True),('size',72161)):
            rows=copy.deepcopy(lock['members']);rows[3][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):c.validate_native_members(rows,lock)
        for rows in (lock['members'][:-1],lock['members']+[lock['members'][0]],list(reversed(lock['members']))):
            with self.assertRaises(ValueError):c.validate_native_members(rows,lock)

    def synthetic_tar(self, mutate=None):
        import io
        import tarfile
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for index,row in enumerate(self.lock()['members']):
                info=tarfile.TarInfo(row['name']);info.type=row['type'].encode('ascii');info.size=row['size']
                if mutate is not None:mutate(index,info)
                archive.addfile(info,io.BytesIO(b's'*info.size) if info.type == tarfile.REGTYPE else None)
        return stream.getvalue()

    def test_manual_extract_regular_directories_only_and_notice_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            c.extract_native_tar(self.synthetic_tar(),root,self.lock())
            self.assertEqual((root/'usr/bin/bwrap').stat().st_size,72160)
            self.assertEqual((root/'usr/share/doc/bubblewrap/copyright').stat().st_size,3388)
            self.assertTrue((root/'usr/share/doc/bubblewrap/copyright').is_file())
            self.assertFalse((root/'postinst').exists())

    def test_unsafe_tar_rejects_before_any_write(self):
        import tarfile
        def traversal(index,info):
            if index == 3:info.name='../escape'
        def symlink(index,info):
            if index == 3:info.type=tarfile.SYMTYPE;info.linkname='/escape';info.size=0
        def special(index,info):
            if index == 3:info.type=tarfile.FIFOTYPE;info.size=0
        for mutate in (traversal,symlink,special):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve()
                with self.assertRaises(ValueError):c.extract_native_tar(self.synthetic_tar(mutate),root,self.lock())
                self.assertEqual(list(root.iterdir()),[])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with self.assertRaises(ValueError):c.extract_native_tar(b's'*262145,root,self.lock())
            self.assertEqual(list(root.iterdir()),[])

    def test_native_cleanup_scope_unknown_special_and_links_reject(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'unexpected').write_text('preserve')
            with self.assertRaises(ValueError):c.validate_native_tree(root,self.lock(),complete=False)
            self.assertEqual((root/'unexpected').read_text(),'preserve')
            (root/'unexpected').unlink();(root/'payload').symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):c.validate_native_tree(root,self.lock(),complete=False)
            (root/'payload').unlink();os.mkfifo(root/'package.deb')
            with self.assertRaises(ValueError):c.validate_native_tree(root,self.lock(),complete=False)

    def test_namespace_unsupported_never_qualifies(self):
        c.validate_namespace_exit(0)
        for value in (1,2,126,127,-9,None,False,'0'):
            with self.subTest(value=value),self.assertRaises(ValueError):c.validate_namespace_exit(value)

    def test_python_library_not_inherited_from_arbitrary_environment(self):
        for prefix,libdir in (('/tmp/python','/tmp/python/lib'),
                              ('/opt/hostedtoolcache/Python/3.12.3/x64','/tmp/lib'),
                              ('/opt/hostedtoolcache/Python/3.14.0/x64','/opt/hostedtoolcache/Python/3.14.0/x64/lib')):
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):c.python_library_path(prefix,libdir)

    def test_diagnostics_only_allow_closed_phase_and_status(self):
        import io
        stream=io.StringIO()
        with patch.object(c.sys,'stderr',stream):
            c.diagnostic('native-size-sha256','PASS')
            with self.assertRaises(ValueError):c.diagnostic('synthetic-private-path','FAIL')
            with self.assertRaises(ValueError):c.diagnostic('namespace','synthetic-token')
        self.assertEqual(json.loads(stream.getvalue()),
                         {'scope':'f07-ci-bootstrap','phase':'native-size-sha256','status':'PASS'})


class NamespaceDiagnosticTests(unittest.TestCase):
    def failed_state(self, raw=b'', complete=True):
        return dict(reason='CHILD_NONZERO',code=1,errno=None,stderr=raw,stderr_count=len(raw),stdout_count=0,
                    stderr_eof=complete,stderr_limit=False,stdout_limit=False,drain=False,deadline=False,reaped=True)

    def receipt(self,state=None):
        return c.namespace_failure_receipt(self.failed_state() if state is None else state,TESTED,CANDIDATE,42,1)

    def test_only_two_entire_synthetic_permission_texts_classify(self):
        for raw in c.PERMISSION_TEXT:
            receipt=self.receipt(self.failed_state(raw))
            self.assertEqual(receipt['known_error_class'],'NAMESPACE_PERMISSION_ERROR_TEXT')
            self.assertIsNone(receipt['errno'])
            self.assertNotIn(raw.decode().strip(),c.encoded(receipt).decode())
        self.assertEqual(self.receipt()['known_error_class'],'EMPTY')

    def test_stderr_injection_ansi_tokens_paths_unknown_and_invalid_utf8(self):
        fake=b'synthetic-FAKE-TOKEN /synthetic/private/path'
        for raw in (fake,c.PERMISSION_TEXT[0]+fake,c.PERMISSION_TEXT[0]+b'\n',
                    b'\x1b[31m'+c.PERMISSION_TEXT[0],b'\xff\x00',
                    b'{"phase":"harness","status":"PASS","instruction":"synthetic-FAKE-TOKEN"}\n'):
            receipt=self.receipt(self.failed_state(raw))
            self.assertEqual(receipt['known_error_class'],'UNKNOWN')
            rendered=c.encoded(receipt)
            self.assertNotIn(b'synthetic-FAKE-TOKEN',rendered)
            self.assertNotIn(b'/synthetic/private/path',rendered)
            self.assertNotIn(b'\x1b',rendered)

    def test_canonical_helper_failure_only_reports_phase(self):
        raw=b''.join(c.encoded(dict(scope='f07-ci-bootstrap',phase='harness',status=s)) for s in ('START','FAIL'))
        receipt=self.receipt(self.failed_state(raw))
        self.assertEqual(receipt['known_error_class'],'INNER_HELPER_FAILURE_REPORTED')
        self.assertEqual(receipt['inner_phase_reported'],'harness')
        self.assertEqual(receipt['status'],'FAIL')
        self.assertEqual(self.receipt(self.failed_state(raw+b'extra'))['known_error_class'],'UNKNOWN')

    def test_prefix_hash_and_truncation_are_explicit(self):
        state=self.failed_state(b's'*c.STDERR_PREFIX)
        state['stderr_count']=c.STDERR_PREFIX+1
        receipt=self.receipt(state)
        self.assertTrue(receipt['stderr_truncated'])
        self.assertEqual(receipt['stderr_prefix_sha256'],hashlib.sha256(state['stderr']).hexdigest())
        self.assertEqual(receipt['known_error_class'],'UNKNOWN')
        state.update(reason='STREAM_LIMIT',stderr_count=c.STREAM_LIMIT,stderr_limit=True,stderr_eof=False)
        receipt=self.receipt(state)
        self.assertFalse(receipt['stderr_complete'])
        self.assertTrue(receipt['stderr_limit_reached'])

    def test_receipt_types_unknown_fields_limits_and_consistency(self):
        for key,value in (('stderr_bytes_observed',True),('stderr_prefix_bytes',False),('process_exit_code',True),
                          ('errno',True),('stderr_bytes_observed',c.STREAM_LIMIT+1),('stderr_prefix_bytes',65537),
                          ('known_error_class','OS_DENIED'),('inner_phase_reported','unknown'),('run_id',False),
                          ('stderr_complete','true'),('stderr_prefix_sha256','a'*64+'\n'),('tested_git_sha',CANDIDATE+'\n')):
            doc=self.receipt();doc[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):c.validate_namespace_diagnostic(doc)
        doc=self.receipt();doc['raw']='synthetic-FAKE-TOKEN'
        with self.assertRaises(ValueError):c.validate_namespace_diagnostic(doc)
        doc=self.receipt();doc['process_signal']=9
        with self.assertRaises(ValueError):c.validate_namespace_diagnostic(doc)
        self.assertLessEqual(len(c.encoded(self.receipt())),4096)

    def test_direct_child_signal_and_shell_code_are_distinct(self):
        state=self.failed_state();state.update(reason='CHILD_SIGNAL',code=-9)
        receipt=self.receipt(state)
        self.assertEqual(receipt['process_signal'],9);self.assertIsNone(receipt['process_exit_code'])
        state.update(reason='CHILD_NONZERO',code=137)
        receipt=self.receipt(state)
        self.assertIsNone(receipt['process_signal']);self.assertEqual(receipt['process_exit_code'],137)
        state.update(reason='SPAWN_OS_ERROR',code=None,errno=2,reaped=False)
        self.assertEqual(self.receipt(state)['errno'],2)

    def test_owned_process_small_dual_output_and_nonzero(self):
        # Root runtime later: synthetic subprocess only, no namespace/provider.
        state=c.capture_namespace_process([c.sys.executable,'-c',
            'import os;os.write(1,b"synthetic-private-stdout");os.write(2,b"synthetic-private-stderr");raise SystemExit(7)'],timeout=3)
        self.assertEqual(state['code'],7);self.assertTrue(state['reaped'])
        self.assertEqual(state['reason'],'CHILD_NONZERO')
        rendered=c.encoded(self.receipt(state))
        self.assertNotIn(b'synthetic-private',rendered)

    def test_stdout_and_stderr_limits_fail_and_reap_exact_child(self):
        for descriptor in (1,2):
            state=c.capture_namespace_process([c.sys.executable,'-c',
                'import os;os.write('+str(descriptor)+',b"s"*1048577)'],timeout=3)
            with self.subTest(descriptor=descriptor):
                self.assertEqual(state['reason'],'STREAM_LIMIT')
                self.assertTrue(state['reaped'])
                self.assertTrue(state['stdout_limit'] if descriptor == 1 else state['stderr_limit'])
                self.assertLessEqual(len(state['stderr']),65536)
                self.assertLessEqual(state['stderr_count'],1048576)
                self.receipt(state)

    def test_silent_timeout_and_ignored_term_are_bounded(self):
        import time
        started=time.monotonic()
        state=c.capture_namespace_process([c.sys.executable,'-c',
            'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(20)'],timeout=0.5)
        self.assertLess(time.monotonic()-started,2)
        self.assertEqual(state['reason'],'DEADLINE');self.assertTrue(state['deadline']);self.assertTrue(state['reaped'])
        self.receipt(state)
        for timeout in (True,0,601,float('inf'),float('nan')):
            with self.assertRaises(ValueError):c.capture_namespace_process([],timeout=timeout)

    def test_spawn_os_error_is_sanitized(self):
        state=c.capture_namespace_process(['/synthetic/nonexistent-executable'],timeout=1)
        self.assertEqual(state['reason'],'SPAWN_OS_ERROR')
        rendered=c.encoded(self.receipt(state))
        self.assertNotIn(b'/synthetic/',rendered)
        self.assertIsInstance(self.receipt(state)['errno'],int)

    def test_eintr_and_eagain_reads_retry_without_losing_bounds(self):
        real=c.read_namespace_pipe
        for error in (InterruptedError(),BlockingIOError()):
            first=[True]
            def reading(descriptor):
                if first[0]:first[0]=False;raise error
                return real(descriptor)
            with patch.object(c,'read_namespace_pipe',side_effect=reading):
                state=c.capture_namespace_process([c.sys.executable,'-c','import os;os.write(2,b"s")'],timeout=3)
            self.assertIsNone(state['reason']);self.assertEqual(state['code'],0);self.assertEqual(state['stderr'],b's')

    def test_postexit_inherited_descriptor_has_one_second_drain_bound(self):
        import time
        started=time.monotonic()
        state=c.capture_namespace_process([c.sys.executable,'-c',
            'import os,time\nif os.fork()==0:\n time.sleep(1.4);os._exit(0)\nelse:\n os._exit(3)'],timeout=3)
        self.assertLess(time.monotonic()-started,2)
        self.assertEqual(state['reason'],'DRAIN_INCOMPLETE');self.assertTrue(state['drain']);self.assertTrue(state['reaped'])
        self.assertFalse(self.receipt(state)['stderr_complete'])

if __name__ == '__main__':unittest.main()
