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


if __name__ == '__main__':unittest.main()
