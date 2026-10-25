"""Execute only in root's isolated test environment; all DBs are temporary fixtures."""
import concurrent.futures
import contextlib
import sqlite3
from unittest.mock import patch
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import traceback

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'orchestration/controller'))
from local import LocalController, canonical_hash, result_digest, AUTHORITY, F11_SCHEMA_VERSION, _REFERENCE, preflight_existing_ledger, stable_ledger_copy

BASE='a'*40
HEAD='b'*40
MANIFEST='c'*64

def task(key, scope=None, locks=None, cpu=1, deps=None, kind='foundation', evidence_level=None):
    return dict(key=key,kind=kind,completion_authority=AUTHORITY,evidence_level=evidence_level,resources=dict(cpu=cpu,memory_mib=64,gpu=0,slots=1,integration=0),
                depends_on=deps or [],write_paths=[scope or 'src/'+key+'/'],locks=locks or [],
                enabled_by_default=True,manual=False,priority='P1')

def policy(workers=2):
    return dict(max_workers=workers,lease_seconds=10,max_attempts=3,
                capacities=dict(cpu=workers,memory_mib=workers*128,gpu=0,slots=workers,integration=0),
                max_cost_per_task_usd=1,total_cost_budget_usd=20)

def result(packet):
    return {**{k:packet[k] for k in ('task_key','lease_token','fence','input_sha256','base_revision')},
            'status':'ready_for_review','summary':'synthetic result',
            'changed_paths':[packet['task']['write_paths'][0]+'file.txt'],
            'tests':[dict(command='synthetic-check',exit_code=0,environment='temporary offline fixture')],
            'artifacts':[dict(path='evidence.json',sha256='d'*64)],'blockers':[]}

def proof(packet, process_ref='synthetic-process'):
    return {**{k:packet[k] for k in ('task_key','fence','input_sha256','base_revision')},
            'process_ref':process_ref,'terminated':True,'effects_reconciled':True,
            'verified_by':'trusted-supervisor','evidence_ref':'synthetic-independent-proof'}

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'test.sqlite3'; self.now=[1000.0]
        self.tasks=[task('A')]; self.pol=policy()
    def make(self, fixture_only=True, **kwargs):
        return LocalController(self.path,self.tasks,self.pol,clock=lambda:self.now[0],fixture_only=fixture_only,**kwargs)
    def claim(self,s,key='A',agent='author'):
        return s.claim(agent,BASE,key)
    def bind(self,s,p,ref='synthetic-process'):
        s.bind_process(p['task_key'],p['lease_token'],p['fence'],p['input_sha256'],p['base_revision'],ref)
    def finish(self,s,p,**kwargs):
        s.finish(result(p),reconciliation=proof(p),candidate_revision=HEAD,manifest_sha256=MANIFEST,**kwargs)
    def receipt(self,s,p):
        return {**{k:p[k] for k in ('task_key','fence','input_sha256','base_revision')},
                'revision':HEAD,'candidate_revision':HEAD,'manifest_sha256':MANIFEST,'result_sha256':result_digest(result(p)),
                'graph_sha256':s.graph_hash,'policy_sha256':s.policy_hash,'verified_by':'independent-reviewer',
                'independent_review':True,'checks_verified':True,'evidence_level':'CODE_MERGED',
                'source':'verified-github-merge','verification_ref':'synthetic-exact-head-check'}
    def test_atomic_same_task_across_controller_instances(self):
        self.make(); barrier=threading.Barrier(8)
        def attempt(n):
            try:
                s=self.make()
            except BaseException:
                barrier.abort()
                raise
            barrier.wait(timeout=10)
            return s.claim('author'+str(n),BASE)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(attempt,n) for n in range(8)]
            claims=[]; errors=[]
            for future in futures:
                try: claims.append(future.result(timeout=20))
                except BaseException as error:
                    errors.append(''.join(traceback.format_exception(error)))
            self.assertFalse(errors, '\n'.join(errors))
        self.assertEqual(sum(p is not None for p in claims),1)
        self.assertEqual(self.make().record('A')['attempts'],1)
    def test_atomic_all_resource_caps(self):
        self.tasks=[task(str(i)) for i in range(8)];self.make()
        def attempt(n): return self.make().claim('author'+str(n),BASE,str(n))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(attempt,n) for n in range(8)]
            claims=[]; errors=[]
            for future in futures:
                try: claims.append(future.result(timeout=20))
                except BaseException as error:
                    errors.append(''.join(traceback.format_exception(error)))
            self.assertFalse(errors, '\n'.join(errors))
        self.assertEqual(sum(p is not None for p in claims),2)
        self.assertEqual(self.make().status()['resources_reserved']['cpu'],2)
        self.assertEqual(self.make().status()['resources_reserved']['slots'],2)
    def test_path_prefix_and_explicit_lock_reservations(self):
        for mode in ('path','explicit'):
            with self.subTest(mode=mode):
                self.path=Path(self.tmp.name)/(mode+'.sqlite3')
                self.tasks=[task('A',scope='src/shared/',locks=['migration'] if mode=='explicit' else []),
                            task('B',scope='src/other/' if mode=='explicit' else 'src/shared/child/',locks=['migration'] if mode=='explicit' else [])]
                s=self.make(); self.assertIsNotNone(self.claim(s)); self.assertIsNone(self.claim(s,'B'))
    def test_sibling_paths_can_run(self):
        self.tasks=[task('A',scope='src/a/'),task('B',scope='src/ab/')]
        s=self.make();self.assertIsNotNone(self.claim(s));self.assertIsNotNone(self.claim(s,'B'))
    def test_expired_finish_commits_orphan_without_status_sweep(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.now[0]+=11
        with self.assertRaises(ValueError): self.finish(s,p)
        self.assertEqual(s.record('A')['state'],'ORPHANED')
        self.assertEqual(s.record('A')['reserved_cost'],1)
    def test_malformed_expired_finish_still_quarantines(self):
        s=self.make();p=self.claim(s);self.now[0]+=11
        with self.assertRaises(ValueError): s.finish({},reconciliation={},candidate_revision=HEAD,manifest_sha256=MANIFEST)
        self.assertEqual(s.record('A')['state'],'ORPHANED')
    def test_expired_heartbeat_commits_orphan(self):
        s=self.make();p=self.claim(s);self.now[0]+=11
        with self.assertRaises(ValueError): s.heartbeat('A',p['lease_token'],p['fence'])
        self.assertEqual(s.record('A')['state'],'ORPHANED')
    def test_restart_keeps_quarantine_capacity_path_and_cost(self):
        self.tasks=[task('A'),task('B')];self.pol=policy(1)
        s=self.make();p=self.claim(s);self.bind(s,p);self.now[0]+=11
        s=self.make();self.assertEqual(s.status()['counts']['ORPHANED'],1)
        self.assertIsNone(self.claim(s,'B'));self.assertEqual(s.status()['reserved_usd'],1)
    def test_live_restart_keeps_current_lease(self):
        s=self.make();p=self.claim(s);s=self.make()
        self.assertIsNone(self.claim(s));self.assertEqual(s.record('A')['fence'],p['fence'])
    def test_finish_needs_bound_process_and_positive_reconciliation(self):
        s=self.make();p=self.claim(s)
        with self.assertRaises(ValueError): self.finish(s,p)
        self.bind(s,p)
        for field,value in [('terminated',False),('effects_reconciled',False),('process_ref','other'),('input_sha256','0'*64),('fence',p['fence']+1),('verified_by','author')]:
            bad=proof(p);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                s.finish(result(p),reconciliation=bad,candidate_revision=HEAD,manifest_sha256=MANIFEST)
        self.assertEqual(s.record('A')['state'],'RUNNING');self.assertEqual(s.record('A')['reserved_cost'],1)
    def test_orphan_release_requires_current_process_and_outcome(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.now[0]+=11
        bad=proof(p);bad['process_ref']='other'
        with self.assertRaises(ValueError):s.reconcile_orphan('A',bad,retry=True)
        self.assertEqual(s.record('A')['state'],'ORPHANED');self.assertEqual(s.record('A')['reserved_cost'],1)
        s.reconcile_orphan('A',proof(p),retry=True,trusted_cost=0)
        p2=self.claim(s,agent='new-author');self.assertGreater(p2['fence'],p['fence'])
        with self.assertRaises(ValueError):self.finish(s,p)
    def test_late_proof_cannot_release_new_attempt(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.now[0]+=11
        s.reconcile_orphan('A',proof(p),retry=True);p2=self.claim(s,agent='second');self.bind(s,p2)
        self.now[0]+=11
        with self.assertRaises(ValueError):s.reconcile_orphan('A',proof(p),retry=True)
        self.assertEqual(s.record('A')['state'],'ORPHANED')
        self.assertEqual(s.record('A')['fence'],p2['fence'])
    def test_result_nested_schema_and_finiteness(self):
        s=self.make();p=self.claim(s);self.bind(s,p)
        mutations=[lambda r:r.update(tests='bad'),lambda r:r['tests'][0].update(exit_code=True),lambda r:r['tests'][0].update(unknown='bad'),lambda r:r['artifacts'][0].update(sha256='a'*64+'\n'),lambda r:r['artifacts'][0].update(path='../escape'),lambda r:r.update(blockers=[{}]),lambda r:r.update(fence=True),lambda r:r.update(actual_cost_usd=float('nan')),lambda r:r.update(extra=True),lambda r:r.update(changed_paths=['outside/file'])]
        for change in mutations:
            r=result(p);change(r)
            with self.assertRaises(ValueError):s.finish(r,reconciliation=proof(p),candidate_revision=HEAD,manifest_sha256=MANIFEST)
        self.assertEqual(s.record('A')['state'],'RUNNING')
    def test_result_wrong_input_or_token_rejected(self):
        s=self.make();p=self.claim(s);self.bind(s,p)
        for key,value in [('input_sha256','0'*64),('base_revision','e'*40),('lease_token','wrong')]:
            r=result(p);r[key]=value
            with self.assertRaises(ValueError):s.finish(r,reconciliation=proof(p),candidate_revision=HEAD,manifest_sha256=MANIFEST)
    def test_review_keeps_locks_until_exact_acceptance(self):
        self.tasks=[task('A',scope='src/shared/'),task('B',scope='src/shared/')]
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        self.assertEqual(s.status()['resources_reserved']['cpu'],0)
        self.assertIsNone(self.claim(s,'B'))
        s.accept('A',self.receipt(s,p));self.assertIsNotNone(self.claim(s,'B'))
    def test_old_candidate_or_input_receipt_rejected(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        for key,value in [('candidate_revision','e'*40),('manifest_sha256','f'*64),('result_sha256','0'*64),('input_sha256','0'*64),('fence',p['fence']+1),('policy_sha256','0'*64)]:
            receipt=self.receipt(s,p);receipt[key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):s.accept('A',receipt)
        self.assertEqual(s.record('A')['state'],'REVIEW')
    def test_replayed_acceptance_and_self_approval_rejected(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        r=self.receipt(s,p);r['verified_by']='author'
        with self.assertRaises(ValueError):s.accept('A',r)
        s.accept('A',self.receipt(s,p))
        with self.assertRaises(ValueError):s.accept('A',self.receipt(s,p))
    def test_result_persists_without_bearer_token(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        row=s.record('A');self.assertNotIn('lease_token',json.loads(row['result']));self.assertNotIn('token',row)
        self.assertNotIn('lease_token',str(s.status()))
    def test_caller_mutation_does_not_change_configuration(self):
        s=self.make();self.tasks[0]['resources']['cpu']=0;self.pol['max_workers']=999
        self.assertEqual(s.tasks['A']['resources']['cpu'],1);self.assertEqual(s.policy['max_workers'],2)
        s.tasks['A']['resources']['cpu']=0
        with self.assertRaises(ValueError):self.claim(s)
    def test_invalid_bool_resource_and_unknown_capacity_rejected(self):
        self.tasks[0]['resources']['cpu']=True
        with self.assertRaises(ValueError):self.make()
        self.tasks[0]['resources']['cpu']=1;self.tasks[0]['resources']['unknown']=1
        with self.assertRaises(ValueError):self.make()
    def test_unknown_cost_reserved_and_overrun_stops(self):
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        self.assertEqual(s.status()['spent_usd'],1)
        self.path=Path(self.tmp.name)/'overrun.sqlite3';s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p,trusted_cost=2)
        self.assertTrue(s.status()['stopped'])
    def test_supplied_f08_live_inputs_are_hold(self):
        inputs=json.loads((ROOT/'docs/orchestration/capacity/dispatch-inputs.json').read_text())
        measurements=json.loads((ROOT/'docs/orchestration/capacity/measurements.json').read_text())
        s=self.make(fixture_only=False,dispatch_inputs=inputs,measurements=measurements,trusted_admission_ref='synthetic-does-not-bypass-missing-inputs')
        with self.assertRaises(ValueError):self.claim(s)
    def test_fixture_database_cannot_be_reopened_live(self):
        self.make()
        with self.assertRaises(ValueError):self.make(fixture_only=False)
    def test_manual_and_deferred_not_claimed(self):
        self.tasks[0]['manual']=True;s=self.make();self.assertIsNone(self.claim(s))
        self.path=Path(self.tmp.name)/'deferred.sqlite3';self.tasks[0]['manual']=False;self.tasks[0]['enabled_by_default']=False
        s=self.make();self.assertIsNone(self.claim(s))
    def no_launch_proof(self,s,p):
        with s._connection() as db:
            attempt=db.execute('SELECT * FROM f11_attempts WHERE task_key=? AND fence=?',(p['task_key'],p['fence'])).fetchone()
        return {**{k:p[k] for k in ('task_key','fence','input_sha256','base_revision')},
                'launch_ref':attempt['launch_ref'],'no_launch_confirmed':True,'effects_reconciled':True,
                'verified_by':'trusted-supervisor','evidence_ref':'synthetic-no-launch-readback'}
    def test_claim_crash_before_binding_has_atomic_recoverable_attempt(self):
        s=self.make();p=self.claim(s)
        proof_record=self.no_launch_proof(s,p)
        self.now[0]+=11;s=self.make()
        self.assertEqual(s.status()['counts']['ORPHANED'],1)
        s.reconcile_orphan('A',proof_record,retry=True,trusted_cost=0)
        p2=self.claim(s,agent='replacement')
        self.assertGreater(p2['fence'],p['fence'])
    def test_no_launch_requires_positive_current_independent_evidence(self):
        s=self.make();p=self.claim(s);good=self.no_launch_proof(s,p);self.now[0]+=11
        for field,value in [('no_launch_confirmed',False),('effects_reconciled',False),('launch_ref','wrong'),('fence',p['fence']+1),('input_sha256','0'*64),('verified_by','author')]:
            bad=dict(good);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):s.reconcile_orphan('A',bad,retry=True)
        missing=dict(good);del missing['no_launch_confirmed']
        with self.assertRaises(ValueError):s.reconcile_orphan('A',missing,retry=True)
        self.assertEqual(s.record('A')['state'],'ORPHANED');self.assertEqual(s.record('A')['reserved_cost'],1)
    def test_bound_process_cannot_use_no_launch_proof(self):
        s=self.make();p=self.claim(s);no_launch=self.no_launch_proof(s,p);self.bind(s,p);self.now[0]+=11
        with self.assertRaises(ValueError):s.reconcile_orphan('A',no_launch,retry=True)
    def test_no_launch_proof_cannot_finish_a_candidate(self):
        s=self.make();p=self.claim(s)
        with self.assertRaises(ValueError):s.finish(result(p),reconciliation=self.no_launch_proof(s,p),candidate_revision=HEAD,manifest_sha256=MANIFEST)
        self.assertEqual(s.record('A')['state'],'RUNNING')
    def test_failed_claim_rolls_back_attempt_row_and_reservations(self):
        class RejectEvent(LocalController):
            def _event(self,db,key,kind,detail):
                if kind=='CLAIM':raise RuntimeError('synthetic-before-commit-crash')
                return super()._event(db,key,kind,detail)
        s=RejectEvent(self.path,self.tasks,self.pol,clock=lambda:self.now[0],fixture_only=True)
        with self.assertRaises(RuntimeError):self.claim(s)
        self.assertEqual(s.record('A')['state'],'BACKLOG')
        with s._connection() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM f11_attempts').fetchone()[0],0)
    def test_old_no_launch_proof_cannot_release_replacement(self):
        s=self.make();p=self.claim(s);old=self.no_launch_proof(s,p);self.now[0]+=11
        s.reconcile_orphan('A',old,retry=True);p2=self.claim(s,agent='replacement');self.now[0]+=11
        with self.assertRaises(ValueError):s.reconcile_orphan('A',old,retry=True)
        self.assertEqual(s.record('A')['fence'],p2['fence']);self.assertEqual(s.record('A')['state'],'ORPHANED')
    def test_normal_and_squash_merge_keep_distinct_candidate_and_merge_ids(self):
        for merge in ('e'*40,'f'*40):
            self.path=Path(self.tmp.name)/(merge[:1]+'.sqlite3')
            s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
            receipt=self.receipt(s,p);receipt['revision']=merge
            s.accept('A',receipt)
            stored=json.loads(s.record('A')['receipt'])
            self.assertEqual(stored['candidate_revision'],HEAD);self.assertEqual(stored['revision'],merge)
    def test_verification_sandbox_only_rejects_code_merge(self):
        self.tasks=[task('A',kind='verification',evidence_level='SANDBOX_QUALIFIED_ONLY')]
        s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        with self.assertRaises(ValueError):s.accept('A',self.receipt(s,p))
        receipt=self.receipt(s,p);receipt.update(evidence_level='SANDBOX_QUALIFIED',source='verified-independent-executor')
        s.accept('A',receipt);self.assertEqual(s.record('A')['state'],'ACCEPTED')
    def test_build_and_foundation_cannot_accept_sandbox_alone(self):
        for kind in ('foundation','implementation'):
            self.path=Path(self.tmp.name)/(kind+'.sqlite3');self.tasks=[task('A',kind=kind)]
            s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
            receipt=self.receipt(s,p);receipt.update(evidence_level='SANDBOX_QUALIFIED',source='verified-independent-executor')
            with self.assertRaises(ValueError):s.accept('A',receipt)
    def test_omitted_runtime_level_defaults_to_sandbox_not_code(self):
        self.tasks=[task('A',kind='integration')];s=self.make();p=self.claim(s);self.bind(s,p);self.finish(s,p)
        with self.assertRaises(ValueError):s.accept('A',self.receipt(s,p))
    def test_missing_kind_authority_and_contradictory_levels_rejected(self):
        for field in ('kind','completion_authority'):
            self.tasks=[task('A')];del self.tasks[0][field]
            with self.assertRaises(ValueError):self.make()
        self.tasks=[task('A',kind='verification',evidence_level='CODE_MERGED')]
        with self.assertRaises(ValueError):self.make()
        self.tasks=[task('A',kind='foundation',evidence_level='SANDBOX_QUALIFIED_ONLY')]
        with self.assertRaises(ValueError):self.make()
    def ledger_snapshot(self):
        with contextlib.closing(sqlite3.connect(self.path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
            schema=db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
            tasks=db.execute('SELECT * FROM tasks ORDER BY key').fetchall()
            metadata=db.execute('SELECT * FROM metadata ORDER BY key').fetchall()
        return self.path.read_bytes(),schema,tasks,metadata,self.path.stat().st_mode
    def test_unmarked_reference_ledger_is_rejected_without_any_mutation(self):
        for active in (False,True):
            self.path=Path(self.tmp.name)/('legacy-active.sqlite3' if active else 'legacy-idle.sqlite3')
            legacy=_REFERENCE.Scheduler(self.path,self.tasks,self.pol,clock=lambda:self.now[0])
            if active:legacy.claim('synthetic-old-worker',BASE,'A')
            before=self.ledger_snapshot()
            with patch.object(_REFERENCE.Scheduler,'__init__',side_effect=RuntimeError('must not initialize')) as initialize:
                with self.assertRaises(ValueError):self.make()
                initialize.assert_not_called()
            self.assertEqual(before,self.ledger_snapshot())
            self.assertEqual(legacy.record('A')['state'],'RUNNING' if active else 'BACKLOG')
    def test_existing_empty_file_is_not_silently_initialized(self):
        self.path.write_bytes(b'')
        with patch.object(_REFERENCE.Scheduler,'__init__',side_effect=RuntimeError('must not initialize')) as initialize:
            with self.assertRaises(ValueError):self.make()
            initialize.assert_not_called()
        self.assertEqual(self.path.read_bytes(),b'')
    def test_old_or_missing_wrapper_version_rejected_without_mutation(self):
        for bad_version in (None,'unsupported-version'):
            self.path=Path(self.tmp.name)/('missing-version.sqlite3' if bad_version is None else 'wrong-version.sqlite3')
            self.make()
            with contextlib.closing(sqlite3.connect(self.path)) as db:
                if bad_version is None:db.execute("DELETE FROM metadata WHERE key='f11_schema_version'")
                else:db.execute("UPDATE metadata SET value=? WHERE key='f11_schema_version'",(bad_version,))
                db.commit()
            before=self.ledger_snapshot()
            with self.assertRaises(ValueError):self.make()
            self.assertEqual(before,self.ledger_snapshot())
    def test_new_versioned_ledger_reopens_and_preserves_active_attempt(self):
        s=self.make();p=self.claim(s)
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='f11_schema_version'").fetchone()[0],F11_SCHEMA_VERSION)
        reopened=self.make()
        self.assertEqual(reopened.record('A')['state'],'RUNNING')
        self.assertEqual(reopened.record('A')['fence'],p['fence'])
        self.assertIsNone(self.claim(reopened))
    def directory_bytes(self, ignore_shm=False):
        # No SQLite connection here: even the test observer must not make SHM.
        return {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.path.parent.iterdir() if p.is_file() and not (ignore_shm and p.name.endswith('-shm'))}

    def detached_wal(self, marked):
        source = self.path.parent / 'wal-source.sqlite3'
        if marked:
            LocalController(source,self.tasks,self.pol,clock=lambda:self.now[0],fixture_only=True)
        else:
            _REFERENCE.Scheduler(source,self.tasks,self.pol,clock=lambda:self.now[0])
        db=sqlite3.connect(source)
        db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute("INSERT INTO metadata VALUES ('synthetic_wal_value','committed')")
        if marked:
            db.execute("UPDATE metadata SET value='offline-fixture' WHERE key='f11_mode'")
        db.commit()
        self.path.write_bytes(source.read_bytes())
        Path(str(self.path)+'-wal').write_bytes(Path(str(source)+'-wal').read_bytes())
        self.addCleanup(db.close)
        return db

    def test_rejected_wal_without_shm_preserves_all_directory_bytes(self):
        self.detached_wal(False)
        before=self.directory_bytes()
        with self.assertRaises(ValueError):self.make()
        self.assertEqual(before,self.directory_bytes())
        self.assertFalse(Path(str(self.path)+'-shm').exists())

    def test_rejected_wal_with_existing_shm_preserves_it(self):
        self.detached_wal(False)
        Path(str(self.path)+'-shm').write_bytes(b'synthetic-existing-index-must-not-be-touched')
        before=self.directory_bytes()
        with self.assertRaises(ValueError):self.make()
        self.assertEqual(before,self.directory_bytes())

    def test_markers_committed_only_in_wal_are_visible(self):
        self.make()
        db=sqlite3.connect(self.path)
        self.addCleanup(db.close)
        db.execute("UPDATE metadata SET value='wrong' WHERE key='f11_mode'");db.commit()
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.execute("UPDATE metadata SET value='offline-fixture' WHERE key='f11_mode'");db.commit()
        before=self.directory_bytes()
        preflight_existing_ledger(self.path,True)
        self.assertEqual(before,self.directory_bytes())

    def test_incompatible_marker_committed_in_wal_is_not_ignored(self):
        self.make()
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        db.execute("UPDATE metadata SET value='wrong' WHERE key='f11_mode'");db.commit()
        before=self.directory_bytes()
        with self.assertRaises(ValueError):preflight_existing_ledger(self.path,True)
        self.assertEqual(before,self.directory_bytes())

    def test_uncommitted_marker_does_not_override_committed_snapshot(self):
        self.make()
        db=sqlite3.connect(self.path);self.addCleanup(db.close)
        db.execute("UPDATE metadata SET value='wrong' WHERE key='f11_mode'")
        before=self.directory_bytes(ignore_shm=True)
        preflight_existing_ledger(self.path,True)
        self.assertEqual(before,self.directory_bytes(ignore_shm=True))

    def test_tiny_snapshot_read_requests_are_bounded_by_observed_size(self):
        from local import read_ledger_files
        self.make()
        original = Path.open
        requests = []
        class ObservedStream:
            def __init__(self, stream, size): self.stream, self.size = stream, size
            def __enter__(self): self.stream.__enter__(); return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def read(self, amount):
                requests.append(amount)
                self_test.assertLessEqual(amount, min(64*1024, self.size+1))
                return self.stream.read(amount)
        self_test = self
        def observed(path, *args, **kwargs):
            stream = original(path, *args, **kwargs)
            return ObservedStream(stream, path.stat().st_size)
        with patch.object(Path, 'open', observed):
            captured = read_ledger_files(self.path)
        self.assertTrue(requests)
        self.assertEqual(captured[''], self.path.read_bytes())

    def test_transient_snapshot_change_retries_without_source_sqlite(self):
        from local import SnapshotChanged
        with patch('local.read_ledger_files',side_effect=[SnapshotChanged('synthetic change'), {'':b'stable'}, {'':b'stable'}]) as read:
            self.assertEqual(stable_ledger_copy(self.path),{'':b'stable'})
            self.assertEqual(read.call_count,3)

    def test_changing_snapshot_fails_closed_after_bounded_retries(self):
        with patch('local.PREFLIGHT_ATTEMPTS',3), patch('local.read_ledger_files',side_effect=[{'': bytes([n])} for n in range(6)]) as read:
            with self.assertRaises(ValueError):stable_ledger_copy(self.path)
            self.assertEqual(read.call_count,6)

    def test_stop_prevents_dispatch_and_preserves_active(self):
        s=self.make();p=self.claim(s);s.stop('synthetic-stop');self.assertIsNone(self.claim(s));self.assertEqual(s.record('A')['state'],'RUNNING')

if __name__=='__main__':unittest.main(verbosity=2)
