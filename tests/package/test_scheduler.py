import concurrent.futures,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from scheduler import Scheduler,validate_graph,path_owned,scopes_conflict,safe_relative
from demo_parallel import result,run_demo

def task(k,deps=(),scope=None,manual=False,enabled=True,cpu=1,locks=()):
    return {'key':k,'depends_on':list(deps),'write_paths':[scope or f'src/{k}/'],'resources':{'cpu':cpu,'memory_mib':64,'gpu':0,'slots':1,'integration':0},
            'locks':list(locks),'manual':manual,'enabled_by_default':enabled,'priority':'P1'}

def policy(workers=4):
    return {'max_workers':workers,'capacities':{'cpu':workers,'memory_mib':workers*128,'gpu':0,'slots':workers,'integration':1},
            'lease_seconds':10,'max_attempts':2,'max_cost_per_task_usd':1.0,'total_cost_budget_usd':20.0}

class SchedulerTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.now=[1000.0]
    def make(self,tasks=None,pol=None):
        return Scheduler(Path(self.tmp.name)/'state.sqlite3',tasks or [task('A')],pol or policy(),clock=lambda:self.now[0])
    def accept(self,s,p):
        s.finish(result(p),trusted_cost=0)
        s.accept(p['task_key'],{'task_key':p['task_key'],'verified_by':'independent','independent_review':True,'checks_verified':True,
                 'revision':'a'*40,'graph_sha256':s.graph_hash,'evidence_level':'CODE_MERGED','source':'unit-test-trusted-receipt'})
    def test_initial_frontier(self):
        s=self.make([task('A'),task('B',['A'])]);self.assertEqual(s.status()['ready'],['A'])
    def test_dependency_waits_for_acceptance(self):
        s=self.make([task('A'),task('B',['A'])]);p=s.claim('author','a'*40);s.finish(result(p),trusted_cost=0)
        self.assertEqual(s.status()['ready'],[]);self.assertEqual(s.status()['counts']['REVIEW'],1)
    def test_unlock_after_acceptance(self):
        s=self.make([task('A'),task('B',['A'])]);p=s.claim('author','a'*40);self.accept(s,p);self.assertEqual(s.status()['ready'],['B'])
    def test_atomic_competing_claim(self):
        s=self.make()
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:claims=list(pool.map(lambda n:s.claim(f'a{n}','a'*40),range(12)))
        self.assertEqual(sum(x is not None for x in claims),1)
    def test_capacity_bound(self):
        s=self.make([task(str(i)) for i in range(10)],policy(2))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:claims=list(pool.map(lambda n:s.claim(str(n),'a'*40),range(10)))
        self.assertEqual(sum(x is not None for x in claims),2);self.assertEqual(s.status()['resources_reserved']['cpu'],2)
    def test_path_lock_conflicts(self):
        s=self.make([task('A',scope='src/shared/'),task('B',scope='src/shared/nested/')]);self.assertIsNotNone(s.claim('a','a'*40));self.assertIsNone(s.claim('b','a'*40))
    def test_sibling_scopes_parallel(self):
        s=self.make([task('A',scope='src/one/'),task('B',scope='src/two/')]);self.assertIsNotNone(s.claim('a','a'*40));self.assertIsNotNone(s.claim('b','a'*40))
    def test_explicit_lock(self):
        s=self.make([task('A',locks=['migration']),task('B',locks=['migration'])]);s.claim('a','a'*40);self.assertIsNone(s.claim('b','a'*40))
    def test_orphan_retains_capacity(self):
        s=self.make([task('A'),task('B')],policy(1));s.claim('a','a'*40);self.now[0]+=11
        self.assertEqual(s.status()['counts']['ORPHANED'],1);self.assertIsNone(s.claim('b','a'*40))
    def test_stale_heartbeat_rejected(self):
        s=self.make();p=s.claim('a','a'*40);self.now[0]+=11
        with self.assertRaises(ValueError):s.heartbeat(p['task_key'],p['lease_token'],p['fence'])
    def test_stale_result_rejected(self):
        s=self.make();p=s.claim('a','a'*40);self.now[0]+=11
        with self.assertRaises(ValueError):s.finish(result(p))
    def test_orphan_needs_positive_proof(self):
        s=self.make();s.claim('a','a'*40);self.now[0]+=11;s.status()
        with self.assertRaises(ValueError):s.reconcile_orphan('A',{'terminated':True},True)
    def test_fence_increases_after_safe_retry(self):
        s=self.make();p=s.claim('a','a'*40);self.now[0]+=11;s.status()
        s.reconcile_orphan('A',{'terminated':True,'effects_reconciled':True,'verified_by':'operator','evidence_ref':'kill-proof'},True,0)
        p2=s.claim('b','a'*40);self.assertGreater(p2['fence'],p['fence'])
        with self.assertRaises(ValueError):s.finish(result(p))
    def test_manual_and_deferred_not_dispatched(self):
        s=self.make([task('A',manual=True),task('B',enabled=False)]);self.assertIsNone(s.claim('a','a'*40))
    def test_no_self_accept(self):
        s=self.make();p=s.claim('author','a'*40);s.finish(result(p),trusted_cost=0)
        with self.assertRaises(ValueError):s.accept('A',{'task_key':'A','verified_by':'author','independent_review':True,'checks_verified':True,'revision':'a'*40,'graph_sha256':s.graph_hash,'evidence_level':'CODE_MERGED','source':'test'})
    def test_result_scope_rejected(self):
        s=self.make();p=s.claim('a','a'*40);r=result(p);r['changed_paths']=['.github/workflows/evil.yml']
        with self.assertRaises(ValueError):s.finish(r)
    def test_input_hash_binding(self):
        s=self.make();p=s.claim('a','a'*40);r=result(p);r['input_sha256']='0'*64
        with self.assertRaises(ValueError):s.finish(r)
    def test_stop_prevents_new_claim(self):
        s=self.make();s.stop('test');self.assertIsNone(s.claim('a','a'*40))
    def test_unknown_usage_charges_reservation(self):
        s=self.make();p=s.claim('a','a'*40);s.finish(result(p));self.assertEqual(s.status()['spent_usd'],1)
    def test_cost_overrun_stops_dispatch(self):
        s=self.make([task('A'),task('B')]);p=s.claim('a','a'*40);s.finish(result(p),trusted_cost=2);self.assertTrue(s.status()['stopped'])
    def test_budget_limits_claims(self):
        p=policy();p['total_cost_budget_usd']=1;s=self.make([task('A'),task('B')],p);s.claim('a','a'*40);self.assertIsNone(s.claim('b','a'*40))
    def test_restart_preserves_lease(self):
        tasks=[task('A')];s=self.make(tasks);s.claim('a','a'*40);s2=self.make(tasks);self.assertIsNone(s2.claim('b','a'*40))
    def test_graph_change_rejected(self):
        self.make([task('A')])
        with self.assertRaises(ValueError):self.make([task('A'),task('B')])
    def test_policy_change_rejected(self):
        self.make()
        with self.assertRaises(ValueError):self.make(pol=policy(2))
    def test_cycle_rejected(self):
        with self.assertRaises(ValueError):validate_graph([task('A',['B']),task('B',['A'])])
    def test_unknown_dependency_rejected(self):
        with self.assertRaises(ValueError):validate_graph([task('A',['MISSING'])])
    def test_path_traversal_rejected(self):
        for value in ['../x','/etc/passwd','a/../../x','a/.git/config','C:\\file']:
            with self.assertRaises(ValueError):safe_relative(value)
    def test_exact_file_scope(self):
        self.assertTrue(path_owned('src/a.py',['src/a.py']));self.assertFalse(path_owned('src/a.py/evil',['src/a.py']))
    def test_prefix_not_string_prefix(self):self.assertFalse(scopes_conflict(['src/a/'],['src/ab/']))
    def test_demo_parallel(self):
        d=run_demo(4);self.assertTrue(d['all_completed']);self.assertGreater(d['observed_peak_parallel_mock_workers'],1);self.assertEqual(d['ai_agents_launched'],0)
if __name__=='__main__':unittest.main()
