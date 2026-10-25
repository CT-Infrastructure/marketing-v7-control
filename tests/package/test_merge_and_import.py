import json,tempfile,unittest,sys,copy
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from verify_merge import verify_records,VerificationError
from seed_github import GitHub,Paused,APIError

class MergeTests(unittest.TestCase):
 def setUp(self):
  self.task={'key':'T1','kind':'implementation','risk':'high','write_paths':['src/t1/']}
  self.policy={'repository':'example/private','expected_head_sha':'a'*40,'expected_input_sha256':'b'*64,'verified_by':'trusted-controller','reviewer_logins':['human-reviewer'],'security_reviewer_logins':['human-reviewer'],'required_checks':[{'name':'tests','app_id':123}]}
  self.pr={'merged':True,'merge_commit_sha':'c'*40,'draft':False,'number':1,'changed_files':1,'user':{'login':'author'},'base':{'repo':{'full_name':'example/private'},'ref':'main'},'head':{'sha':'a'*40},'body':'Task-Key: T1\nInput-SHA256: '+'b'*64}
  self.files=[{'filename':'src/t1/file.py'}]
  self.reviews=[{'user':{'login':'human-reviewer'},'state':'APPROVED','commit_id':'a'*40,'submitted_at':'2026-10-25T00:00:00Z'}]
  self.checks=[{'name':'tests','app':{'id':123},'head_sha':'a'*40,'status':'completed','conclusion':'success','id':1}]
 def verify(self):return verify_records(self.task,self.policy,self.pr,self.files,self.reviews,self.checks,{'status':'ahead'})
 def test_valid_exact_head(self):self.assertEqual(self.verify()['evidence_level'],'CODE_MERGED')
 def test_unmerged_rejected(self):
  self.pr['merged']=False
  with self.assertRaises(VerificationError):self.verify()
 def test_stale_review_rejected(self):
  self.reviews[0]['commit_id']='d'*40
  with self.assertRaises(VerificationError):self.verify()
 def test_wrong_check_app_rejected(self):
  self.checks[0]['app']['id']=456
  with self.assertRaises(VerificationError):self.verify()
 def test_later_failed_check_rejected(self):
  newer=copy.deepcopy(self.checks[0]);newer.update(id=2,conclusion='failure');self.checks.append(newer)
  with self.assertRaises(VerificationError):self.verify()
 def test_self_review_rejected(self):
  self.pr['user']['login']='human-reviewer'
  with self.assertRaises(VerificationError):self.verify()
 def test_scope_rename_rejected(self):
  self.files[0]['previous_filename']='.github/workflows/ci.yml'
  with self.assertRaises(VerificationError):self.verify()
 def test_missing_files_rejected(self):
  self.pr['changed_files']=2
  with self.assertRaises(VerificationError):self.verify()
 def test_execution_not_proven_by_pr(self):
  self.task['kind']='verification'
  with self.assertRaises(VerificationError):self.verify()
 def test_input_binding_rejected(self):
  self.pr['body']='Task-Key: T1'
  with self.assertRaises(VerificationError):self.verify()
 def test_security_review_required(self):
  self.policy['security_reviewer_logins']=[]
  with self.assertRaises(VerificationError):self.verify()

class ImportTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.gh=GitHub({'owner':'example','repository':'private','mutation_delay_seconds':0,'maximum_mutations_per_run':2},Path(self.tmp.name)/'journal.json')
 def test_ambiguous_create_not_replayed(self):
  with patch('seed_github.subprocess.run',side_effect=OSError('down')):
   with self.assertRaises(APIError):self.gh.call(['api','test'],{},mutation='issue:create:T1')
  self.assertEqual(self.gh.state['pending']['key'],'issue:create:T1')
  with self.assertRaises(Paused):self.gh.call(['api','test'],{},mutation='issue:create:T1')
 def test_readback_adoption_clears_pending(self):
  self.gh.state['pending']={'key':'issue:create:T1'};self.gh.adopt('wrong');self.assertIsNotNone(self.gh.state['pending']);self.gh.adopt('issue:create:T1');self.assertIsNone(self.gh.state['pending'])
 def test_graphql_errors_remain_pending(self):
  with patch('seed_github.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='{"errors":[{"message":"unknown"}]}',stderr='')):
   with self.assertRaises(APIError):self.gh.graphql('mutation{}',key='test')
  self.assertEqual(self.gh.state['pending']['key'],'test')
 def test_budget_pause_does_not_write(self):
  self.gh.count=2
  with patch('seed_github.subprocess.run') as run:
   with self.assertRaises(Paused):self.gh.call(['api','test'],{},mutation='test')
   run.assert_not_called()
if __name__=='__main__':unittest.main()

class SourceRevisionTests(unittest.TestCase):
 def invoke(self,state='ACCEPTED',revision='a'*40,returncode=0):
  from run_agents import source_contains_prerequisites
  s=SimpleNamespace(tasks={'T':{'depends_on':['D']}},record=lambda _: {'state':state,'receipt':json.dumps({'revision':revision})})
  with patch('run_agents.subprocess.run',return_value=SimpleNamespace(returncode=returncode)):
   return source_contains_prerequisites(Path('/trusted'), 'b'*40,s,'T')
 def test_accepted_ancestor_allows_dispatch(self):self.assertTrue(self.invoke())
 def test_stale_source_holds_dispatch(self):self.assertFalse(self.invoke(returncode=1))
 def test_unaccepted_dependency_holds_dispatch(self):self.assertFalse(self.invoke(state='REVIEW'))
 def test_nonrevision_receipt_holds_dispatch(self):self.assertFalse(self.invoke(revision='claimed-pass'))
