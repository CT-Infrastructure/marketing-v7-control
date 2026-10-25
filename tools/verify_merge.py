#!/usr/bin/env python3
"""Read-only GitHub merge verifier; no merge, acceptance or GitHub mutation.

Run on the trusted controller with a narrow read identity. A receipt covers
CODE_MERGED only. F13/F18 must qualify receipt ingestion into Scheduler.accept;
verification/production tasks require independent execution/human evidence.
"""
from __future__ import annotations
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
from scheduler import canonical_hash,path_owned
ROOT=Path(__file__).resolve().parents[1]

class VerificationError(ValueError):pass

def verify_records(task:dict,policy:dict,pr:dict,files:list,reviews:list,checks:list,comparison:dict)->dict:
    repo=policy.get('repository','');head=policy.get('expected_head_sha','')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or not re.fullmatch(r'[a-f0-9]{40}',head):raise VerificationError('Explicit repository and trusted candidate head SHA required')
    if not policy.get('required_checks') or not policy.get('reviewer_logins') or not policy.get('verified_by'):raise VerificationError('Trusted check-app IDs, reviewers and verifier identity must be configured')
    if task.get('kind') in ['verification','integration','human-gate','selection'] or task.get('manual'):raise VerificationError('A merged PR cannot establish runtime qualification or human approval')
    if not pr.get('merged') or not pr.get('merge_commit_sha') or pr.get('draft'):raise VerificationError('PR has not been merged')
    if pr['base']['repo']['full_name']!=repo or pr['base']['ref']!=policy.get('base_branch','main') or pr['head']['sha']!=head:raise VerificationError('PR repository/base/head mismatch')
    if f"Task-Key: {task['key']}" not in (pr.get('body') or ''):raise VerificationError('PR lacks reviewed task-key binding')
    expected_input=policy.get('expected_input_sha256','')
    if not re.fullmatch('[a-f0-9]{64}',expected_input) or f'Input-SHA256: {expected_input}' not in (pr.get('body') or ''):raise VerificationError('PR lacks trusted packet hash binding')
    if len(files)!=pr.get('changed_files') or len(files)>=3000:raise VerificationError('Incomplete or oversized file listing')
    for f in files:
        for name in [f['filename']]+([f['previous_filename']] if f.get('previous_filename') else []):
            if not path_owned(name,task.get('write_paths',[])):raise VerificationError('PR changes a path outside task scope')
    # Latest decisive review from each identity at this head; a later changes-request blocks.
    latest={}
    for r in sorted(reviews,key=lambda r:r.get('submitted_at') or ''):
        if r.get('state') in ['APPROVED','CHANGES_REQUESTED','DISMISSED']:
            latest[r['user']['login']]=r
    author=pr['user']['login'];allowed=set(policy['reviewer_logins'])-{author}
    approvals={u for u,r in latest.items() if u in allowed and r.get('state')=='APPROVED' and r.get('commit_id')==head}
    if any(r.get('state')=='CHANGES_REQUESTED' for u,r in latest.items() if u in allowed):raise VerificationError('Outstanding trusted changes-request')
    if len(approvals)<int(policy.get('minimum_approvals',1)):raise VerificationError('Insufficient independent exact-head approvals')
    if task.get('risk') in ['high','critical']:
        humans=set(policy.get('security_reviewer_logins',[]))
        if not (approvals & humans):raise VerificationError('High-risk task requires named security reviewer approval')
    for rule in policy['required_checks']:
        matches=[c for c in checks if c.get('name')==rule['name'] and c.get('app',{}).get('id')==rule['app_id'] and c.get('head_sha')==head]
        if not matches:raise VerificationError('Required check from trusted app missing')
        newest=max(matches,key=lambda c:c.get('id',0))
        if newest.get('status')!='completed' or newest.get('conclusion')!='success':raise VerificationError('Required check not successful')
    if comparison.get('status') not in ['ahead','identical']:raise VerificationError('Merge commit no longer belongs to current target branch history')
    return {'task_key':task['key'],'verified_by':policy['verified_by'],'independent_review':True,'checks_verified':True,
            'revision':pr['merge_commit_sha'],'candidate_revision':head,'evidence_level':'CODE_MERGED','source':'verified-github-merge',
            'input_sha256':expected_input,'reviewers':sorted(approvals),'pull_request':pr['number'],
            'repository':repo,'limitations':'Does not attest sandbox, staging, production, environment protections or live service acceptance.'}

class ReadGitHub:
    def get(self,path,paginate=False):
        args=['gh','api','--hostname','github.com','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2026-03-10',path]
        if paginate:args+=['--paginate','--slurp']
        r=subprocess.run(args,check=True,text=True,capture_output=True,timeout=90)
        result=json.loads(r.stdout)
        return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--task',required=True);p.add_argument('--pr',type=int,required=True);p.add_argument('--policy',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();policy=json.loads(Path(a.policy).read_text());graph=json.loads((ROOT/'orchestration/task_graph.json').read_text())['tasks'];task=next(t for t in graph if t['key']==a.task)
    repo=policy.get('repository','')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or a.pr<=0:raise VerificationError('Invalid explicit destination')
    gh=ReadGitHub();prefix=f'repos/{repo}';pr=gh.get(f'{prefix}/pulls/{a.pr}')
    files=[x for page in gh.get(f'{prefix}/pulls/{a.pr}/files?per_page=100',True) for x in page]
    reviews=[x for page in gh.get(f'{prefix}/pulls/{a.pr}/reviews?per_page=100',True) for x in page]
    head=pr['head']['sha'];checks=[x for page in gh.get(f'{prefix}/commits/{head}/check-runs?filter=latest&per_page=100',True) for x in page['check_runs']]
    branch=pr['base']['ref']
    from urllib.parse import quote
    comparison=gh.get(f"{prefix}/compare/{pr['merge_commit_sha']}...{quote(branch,safe='')}")
    receipt=verify_records(task,policy,pr,files,reviews,checks,comparison);receipt['graph_sha256']=canonical_hash(graph)
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'verified':'CODE_MERGED','task':a.task,'receipt':str(out),'accepted_by_scheduler':False}))
if __name__=='__main__':
    try:main()
    except (VerificationError,StopIteration,subprocess.SubprocessError,KeyError) as e:print('Verification failed: '+str(e),file=sys.stderr);raise SystemExit(1)
