#!/usr/bin/env python3
"""Plan or incrementally seed an explicitly approved private GitHub destination.

Default is local plan only. Real mutations use existing gh authentication, a
single-writer journal, stable markers, pagination and bounded pacing. No tokens
are accepted as arguments. Source upload, live deployment and policy bypass are
intentionally not implemented here.
"""
from __future__ import annotations
import argparse, fcntl, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
from urllib.parse import quote
ROOT=Path(__file__).resolve().parents[1]

class Paused(RuntimeError):pass
class APIError(RuntimeError):pass

def atomic_json(path: Path, value: dict):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=path.with_suffix('.tmp')
    with tmp.open('w') as f:
        os.chmod(tmp,0o600);json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)

def preserve_human_notes(existing: str, generated: str) -> str:
    begin='<!-- BEGIN V7 GENERATED -->';end='<!-- END V7 GENERATED -->'
    if existing.count(begin)!=1 or existing.count(end)!=1:raise ValueError('Managed issue lacks unambiguous generated-region markers')
    a,b=existing.index(begin),existing.index(end)+len(end)
    c,d=generated.index(begin),generated.index(end)+len(end)
    return existing[:a]+generated[c:d]+existing[b:]

def validate_destination(config: dict, apply: bool):
    if config.get('visibility')!='private':raise ValueError('This package only seeds private repositories')
    if apply:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}',config.get('owner') or ''):raise ValueError('Explicit valid GitHub owner required')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',config.get('repository') or ''):raise ValueError('Explicit valid repository name required')
        if not config.get('source_reviewed') or not config.get('private_access_reviewed'):raise ValueError('Source/disclosure and private access review required')
        if config.get('native_relationships') not in ['required','manifest-only']:raise ValueError('Relationship mode must be explicit')

class GitHub:
    def __init__(self, config: dict, journal: Path):
        self.cfg=config;self.path=journal;self.count=0;self.last=0.0
        self.target=f"{config['owner']}/{config['repository']}"
        self.state=json.loads(journal.read_text()) if journal.exists() else {'target':self.target,'issues':{},'project':None,'field_values':{},'relations':{},'history':[],'pending':None}
        if self.state['target']!=self.target:raise ValueError('Journal belongs to a different repository')
    def save(self):atomic_json(self.path,self.state)
    def adopt(self,key):
        if self.state.get('pending',{} ) and self.state['pending'].get('key')==key:
            self.state['pending']=None;self.save()
    def call(self,args: list[str],payload: dict|None=None,mutation: str|None=None):
        if mutation:
            if self.state.get('pending'):raise Paused('Unresolved prior mutation; reconcile its remote result before any further write: '+self.state['pending']['key'])
            now=time.time();self.state['history']=[t for t in self.state.get('history',[]) if now-t<3600]
            if self.count>=int(self.cfg.get('maximum_mutations_per_run',100)):raise Paused('Per-run mutation budget reached; rerun to reconcile/resume')
            if len(self.state['history'])>=int(self.cfg.get('maximum_mutations_per_hour',300)):raise Paused('Local hourly mutation budget reached; retain journal and resume only after budget recovers')
            time.sleep(max(0,float(self.cfg.get('mutation_delay_seconds',1.2))-(time.monotonic()-self.last)))
            self.state['pending']={'key':mutation,'started_at':time.time(),'request_sha256':hashlib.sha256(json.dumps([args,payload],sort_keys=True).encode()).hexdigest()};self.save()
        command=['gh',*args]
        try:
            r=subprocess.run(command,input=json.dumps(payload) if payload is not None else None,text=True,capture_output=True,timeout=90)
        except (OSError,subprocess.TimeoutExpired) as e:
            raise APIError('GitHub command outcome uncertain; read-back required before retry') from e
        if r.returncode:
            # Keep failed/unknown mutation journal. Never blindly replay a create.
            match=re.search(r'HTTP (\d{3})',r.stderr)
            code=match.group(1) if match else 'unknown'
            raise APIError(f'GitHub command failed (HTTP {code}); inspect privately, respect Retry-After, and reconcile pending writes. No automatic mutation retry.')
        if mutation:
            self.last=time.monotonic();self.count+=1;self.state['history'].append(time.time());self.state['pending']=None;self.save()
        if not r.stdout.strip():return None
        try:return json.loads(r.stdout)
        except json.JSONDecodeError as e:raise APIError('Non-JSON GitHub response; read-back required') from e
    def api(self,path: str,method='GET',data=None,key=None,paginate=False):
        args=['api','--hostname','github.com','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: '+self.cfg.get('api_version','2026-03-10'),'-X',method,path]
        if data is not None:args+=['--input','-']
        if paginate:args+=['--paginate','--slurp']
        value=self.call(args,data,mutation=key)
        if paginate:return [entry for page in value for entry in page]
        return value
    def graphql(self,query,variables=None,key=None):
        value=self.call(['api','--hostname','github.com','graphql','--input','-'],{'query':query,'variables':variables or {}},mutation=key)
        if value.get('errors'):
            if key:
                self.state['pending']={'key':key,'started_at':time.time(),'graphql_error':True};self.save()
            raise APIError('GraphQL reported errors; inspect/read back instead of assuming success')
        return value['data']


def project_fields(gh,project_id):
    q='query($id:ID!){node(id:$id){... on ProjectV2{fields(first:100){nodes{... on ProjectV2Field{id name dataType} ... on ProjectV2SingleSelectField{id name dataType options{id name}}}}}}}'
    return {f['name']:f for f in gh.graphql(q,{'id':project_id})['node']['fields']['nodes'] if f}

def project_items(gh,project_id):
    q='query($id:ID!,$after:String){node(id:$id){... on ProjectV2{items(first:100,after:$after){nodes{id content{... on Issue{id}}} pageInfo{endCursor hasNextPage}}}}}'
    out={};cursor=None
    while True:
        page=gh.graphql(q,{'id':project_id,'after':cursor})['node']['items']
        for item in page['nodes']:
            if item.get('content',{}):out[item['content']['id']]=item['id']
        if not page['pageInfo']['hasNextPage']:return out
        cursor=page['pageInfo']['endCursor']

def ensure_project(gh,owner_info,model,repo):
    owner=gh.cfg['owner'];project=gh.state.get('project');number=gh.cfg.get('project_number')
    owner_kind='organization' if owner_info['type']=='Organization' else 'user'
    if number:
        q=f'query($owner:String!,$number:Int!){{{owner_kind}(login:$owner){{projectV2(number:$number){{id number title public url shortDescription}}}}}}'
        project=gh.graphql(q,{'owner':owner,'number':int(number)})[owner_kind]['projectV2']
        if not project:raise APIError('Explicit project number not accessible')
    if not project:
        q=f'query($owner:String!,$after:String){{{owner_kind}(login:$owner){{projectsV2(first:100,after:$after){{nodes{{id number title public url shortDescription}} pageInfo{{hasNextPage endCursor}}}}}}}}'
        candidates=[];cursor=None
        while True:
            page=gh.graphql(q,{'owner':owner,'after':cursor})[owner_kind]['projectsV2']
            candidates += [x for x in page['nodes'] if x['title']==gh.cfg['project_title']]
            if not page['pageInfo']['hasNextPage']:break
            cursor=page['pageInfo']['endCursor']
        if candidates:
            if len(candidates)!=1 or 'marketing-v7-agent-package' not in (candidates[0].get('shortDescription') or ''):
                raise Paused('Project-title match is ambiguous/unmanaged. Read back and set explicit project_number; do not create another project.')
            project=candidates[0];gh.adopt('project:create')
        else:
            if not gh.cfg.get('allow_project_create'):raise Paused('Project creation not authorized')
            data=gh.graphql('mutation($owner:ID!,$title:String!){createProjectV2(input:{ownerId:$owner,title:$title}){projectV2{id number title public url}}}',{'owner':owner_info['node_id'],'title':gh.cfg['project_title']},key='project:create')
            project=data['createProjectV2']['projectV2']
    gh.state['project']=project;gh.save();gh.adopt('project:create')
    if not gh.state.get('project_configured'):
        gh.graphql('mutation($id:ID!,$description:String!){updateProjectV2(input:{projectId:$id,public:false,shortDescription:$description}){projectV2{id public}}}',{'id':project['id'],'description':'marketing-v7-agent-package — engineering only; production remains held.'},key='project:private')
        gh.graphql('mutation($project:ID!,$repo:ID!){linkProjectV2ToRepository(input:{projectId:$project,repositoryId:$repo}){repository{id}}}',{'project':project['id'],'repo':repo['node_id']},key='project:link')
        check=gh.graphql('query($id:ID!){node(id:$id){... on ProjectV2{id public number url}}}',{'id':project['id']})['node']
        if check['public']:raise APIError('Project privacy read-back failed')
        gh.state['project_configured']=True;gh.save()
    fields=project_fields(gh,project['id'])
    for f in model['fields']:
        key='field:'+f['name']
        if f['name'] in fields:
            gh.adopt(key)
            actual=fields[f['name']]
            if actual.get('dataType')!=f['type']:raise Paused('Existing project field has incompatible type: '+f['name'])
            if f['type']=='SINGLE_SELECT' and not set(f['options']).issubset({o['name'] for o in actual.get('options',[])}):raise Paused('Existing field options differ; review manually: '+f['name'])
            continue
        args=['project','field-create',str(project['number']),'--owner',owner,'--name',f['name'],'--data-type',f['type'],'--format','json']
        if f['type']=='SINGLE_SELECT':args+=['--single-select-options',','.join(f['options'])]
        gh.call(args,mutation=key);fields=project_fields(gh,project['id'])
    return project,fields


def seed(gh,issues,model,limit):
    who=gh.api('/user');owner=gh.api('/users/'+gh.cfg['owner'])
    target=gh.target
    try:repo=gh.api('/repos/'+target)
    except APIError as exc:
        # A missing repository and an inaccessible one are not automatically equivalent.
        if 'HTTP 404' not in str(exc) or not gh.cfg.get('allow_repository_create'):raise
        data={'name':gh.cfg['repository'],'private':True,'auto_init':True,'description':model['description'],'has_issues':True,'has_wiki':False}
        if owner['type']=='Organization':path='/orgs/'+gh.cfg['owner']+'/repos'
        elif who['login'].lower()==gh.cfg['owner'].lower():path='/user/repos'
        else:raise ValueError('Cannot create a repository in another personal account')
        gh.api(path,'POST',data,key='repository:create');repo=gh.api('/repos/'+target)
    gh.adopt('repository:create')
    if not repo.get('private'):raise ValueError('Existing repository is not private; refusing to change or publish to it')
    if not repo.get('permissions',{}).get('admin'):raise ValueError('Bootstrap requires verified administrative repository access; worker tokens are unsuitable')
    labels={x['name']:x for x in gh.api('/repos/'+target+'/labels?per_page=100',paginate=True)}
    for label in model['labels']:
        key='label:'+label['name']
        if label['name'] in labels:gh.adopt(key);continue
        gh.api('/repos/'+target+'/labels','POST',label,key=key)
    milestones={x['title']:x for x in gh.api('/repos/'+target+'/milestones?state=all&per_page=100',paginate=True)}
    for milestone in model['milestones']:
        key='milestone:'+milestone['title']
        if milestone['title'] in milestones:gh.adopt(key);continue
        milestones[milestone['title']]=gh.api('/repos/'+target+'/milestones','POST',milestone,key=key)
    all_remote=gh.api('/repos/'+target+'/issues?state=all&per_page=100',paginate=True)
    remote={};pattern=re.compile(r'<!-- v7-agent-package:([A-Z0-9-]+) -->')
    for r in all_remote:
        if 'pull_request' in r:continue
        matches=pattern.findall(r.get('body') or '')
        if len(matches)>1:raise ValueError('Multiple package markers in one remote issue')
        if matches:
            key=matches[0]
            if key in remote:raise ValueError('Duplicate stable package key on GitHub: '+key)
            remote[key]=r
    selected=issues[:limit] if limit else issues
    for spec in selected:
        key=spec['key'];body=(ROOT/spec['body_path']).read_text()
        labels=['type:'+spec['kind'],'risk:'+spec['risk'],'priority:'+spec['priority']]
        if spec['kind']=='human-gate':labels.append('manual-gate')
        if not spec['enabled_by_default']:labels.append('deferred')
        if key in remote:
            gh.adopt('issue:create:'+key)
            old=remote[key];merged=preserve_human_notes(old['body'],body)
            desired_labels=sorted(set(labels)|{x['name'] for x in old.get('labels',[])})
            if merged!=old['body'] or old['title']!=spec['title'] or set(desired_labels)!={x['name'] for x in old.get('labels',[])}:
                old=gh.api(f"/repos/{target}/issues/{old['number']}",'PATCH',{'title':spec['title'],'body':merged,'labels':desired_labels},key='issue:update:'+key);remote[key]=old
        else:
            remote[key]=gh.api('/repos/'+target+'/issues','POST',{'title':spec['title'],'body':body,'labels':labels,'milestone':milestones[spec['phase']]['number']},key='issue:create:'+key)
        r=remote[key];gh.state['issues'][key]={k:r[k] for k in ['number','id','node_id','html_url']};gh.save()
    # Native relations: GET before mutate. Stable ID, not issue number, is the POST body identity.
    if gh.cfg['native_relationships']=='required':
        for spec in selected:
            current=remote.get(spec['key'])
            if not current:continue
            parent_key=spec.get('parent_key')
            if parent_key and parent_key in remote:
                parent=remote[parent_key];relkey='parent:'+spec['key']
                children=gh.api(f"/repos/{target}/issues/{parent['number']}/sub_issues?per_page=100",paginate=True)
                if current['id'] in {x['id'] for x in children}:gh.adopt(relkey)
                else:gh.api(f"/repos/{target}/issues/{parent['number']}/sub_issues",'POST',{'sub_issue_id':current['id']},key=relkey)
            deps=[d for d in spec['depends_on'] if d in remote]
            if deps:
                listed=gh.api(f"/repos/{target}/issues/{current['number']}/dependencies/blocked_by?per_page=100",paginate=True)
                present={x['id'] for x in listed}
                for dep in deps:
                    relkey='blocked-by:'+spec['key']+':'+dep
                    if remote[dep]['id'] in present:gh.adopt(relkey);continue
                    gh.api(f"/repos/{target}/issues/{current['number']}/dependencies/blocked_by",'POST',{'issue_id':remote[dep]['id']},key=relkey)
    project,fields=ensure_project(gh,owner,model,repo)
    attached=project_items(gh,project['id'])
    for spec in selected:
        r=remote[spec['key']];key='project-item:'+spec['key']
        if r['node_id'] not in attached:
            data=gh.graphql('mutation($project:ID!,$content:ID!){addProjectV2ItemById(input:{projectId:$project,contentId:$content}){item{id}}}',{'project':project['id'],'content':r['node_id']},key=key)
            attached[r['node_id']]=data['addProjectV2ItemById']['item']['id']
        else:gh.adopt(key)
        item=attached[r['node_id']]
        values={'Package Key':spec['key'],'Execution':'Manual hold' if spec['manual'] else ('Backlog' if spec['enabled_by_default'] else 'Deferred'),
                'Priority':spec['priority'],'Phase':spec['phase'],'Risk':spec['risk'],'Workstream':spec['area'],'Workflow ID':spec.get('workflow_id') or '', 'Evidence level':'Not run'}
        for name,value in values.items():
            cachekey=spec['key']+':'+name
            # Initial seeding only: never reset a field once runtime tracking has started.
            if cachekey in gh.state['field_values']:continue
            field=fields[name]
            val={'singleSelectOptionId':next(o['id'] for o in field['options'] if o['name']==value)} if field['dataType']=='SINGLE_SELECT' else {'text':value}
            gh.graphql('mutation($project:ID!,$item:ID!,$field:ID!,$value:ProjectV2FieldValue!){updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:$value}){projectV2Item{id}}}',{'project':project['id'],'item':item,'field':field['id'],'value':val},key='field-value:'+cachekey)
            gh.state['field_values'][cachekey]=value;gh.save()
    verified=project_items(gh,project['id'])
    missing=[x['key'] for x in selected if remote[x['key']]['node_id'] not in verified]
    if missing:raise APIError('Project item read-back missing expected members; do not blindly recreate: '+','.join(missing[:8]))
    report={'repository':repo['html_url'],'project':project['url'],'managed_issues_observed':len(remote),'requested_batch':len(selected),
            'mutations_this_run':gh.count,'project_membership_readback':'PASS','source_pushed':False,'rulesets_enforced_by_this_script':False,
            'views_created_by_this_script':False,'remaining_bootstrap':'Push reviewed seed PR, configure actual code owners/protections/environments/views and verify capabilities.','production_actions':0}
    gh.state['last_report']=report;gh.save();return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',default=str(ROOT/'config/github.example.json'))
    modes=p.add_mutually_exclusive_group();modes.add_argument('--plan',action='store_true');modes.add_argument('--apply',action='store_true')
    p.add_argument('--confirm');p.add_argument('--limit',type=int,default=0);p.add_argument('--journal',default=str(ROOT/'.control/github-import.json'))
    a=p.parse_args();cfg=json.loads(Path(a.config).read_text());validate_destination(cfg,a.apply)
    issues=json.loads((ROOT/'backlog/issues.json').read_text())['issues'];model=json.loads((ROOT/'config/project.json').read_text())
    if a.limit<0:p.error('limit must be nonnegative')
    if not a.apply:
        print(json.dumps({'mode':'PLAN_ONLY_NO_NETWORK','target':str(cfg.get('owner') or '<OWNER>')+'/'+cfg['repository'],'visibility':cfg['visibility'],
          'total_issue_records':len(issues),'selected_batch':min(a.limit,len(issues)) if a.limit else len(issues),'labels':len(model['labels']),
          'milestones':len(model['milestones']),'project_fields':len(model['fields']),'parent_links':sum(bool(i['parent_key']) for i in issues),
          'build_dependency_links':sum(len(i['depends_on']) for i in issues),'maximum_mutations_per_run':cfg.get('maximum_mutations_per_run'),
          'requires_explicit_apply':True,'live_agents_launched':0,'production_actions':0},indent=2));return
    if a.confirm!=cfg['owner']+'/'+cfg['repository']:p.error('--confirm must exactly match OWNER/REPOSITORY')
    path=Path(a.journal);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.with_suffix('.lock').open('w') as lock:
        os.chmod(lock.name,0o600)
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise SystemExit('Another importer owns this journal; no writes performed')
        gh=GitHub(cfg,path)
        try:print(json.dumps(seed(gh,issues,model,a.limit),indent=2))
        except (Paused,APIError) as e:
            print(json.dumps({'status':'PAUSED_OR_BLOCKED','reason':str(e),'mutations_this_run':gh.count,'journal':str(path),'pending':gh.state.get('pending')},indent=2));raise SystemExit(2)
if __name__=='__main__':main()
