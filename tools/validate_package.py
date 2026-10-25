#!/usr/bin/env python3
"""Validate documentation/manifest integrity. Does NOT qualify runtime services."""
from __future__ import annotations
import collections,csv,hashlib,json,re,sys
from pathlib import Path
from scheduler import validate_graph,safe_relative,validate_policy
ROOT=Path(__file__).resolve().parents[1]

def validate(root: Path=ROOT) -> dict:
    issues=json.loads((root/'backlog/issues.json').read_text())['issues'];by={x['key']:x for x in issues}
    tasks=json.loads((root/'orchestration/task_graph.json').read_text())['tasks'];tby={x['key']:x for x in tasks}
    workflows=json.loads((root/'reference/workflow_catalog.json').read_text())['workflows']
    components=json.loads((root/'reference/components/component_registry.json').read_text())['components']
    cases=list(csv.DictReader((root/'reference/acceptance/Original_Acceptance_Matrix.csv').open()))
    trace=list(csv.DictReader((root/'backlog/acceptance_traceability.csv').open()))
    assert len(workflows)==190 and len({w['id'] for w in workflows})==190,'Workflow coverage changed'
    assert len(components)==147 and len({c['component_id'] for c in components})==147,'Component coverage changed'
    assert len(cases)==576,'Source acceptance count changed'
    assert len(issues)==len(by),'Duplicate issue keys'
    order=validate_graph(tasks)
    assert set(tby)=={x['key'] for x in issues if x['kind']!='epic'},'Task/issue mismatch'
    assert all(by[k]==v for k,v in tby.items()),'Task metadata diverges from issue catalog'
    maxbody=0
    for issue in issues:
        body=(root/issue['body_path']).read_text();maxbody=max(maxbody,len(body))
        assert len(body)<60000,issue['key']+' body exceeds safe GitHub limit'
        assert f"<!-- v7-agent-package:{issue['key']} -->" in body,'Stable marker absent'
        assert body.count('<!-- BEGIN V7 GENERATED -->')==1 and body.count('<!-- END V7 GENERATED -->')==1,'Ambiguous generated markers'
        assert 'security' in body.lower() and 'acceptance' in body.lower() if issue['kind'] not in ['epic','human-gate'] else True
        for dependency in issue['depends_on']:assert dependency in by and by[dependency]['kind']!='epic','Unknown/epic build prerequisite'
        if issue['parent_key']:assert issue['parent_key'] in by,'Unknown parent'
        for scope in issue['write_paths']:safe_relative(scope)
        if issue.get('body_sha256'):assert hashlib.sha256(body.encode()).hexdigest()==issue['body_sha256'],'Issue body hash mismatch'
    children=collections.Counter(x['parent_key'] for x in issues if x['parent_key'])
    assert max(children.values())<=100,'GitHub parent exceeds native sub-issue limit'
    for x in issues:
        seen={x['key']};cursor=x;depth=0
        while cursor['parent_key']:
            assert cursor['parent_key'] not in seen,'Parent cycle';seen.add(cursor['parent_key']);cursor=by[cursor['parent_key']];depth+=1
        assert depth<=8,'Native sub-issue depth exceeded'
    for w in workflows:
        for stage in ['BUILD','TEST','VERIFY']:assert f"WF-{w['id']}-{stage}" in by,'Workflow stage missing'
        assert f"WF-{w['id']}-BUILD" not in by[f"WF-{w['id']}-TEST"]['depends_on'],'Tests-first parallelism regressed'
        assert {f"WF-{w['id']}-BUILD",f"WF-{w['id']}-TEST"}.issubset(by[f"WF-{w['id']}-VERIFY"]['depends_on'])
        assert (root/f"reference/mermaid/{w['id']}.mmd").is_file()
    assert {c['issue_key'] for c in components}.issubset(by),'Unassigned component'
    assert {r['source_test_id'] for r in trace}=={r['test_id'] for r in cases} and len(trace)==len(cases),'Acceptance traceability gap'
    for r in trace:
        for key in ['implementation_issue','test_authoring_issue','verification_issue']:assert r[key] in by
        assert r['initial_status']=='NOT_RUN','Runtime tests fabricated as executed'
    legacy=json.loads((root/'backlog/legacy_evidence_traceability.json').read_text())['rows']
    assert len(legacy)==329,'Legacy source row coverage changed'
    for policy in [root/'config/orchestration.example.json']:validate_policy(json.loads(policy.read_text()))
    assert json.loads((root/'config/orchestration.example.json').read_text())['mode']=='disabled'
    assert json.loads((root/'config/github.example.json').read_text())['visibility']=='private'
    for path in (root/'.github/workflows').glob('*.yml'):
        text=path.read_text()
        assert 'pull_request_target' not in text,'Unsafe trigger in seed workflow'
        for action in re.findall(r'uses:\s*([^\s#]+)',text):assert re.search(r'@[a-f0-9]{40}$',action),'Unpinned action'
    levels={}
    for k in order:levels[k]=0 if not tby[k]['depends_on'] else max(levels[d] for d in tby[k]['depends_on'])+1
    level_counts=collections.Counter(levels[k] for k in order if not tby[k]['manual'] and tby[k]['enabled_by_default'])
    # Frontier sizes below describe a graph, not real hardware or agent performance.
    return {'validation_scope':'PACKAGE_MANIFESTS_ONLY','status':'PASS','issues':len(issues),'schedulable_and_manual_tasks':len(tasks),
       'issue_types':dict(collections.Counter(x['kind'] for x in issues)), 'workflow_count':len(workflows),'component_count':len(components),
       'source_acceptance_ids':len(cases),'legacy_opaque_rows':len(legacy),'build_edges':sum(len(x['depends_on']) for x in tasks),
       'build_dag_acyclic':True,'native_parent_max_children':max(children.values()),'largest_issue_body_characters':maxbody,
       'independent_tests_first_tasks':190,'topological_level_counts_not_runtime_parallelism':dict(sorted(level_counts.items())),
       'live_github_tested':False,'real_agent_adapter_tested':False,'production_tests_executed':False}
if __name__=='__main__':
    try:print(json.dumps(validate(),indent=2))
    except (AssertionError,ValueError,KeyError) as e:print('VALIDATION FAILED: '+str(e),file=sys.stderr);raise SystemExit(1)
