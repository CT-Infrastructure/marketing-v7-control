"""Offline source reconciliation. This does not query GitHub or qualify runtime."""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PATHS = {
    'catalog': 'reference/workflow_catalog.json',
    'registry': 'reference/components/component_registry.json',
    'original': 'reference/acceptance/Original_Acceptance_Matrix.csv',
    'trace': 'backlog/acceptance_traceability.csv',
    'issues': 'backlog/issues.json',
    'graph': 'orchestration/task_graph.json',
    'routing': 'config/repositories.json',
    'contracts': 'reference/architecture/Integration_Contracts.md',
}

def source_bytes(raw):
    """Only reverse uniform Git CRLF materialization, never normalize content."""
    if b'\r' not in raw:
        return raw
    result = raw.replace(b'\r\n', b'\n')
    if b'\r' in result or result.replace(b'\n', b'\r\n') != raw:
        raise ValueError('unsupported source line endings')
    return result


def load_sources(root=ROOT):
    pins = json.loads((HERE / 'source-hashes.json').read_text())['sources']
    data = {}
    for name, path in PATHS.items():
        raw = (root / path).read_bytes()
        normalized = source_bytes(raw)
        if hashlib.sha256(normalized).hexdigest() != pins[path]['sha256_lf']:
            raise ValueError('source hash changed: ' + path)
        text = normalized.decode('utf-8')
        data[name] = (list(csv.DictReader(io.StringIO(text))) if path.endswith('.csv')
                      else json.loads(text) if path.endswith('.json') else text)
    # Body custody is checked separately from the catalog's semantic coverage.
    for issue in data['issues']['issues']:
        path = Path(issue['body_path'])
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('unsafe issue body path')
        body = source_bytes((root / path).read_bytes())
        if hashlib.sha256(body).hexdigest() != issue['body_sha256']:
            raise ValueError('issue body hash changed: ' + issue['key'])
        if body.count(('<!-- v7-agent-package:' + issue['key'] + ' -->').encode()) != 1:
            raise ValueError('issue body marker mismatch: ' + issue['key'])
    return data


def indexed(rows, field):
    result = {row[field]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError('duplicate ' + field)
    return result


def reconcile(data, mapping):
    """Reject coverage drift; report unresolved semantics without promoting them."""
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    workflows = indexed(data['catalog']['workflows'], 'id')
    components = indexed(data['registry']['components'], 'component_id')
    issues = indexed(data['issues']['issues'], 'key')
    tasks = indexed(data['graph']['tasks'], 'key')
    original = indexed(data['original'], 'test_id')
    trace = indexed(data['trace'], 'source_test_id')
    curated = indexed(mapping['components'], 'component_id')
    require((len(workflows), len(components), len(original), len(issues), len(tasks)) ==
            (190, 147, 576, 785, 759), 'source coverage counts changed')
    require(set(tasks) == {k for k, v in issues.items() if v['kind'] != 'epic'},
            'DAG must contain exactly all non-epic issues')
    require(set(issues) == set(data['routing']['issue_repositories']), 'issue routing coverage')
    approved = {r['name'] for r in data['routing']['repositories']}
    require(set(data['routing']['issue_repositories'].values()) <= approved, 'unknown routed repository')
    require(set(curated) == set(components), 'curated component coverage')
    for cid, component in components.items():
        row = curated[cid]
        require(component['issue_key'] == cid and cid in tasks, 'component issue missing: ' + cid)
        for field in ('name', 'source_classification', 'native_parent'):
            require(row[field] == component[field], 'curated source drift: ' + cid)
        require(row['engineering_issue'] == cid and row['reviewer_issue'] == cid, 'component ownership drift')
        require(row['declared_workflows'] == component['supports_workflows'], 'component association drift')
        require(set(row['declared_workflows']) <= set(workflows), 'unknown component workflow')
        require(row['association_status'] == 'SOURCE_DECLARED_NOT_CONSUMER_CONFIRMED',
                'unreviewed association promoted to confirmed')
        require(row['consumer_contract_status'] == 'NEEDS_WORKFLOW_REVIEW', 'consumer review missing')
        contract = row['contract']
        require(contract['status'] in ('NORMATIVE_BOUNDARY_CITED', 'NEEDS_COMPONENT_OWNER_REVIEW'),
                'unknown contract evidence status')
        if contract['status'] == 'NORMATIVE_BOUNDARY_CITED':
            require(contract['source'] == PATHS['contracts'] + '#authorities-and-actions', 'contract source')
            require('| ' + contract['authority'] + ' |' in data['contracts'], 'contract authority absent')
    for wid, workflow in workflows.items():
        expected = {'WF-' + wid + '-' + stage for stage in ('BUILD', 'TEST', 'VERIFY')}
        actual = {k for k, v in tasks.items() if v.get('workflow_id') == wid}
        require(actual == expected, 'workflow stage coverage: ' + wid)
        for stage in ('BUILD', 'TEST', 'VERIFY'):
            task = tasks['WF-' + wid + '-' + stage]
            require(task == issues[task['key']], 'task differs from issue')
        verify = tasks['WF-' + wid + '-VERIFY']
        require({'WF-' + wid + '-BUILD', 'WF-' + wid + '-TEST'} <= set(verify['depends_on']),
                'VERIFY lacks BUILD/TEST: ' + wid)
    require(set(original) == set(trace), 'orphan original acceptance IDs')
    routing_review = {r['source_test_id']: r for r in mapping['acceptance_routes']}
    require(set(routing_review) == {k for k, r in original.items() if r['workflow_id'] not in workflows},
            'acceptance route review coverage')
    for wid, workflow in workflows.items():
        require(Counter(workflow['acceptance_tests']) == Counter(
            r['test'] for r in original.values() if r['workflow_id'] == wid),
            'workflow acceptance text coverage: ' + wid)
    pending_acceptance_routes = []
    for test_id, row in original.items():
        link = trace[test_id]
        wid = link['workflow_id']
        require(wid in workflows, 'unknown acceptance workflow')
        if row['workflow_id'] in workflows:
            require(wid == row['workflow_id'], 'acceptance workflow drift')
        else:
            review = routing_review.get(test_id)
            require(review is not None and review['source_selector'] == row['workflow_id']
                    and review['mapped_workflow'] == wid
                    and review['status'] == 'EXISTING_ROUTE_REQUIRES_REVIEW',
                    'unreviewed baseline or range acceptance routing changed')
            pending_acceptance_routes.append(review)
        require(row['test'] == link['test'], 'acceptance text drift')
        for column, stage in (('implementation_issue', 'BUILD'), ('test_authoring_issue', 'TEST'),
                              ('verification_issue', 'VERIFY')):
            require(link[column] == 'WF-' + wid + '-' + stage, 'acceptance stage misroute')
        require(link['initial_status'] == 'NOT_RUN', 'runtime evidence falsely promoted')
    require(Counter(r['status'] for r in original.values()) ==
            {'NOT_RUN': 564, 'OPEN_SOURCE_BLOCKER': 12}, 'original annotations changed')
    for key, task in tasks.items():
        require(task == issues[key], 'task/issue drift: ' + key)
        require(len(task['depends_on']) == len(set(task['depends_on'])), 'duplicate prerequisite')
        for dependency in task['depends_on']:
            require(dependency in tasks, 'unknown or epic prerequisite')
            require(not (task['kind'] != 'human-gate' and tasks[dependency]['kind'] == 'human-gate'),
                    'human gate blocks ordinary engineering')
        if task['kind'] == 'test-authoring':
            require(not any(tasks[d]['kind'] == 'implementation' for d in task['depends_on']),
                    'test writing waits on implementation')
    pending = {k: set(v['depends_on']) for k, v in tasks.items()}
    while pending:
        ready = {k for k, dependencies in pending.items() if not dependencies}
        require(bool(ready), 'build prerequisite cycle')
        pending = {k: d - ready for k, d in pending.items() if k not in ready}
    edges = data['catalog']['connections']
    require(len(edges) == 1847, 'runtime edge count changed')
    for edge in edges:
        require(edge['from'] in workflows and edge['to'] in workflows, 'orphan runtime edge')
        require(edge['type'] in data['catalog']['edge_semantics'], 'unknown runtime edge semantics')
    unresolved = [{'component_id': k, 'reviewer_issue': k,
                   'component_contract': v['contract']['status'],
                   'consumer_workflows_pending': v['declared_workflows']}
                  for k, v in sorted(curated.items())]
    return {'local_source_coverage': 'COMPLETE',
            'counts': {'workflows': 190, 'workflow_packages': 570, 'components': 147,
                       'original_acceptance_ids': 576, 'issues': 785, 'tasks': 759,
                       'runtime_edges_not_build_prerequisites': 1847},
            'original_annotations': {'NOT_RUN': 564, 'OPEN_SOURCE_BLOCKER': 12},
            'runtime_execution': {'NOT_RUN': 576, 'qualification_claimed': False},
            'remote_import': {'status': 'INCOMPLETE_REPORTED_BY_COORDINATOR',
                              'reported_managed_issues': 210, 'expected_source_issues': 785,
                              'live_verified_by_this_tool': False},
            'component_reviews': unresolved,
            'acceptance_routing_review': pending_acceptance_routes,
            'graph_amendments_applied': False,
            'runtime_feedback_policy': 'Runtime connections are audited separately and never copied into the DAG.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    mapping = json.loads((HERE / 'component-contracts.json').read_text())
    mapping['acceptance_routes'] = json.loads((HERE / 'acceptance-routing-review.json').read_text())['routes']
    report = reconcile(load_sources(args.root), mapping)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
