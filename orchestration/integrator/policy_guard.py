"""Nonauthorizing F13 host consistency guard. No queue, API, Git or SDK effects.

Call only from an independently authenticated trusted host against stable exports
outside worker reach. This module cannot authenticate any caller or its JSON.
Even a consistent observation returns HOLD/effect_authority=NONE.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path


class Held(ValueError):
    """Redacted reason code; never echo worker content or secret-bearing result."""


def need(condition, code):
    if not condition:
        raise Held(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def raw_digest(value):
    return hashlib.sha256(value).hexdigest()


def exact(value, fields, code):
    need(type(value) is dict and set(value) == set(fields.split()), code)


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def path_name(value):
    need(type(value) is str and 0 < len(value) <= 512, 'PATH_FORMAT')
    need(not value.startswith('/') and '\\' not in value and ':' not in value
         and all(p not in ('', '.', '..') for p in value.split('/'))
         and all(ord(c) >= 32 and ord(c) != 127 for c in value), 'PATH_TRAVERSAL')
    need(all(p.casefold() != '.git' for p in value.split('/')), 'GIT_METADATA')
    return value


def beneath(name, prefix):
    return name.startswith(prefix) if prefix.endswith('/') else name == prefix


def strict_json(raw, limit):
    need(type(raw) is bytes and len(raw) <= limit, 'RESULT_BOUND')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Held('JSON_CONSTANT')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Held('RESULT_JSON') from None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _root_fd(root):
    # Open every ancestor relative to the already-open parent, no symlink walk.
    need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW')
         and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd,
         'POSIX_DESCRIPTOR_SUPPORT_REQUIRED')
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'ABSOLUTE_HOST_EXPORT_REQUIRED')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in root.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except OSError:
        os.close(fd)
        raise Held('LINK_OR_INVALID_EXPORT_ESCALATION') from None
    except BaseException:
        os.close(fd)
        raise


def observe(root, limits):
    """Complete bounded regular-file inventory; no agent manifest is trusted.

    The trusted caller must exclude worker writes for the whole call. Descriptor
    and before/after checks detect observed races, not an adversarially timed
    replacement between separate calls. Recollect immediately before any later
    privileged action in the existing controller; no atomic snapshot is claimed.
    """
    rows = []
    total = 0
    seen = set()
    def walk(fd, prefix=''):
        nonlocal total
        before_dir = _identity(os.fstat(fd))
        names = sorted(os.listdir(fd))
        need(len(names) <= limits['files'], 'ENTRY_BOUND')
        for name in names:
            relative = path_name(prefix + name)
            key = relative.casefold()
            need(key not in seen, 'AMBIGUOUS_PATH')
            seen.add(key)
            need(len(seen) <= limits['files'], 'ENTRY_BOUND')
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(not stat.S_ISLNK(named.st_mode), 'LINK_ESCALATION')
            if stat.S_ISDIR(named.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(_identity(os.fstat(child)) == _identity(named), 'DIRECTORY_RACE')
                    walk(child, relative + '/')
                    need(_identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                         == _identity(named), 'DIRECTORY_RACE')
                finally:
                    os.close(child)
                continue
            need(stat.S_ISREG(named.st_mode) and named.st_nlink == 1, 'SPECIAL_OR_HARDLINK_ESCALATION')
            need(named.st_size <= limits['file_bytes'], 'FILE_BOUND')
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                              | os.O_CLOEXEC, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                need(_identity(before) == _identity(named), 'FILE_RACE')
                parts = []
                left = before.st_size + 1
                while left:
                    block = os.read(file_fd, min(65536, left))
                    if not block:
                        break
                    parts.append(block)
                    left -= len(block)
                content = b''.join(parts)
                need(len(content) == before.st_size and _identity(os.fstat(file_fd))
                     == _identity(before) == _identity(os.stat(name, dir_fd=fd,
                                                             follow_symlinks=False)), 'FILE_RACE')
                total += len(content)
                need(total <= limits['total_bytes'], 'TOTAL_BOUND')
                rows.append(dict(path=relative, sha256=raw_digest(content),
                                 bytes=len(content), executable=bool(before.st_mode & 0o111)))
            finally:
                os.close(file_fd)
        need(names == sorted(os.listdir(fd)) and before_dir == _identity(os.fstat(fd)),
             'DIRECTORY_RACE')
    fd = _root_fd(root)
    try:
        walk(fd)
    finally:
        os.close(fd)
    return sorted(rows, key=lambda row: row['path'])


def _binding(value):
    exact(value, 'repository task fence input_sha256 base head tree', 'BINDING_SCHEMA')
    need(type(value['fence']) is int and value['fence'] > 0, 'FENCE')
    need(all(type(value[k]) is str and value[k] for k in ('repository', 'task')), 'BINDING_ID')
    need(sha(value['input_sha256']), 'INPUT_HASH')
    need(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}', value[k])
             for k in ('base', 'head', 'tree')), 'GIT_IDENTITY')


def _pages(sources, required, binding, limits):
    need(type(sources) is dict and set(sources) == set(required), 'SOURCE_SET')
    total_raw = 0
    observed_sources = {}
    for kind in required:
        pages = sources[kind]
        need(type(pages) is list and 0 < len(pages) <= limits['pages'], 'PAGINATION_BOUND')
        ids = set()
        observed_sources[kind] = {}
        count = 0
        for index, page in enumerate(pages):
            exact(page, 'page next_page records raw_utf8 raw_sha256 binding', 'PAGE_SCHEMA')
            need(type(page['page']) is int and page['page'] == index + 1
                 and page['next_page'] == (index + 2 if index + 1 < len(pages) else None),
                 'INCOMPLETE_PAGINATION')
            need(page['binding'] == binding and sha(page['raw_sha256']), 'SOURCE_BINDING')
            need(type(page['raw_utf8']) is str and len(page['raw_utf8'].encode()) <= limits['file_bytes'] and raw_digest(page['raw_utf8'].encode()) == page['raw_sha256'], 'UNVERIFIED_RAW_SOURCE')
            total_raw += len(page['raw_utf8'].encode())
            need(total_raw <= limits['total_bytes'], 'SOURCE_TOTAL_BOUND')
            raw = strict_json(page['raw_utf8'].encode(), limits['file_bytes'])
            need(type(raw) is list and len(raw) <= limits['records'], 'RAW_SOURCE_RECORDS')
            observed = []
            for item in raw:
                need(type(item) is dict and type(item.get('id')) in (str, int)
                     and type(item.get('id')) is not bool, 'RAW_SOURCE_ID')
                observed.append(dict(id=str(item['id']), sha256=digest(item)))
                observed_sources[kind][str(item['id'])] = item
            need(type(page['records']) is list and page['records'] == observed, 'UNVERIFIED_RAW_SOURCE')
            for record in page['records']:
                exact(record, 'id sha256', 'SOURCE_RECORD')
                need(type(record['id']) is str and record['id'] and record['id'] not in ids
                     and sha(record['sha256']), 'DUPLICATE_OR_UNKNOWN_SOURCE')
                ids.add(record['id'])
                count += 1
                need(count <= limits['records'], 'SOURCE_BOUND')
    return observed_sources


def assess(base_root, candidate_root, result_bytes, *, expected_binding, host_facts, policy):
    """Return a redacted consistency report, ALWAYS HOLD/effect_authority NONE.

    host_facts/expected_binding must originate in independent host collection,
    never deserialized worker claims. This API does not authenticate them.
    Required checks/identities and freshness are privileged caller inputs; the
    guard cannot discover authority or replace current GitHub native validation.
    """
    report = dict(decision='HOLD', effect_authority='NONE', consistent=False,
                  human_escalation=False, reasons=[])
    try:
        need(policy == json.loads(Path(__file__).with_name('reviewed-policy.v1.json').read_text()),
             'POLICY_DRIFT')
        _binding(expected_binding)
        exact(host_facts, 'binding policy_sha256 result_sha256 manifest_sha256 test_sha256 review_sha256 checks_sha256 source_sha256 author reviewer tests review checks required_checks sources findings now', 'HOST_FACT_SCHEMA')
        need(host_facts['binding'] == expected_binding, 'CURRENT_BINDING_CHANGED')
        need(host_facts['policy_sha256'] == digest(policy), 'POLICY_DIGEST')
        result = strict_json(result_bytes, policy['limits']['result_bytes'])
        exact(result, 'task_key fence input_sha256 base_revision status changed_paths artifacts tests summary blockers', 'SANITIZED_RESULT_SCHEMA')
        need(result['status'] == 'ready_for_review' and result['blockers'] == []
             and type(result['summary']) is str, 'RESULT_STATUS')
        need(type(result['fence']) is int and result['fence'] == expected_binding['fence']
             and result['task_key'] == expected_binding['task']
             and result['input_sha256'] == expected_binding['input_sha256']
             and result['base_revision'] == expected_binding['base'], 'RESULT_BINDING')
        need(raw_digest(result_bytes) == host_facts['result_sha256'], 'RESULT_CHANGED')
        base = observe(base_root, policy['limits'])
        candidate = observe(candidate_root, policy['limits'])
        base_by = {r['path']: r for r in base}
        candidate_by = {r['path']: r for r in candidate}
        changed = sorted(k for k in set(base_by) | set(candidate_by)
                         if base_by.get(k) != candidate_by.get(k))
        need(bool(changed), 'NO_ACTUAL_CHANGE')
        report['observed_manifest_sha256'] = digest(candidate)
        # Scope is authenticated separately by the caller; use this task's closed
        # four-file policy route, never a result-supplied or dynamic allowlist.
        allowed = {'orchestration/integrator/README.md',
                   'orchestration/integrator/reviewed-policy.v1.json',
                   'orchestration/integrator/policy_guard.py',
                   'tests/integrator/test_reviewed_policy.py'}
        for name in changed:
            need(name in allowed, 'UNOWNED_ESCALATION')
            need(name in candidate_by, 'DELETE_OR_RENAME_ESCALATION')
            need(not any(beneath(name, prefix) for prefix in policy['protected_prefixes'])
                 and name not in policy['protected_files'], 'PROTECTED_ESCALATION')
        need(digest(candidate) == host_facts['manifest_sha256'], 'OBSERVED_MANIFEST_CHANGED')
        need(type(result['changed_paths']) is list, 'DECLARED_PATH_LIST')
        for name in result['changed_paths']:path_name(name)
        need(result['changed_paths'] == changed,
             'DECLARED_DIFF_MISMATCH')
        artifacts = result['artifacts']
        need(type(artifacts) is list and len(artifacts) == len(changed), 'ARTIFACT_SET')
        for row, name in zip(artifacts, changed):
            exact(row, 'path sha256', 'ARTIFACT_SCHEMA')
            need(path_name(row['path']) == name and row['sha256'] == candidate_by[name]['sha256'],
                 'ACTUAL_CONTENT_HASH_MISMATCH')
        source_records = _pages(host_facts['sources'], policy['required_sources'], expected_binding, policy['limits'])
        need(type(host_facts['tests']) is list and len(host_facts['tests']) <= policy['limits']['records']
             and type(host_facts['checks']) is list and len(host_facts['checks']) <= policy['limits']['records'], 'EVIDENCE_BOUND')
        for key, raw_key in (('tests', 'test_sha256'), ('review', 'review_sha256'),
                             ('checks', 'checks_sha256'), ('sources', 'source_sha256')):
            need(digest(host_facts[key]) == host_facts[raw_key], 'EVIDENCE_DIGEST_CHANGED')
        need(type(host_facts['author']) is str and host_facts['author']
             and type(host_facts['reviewer']) is str and host_facts['reviewer']
             and host_facts['author'] != host_facts['reviewer'], 'SELF_REVIEW')
        review = host_facts['review']
        exact(review, 'binding author reviewer model effort complete open_findings reviewed_at expires_at source_id source_sha256', 'REVIEW_SCHEMA')
        raw_review = source_records['reviews'].get(review['source_id'])
        need(type(raw_review) is dict and digest(raw_review) == review['source_sha256']
             and raw_review == dict({k:v for k,v in review.items() if k not in ('source_id','source_sha256')}, id=review['source_id']), 'UNVERIFIED_REVIEW_SOURCE')
        need(review['binding'] == expected_binding and review['author'] == host_facts['author']
             and review['reviewer'] == host_facts['reviewer'] and review['model'] == 'gpt-6.1-sol'
             and review['effort'] == 'max' and review['complete'] is True
             and review['open_findings'] == [], 'INDEPENDENT_WHOLE_REVIEW_REQUIRED')
        now = host_facts['now']
        need(type(now) in (int, float) and type(review['reviewed_at']) in (int, float)
             and type(review['expires_at']) in (int, float)
             and all(math.isfinite(x) for x in (now, review['reviewed_at'], review['expires_at']))
             and review['reviewed_at'] <= now < review['expires_at']
             and review['expires_at'] - review['reviewed_at'] <= policy['review']['max_age_seconds'], 'STALE_REVIEW')
        tests = host_facts['tests']
        need(type(tests) is list and bool(tests) and result['tests'] == tests, 'INDEPENDENT_TEST_RESULT_MISMATCH')
        for test in tests:
            exact(test, 'command exit_code output_sha256 binding', 'TEST_SCHEMA')
            need(type(test['command']) is str and test['command'] and type(test['exit_code']) is int
                 and test['exit_code'] == 0 and sha(test['output_sha256'])
                 and test['binding'] == expected_binding, 'UNVERIFIED_TEST')
        required = host_facts['required_checks']
        need(type(required) is dict and bool(required) and all(type(k) is str and k
             and type(v) is int and v > 0 for k, v in required.items()), 'REQUIRED_CHECK_PROFILE')
        checks = host_facts['checks'];seen = set();ids = set()
        need(type(checks) is list and len(checks) == len(required), 'CHECK_SET')
        for check in checks:
            exact(check, 'id name app_id head status conclusion', 'CHECK_SCHEMA')
            need(type(check['id']) is int and check['id'] > 0 and check['id'] not in ids
                 and check['name'] in required and check['name'] not in seen
                 and type(check['app_id']) is int and check['app_id'] == required[check['name']]
                 and check['head'] == expected_binding['head'] and check['status'] == 'completed'
                 and check['conclusion'] == 'success', 'UNVERIFIED_OR_AMBIGUOUS_CHECK')
            need(source_records['checks'].get(str(check['id'])) == check, 'UNVERIFIED_CHECK_SOURCE')
            seen.add(check['name']);ids.add(check['id'])
        findings = host_facts['findings']
        need(type(findings) is list, 'FINDING_HISTORY')
        finding_ids = set()
        observed_findings = {row['id']: row['sha256'] for page in host_facts['sources']['findings'] for row in page['records']}
        need(len(findings) == len(observed_findings), 'OMITTED_FINDING_DISPOSITION')
        for finding in findings:
            exact(finding, 'id source_sha256 severity status current_binding regression_sha256 rereview_sha256', 'FINDING_SCHEMA')
            need(type(finding['id']) is str and finding['id'] and finding['id'] not in finding_ids
                 and finding['severity'] in ('P0','P1','P2','P3')
                 and finding['status'] == 'resolved' and finding['current_binding'] == expected_binding
                 and finding['source_sha256'] == observed_findings.get(finding['id']) and finding['regression_sha256'] == host_facts['test_sha256']
                 and finding['rereview_sha256'] == host_facts['review_sha256'], 'UNRESOLVED_OR_STALE_FINDING')
            finding_ids.add(finding['id'])
        # Bounded complete final reread detects any observed export change.
        need(observe(base_root, policy['limits']) == base
             and observe(candidate_root, policy['limits']) == candidate, 'LATE_SOURCE_DRIFT')
        report['consistent'] = True
        report['reasons'] = ['HOST_CONSISTENCY_ONLY_REQUIRES_EXISTING_TRUSTED_OWNER']
    except Held as error:
        code = str(error)
        report['reasons'] = [code]
        report['human_escalation'] = any(word in code for word in ('ESCALATION', 'PATH_', 'LINK', 'SPECIAL', 'GIT_METADATA', 'AMBIGUOUS_PATH'))
    except (OSError, TypeError, KeyError, ValueError, RecursionError):
        report['reasons'] = ['MALFORMED_OR_UNREADABLE_HOST_OBSERVATION']
    return report
