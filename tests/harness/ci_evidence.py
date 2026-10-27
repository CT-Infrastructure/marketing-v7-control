"""Closed synthetic CI receipts. No arbitrary logs, environment or payload exports."""
from __future__ import annotations
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import unittest
import urllib.request

MAX_FILE = 1048576
MAX_TOTAL = 2 * MAX_FILE
FILES = ('evidence.json', 'manifest.json')
ORIGINAL = ('test_synthetic', 'test_probe_network', 'test_export_retention')
SOURCE = (
    '.github/workflows/package-validation.yml',
    '.github/scripts/validate-f07-harness.sh',
    'tests/harness/ci_evidence.py', 'tests/harness/test_ci_evidence.py',
    'tests/harness/requirements-ci.lock', 'tests/harness/README.md',
    'tests/harness/native-ci.lock.json',
    'tests/harness/native_source_build.py','tests/harness/test_native_source_build.py',
    'tests/harness/native-source-ci.lock.json','tests/harness/native-build-authorization.lock.json',
    'tests/harness/test_synthetic.py', 'tests/harness/test_probe_network.py',
    'tests/harness/test_export_retention.py', 'tests/harness/synthetic.py',
    'tests/harness/probe_network.py', 'tests/harness/export_retention.py',
)
ROOT = Path(__file__).resolve().parents[2]
REMAINDER = {'full_network_scope': 'NOT_RUN', 'hardkill_cleanup': 'NOT_RUN',
             'seven_day_elapsed_deletion': 'NOT_RUN', 'production_acceptance': 'NOT_RUN'}


def require(condition, reason='invalid closed CI evidence'):
    if not condition:
        raise ValueError(reason)


def hex_value(value, length):
    require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is not None)
    return value


def number(value, minimum=1, maximum=2**63-1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def encoded(doc):
    return (json.dumps(doc, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate field')
        result[key] = value
    return result


def canonical_root(root):
    root = Path(root)
    require(root.is_absolute() and root != Path(root.anchor))
    require(root.resolve() == root and root.is_dir())
    for part in (root, *root.parents):
        require(not part.is_symlink() and not (hasattr(part, 'is_junction') and part.is_junction()))
    return root


def read_regular(root, name):
    require(name in FILES, 'file outside allowlist')
    root = canonical_root(root)
    path = root / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink())
    require(not getattr(info, 'st_file_attributes', 0) & 0x400)
    if hasattr(os, 'getuid'):
        require(info.st_uid == os.getuid())
    require(info.st_size <= MAX_FILE, 'file size bound')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink) ==
                (info.st_dev, info.st_ino, info.st_size, 1))
        raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE and len(raw) == info.st_size, 'file size bound')
    doc = json.loads(raw, object_pairs_hook=unique)
    require(raw == encoded(doc), 'noncanonical or unredacted bytes')
    return raw, doc


def validate_evidence(doc, tested, candidate):
    hex_value(tested, 40)
    hex_value(candidate, 40)
    require(type(doc) is dict and set(doc) == {
        'schema', 'synthetic_only', 'tested_git_sha', 'pr_candidate_sha', 'python',
        'namespace', 'original', 'helper', 'probe', 'retention_days', 'remaining'})
    require(doc['schema'] == 'f07-ci-v1' and doc['synthetic_only'] is True)
    require(doc['tested_git_sha'] == tested and doc['pr_candidate_sha'] == candidate)
    require(doc['python'] == '3.12.3' and doc['namespace'] == 'bwrap-unshare-all')
    require(type(doc['retention_days']) is int and doc['retention_days'] == 7)
    require(doc['remaining'] == REMAINDER)
    for mode in ('normal', 'optimized'):
        require(type(doc['original']) is dict and set(doc['original']) == {'normal', 'optimized'})
        require(doc['original'][mode] == {'run': 54, 'failures': 0, 'errors': 0, 'skipped': 0})
        # Equality alone would accept bools in place of integers.
        require(all(type(v) is int for v in doc['original'][mode].values()))
    require(type(doc['helper']) is dict and set(doc['helper']) == {'normal', 'optimized'})
    for item in doc['helper'].values():
        require(type(item) is dict and set(item) == {'run', 'failures', 'errors', 'skipped'})
        number(item['run'])
        require(all(type(item[k]) is int and item[k] == 0 for k in ('failures', 'errors', 'skipped')))
    require(type(doc['probe']) is dict and set(doc['probe']) == {'normal', 'optimized'})
    for item in doc['probe'].values():
        require(type(item) is dict and set(item) == {'status', 'target', 'errno', 'phase', 'scope'})
        require(item['status'] == 'DENY_OBSERVED' and item['target'] == '192.0.2.1:9')
        require(item['phase'] == 'connect' and type(item['errno']) is int and item['errno'] in (101, 113))
        require(item['scope'] == 'one TCP TEST-NET probe only')
    # No unknown strings or free text fields survive these exhaustive schemas.
    return doc


def source_hashes():
    # Include every tracked source blob, not just the changed files; no paths from env.
    listing = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    result = {}
    for raw in listing:
        if not raw:
            continue
        name = raw.decode('utf-8')
        path = ROOT / name
        require(path.resolve().is_relative_to(ROOT) and path.is_file() and not path.is_symlink())
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def validate_bundle(root, tested, candidate, expected_sources=None):
    root = canonical_root(root)
    require({p.name for p in root.iterdir()} == set(FILES), 'exact two-file allowlist required')
    evidence_raw, evidence = read_regular(root, 'evidence.json')
    validate_evidence(evidence, tested, candidate)
    manifest_raw, manifest = read_regular(root, 'manifest.json')
    require(len(evidence_raw) + len(manifest_raw) <= MAX_TOTAL, 'aggregate size bound')
    require(type(manifest) is dict and set(manifest) == {'schema', 'tested_git_sha', 'pr_candidate_sha',
            'retention_days', 'files', 'source_sha256'})
    require(manifest['schema'] == 'f07-ci-manifest-v1')
    require(manifest['tested_git_sha'] == tested and manifest['pr_candidate_sha'] == candidate)
    require(type(manifest['retention_days']) is int and manifest['retention_days'] == 7)
    require(manifest['files'] == {'evidence.json': {'bytes': len(evidence_raw),
            'sha256': hashlib.sha256(evidence_raw).hexdigest()}})
    require(type(manifest['files']['evidence.json']['bytes']) is int)
    sources = manifest['source_sha256']
    require(type(sources) is dict and set(SOURCE) <= set(sources) and 1 <= len(sources) <= 2000)
    for name, digest in sources.items():
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name) is not None)
        require(not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))
        hex_value(digest, 64)
    if expected_sources is not None:
        require(sources == expected_sources, 'source bytes changed')
    return manifest


def suite(modules, expected=None):
    loaded = unittest.TestLoader().loadTestsFromNames(modules)
    if expected is not None:
        require(loaded.countTestCases() == expected, 'original suite count changed')
    # Captures are deliberately discarded; no arbitrary exception/fixture text is exported.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = unittest.TextTestRunner(stream=io.StringIO()).run(loaded)
    receipt = dict(run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
    require(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses,
            'test suite unsuccessful or skipped')
    return receipt


def child(mode, kind):
    args = [sys.executable, '-B'] + (['-O'] if mode == 'optimized' else [])
    if kind == 'probe':
        args += [str(ROOT/'tests/harness/probe_network.py'), '--probe-test-net']
    else:
        args += [str(Path(__file__)), 'suite', kind]
    finished = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    require(finished.returncode == 0 and len(finished.stdout) <= 8192, 'isolated child failed')
    return json.loads(finished.stdout, object_pairs_hook=unique)


def run(root, tested, candidate):
    import platform
    require(platform.python_version() == '3.12.3')
    require(os.environ.get('F07_NETWORK_NAMESPACE_EXPECTED') == '1')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == tested,
            'checkout differs from actual GITHUB_SHA')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT),
            'tracked source is dirty')
    doc = dict(schema='f07-ci-v1', synthetic_only=True, tested_git_sha=tested, pr_candidate_sha=candidate,
               python='3.12.3', namespace='bwrap-unshare-all', original={}, helper={}, probe={},
               retention_days=7, remaining=REMAINDER.copy())
    for mode in ('normal', 'optimized'):
        doc['original'][mode] = child(mode, 'original')
        doc['helper'][mode] = child(mode, 'helper')
        doc['probe'][mode] = child(mode, 'probe')
    validate_evidence(doc, tested, candidate)
    root = canonical_root(root)
    require(not list(root.iterdir()))
    data = encoded(doc)
    manifest = dict(schema='f07-ci-manifest-v1', tested_git_sha=tested, pr_candidate_sha=candidate,
                    retention_days=7, files={'evidence.json': {'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}},
                    source_sha256=source_hashes())
    for name, raw in (('evidence.json', data), ('manifest.json', encoded(manifest))):
        require(len(raw) <= MAX_FILE)
        with (root/name).open('xb') as stream:
            require(stream.write(raw) == len(raw))
    validate_bundle(root, tested, candidate, source_hashes())


def stamp(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value) is not None)
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_metadata(doc, *, artifact_id, digest, run_id, tested, candidate, name, now):
    hex_value(tested, 40)
    hex_value(candidate, 40)
    number(artifact_id)
    number(run_id)
    hex_value(digest, 64)
    require(type(doc) is dict)
    require(type(doc.get('id')) is int and doc['id'] == artifact_id)
    require(doc.get('name') == name and doc.get('digest') == 'sha256:'+digest)
    number(doc.get('size_in_bytes'), maximum=MAX_TOTAL + 65536)
    require(doc.get('expired') is False)
    workflow = doc.get('workflow_run')
    require(type(workflow) is dict and type(workflow.get('id')) is int and workflow['id'] == run_id)
    require(workflow.get('head_sha') == candidate)
    created, expires = stamp(doc.get('created_at')), stamp(doc.get('expires_at'))
    require(timedelta(days=7)-timedelta(minutes=5) <= expires-created <= timedelta(days=7)+timedelta(minutes=5))
    require(timedelta(0) <= now-created <= timedelta(minutes=30) and expires > now)
    return dict(schema='f07-service-metadata-v1', artifact_id=artifact_id, digest=digest, run_id=run_id,
                tested_git_sha=tested, pr_candidate_sha=candidate, created_at=doc['created_at'], expires_at=doc['expires_at'],
                size_in_bytes=doc['size_in_bytes'], expired=False, retention='configured-seven-day-expiry',
                configured_permissions={'contents':'read', 'actions':'read'},
                metadata_get='OBSERVED', authorization_matrix='NOT_RUN', remaining=REMAINDER.copy())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('metadata redirect forbidden')


def metadata(root, tested, candidate):
    validate_bundle(root, tested, candidate, source_hashes())
    repo = os.environ['GITHUB_REPOSITORY']
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) is not None)
    require(all(part not in ('.', '..') for part in repo.split('/')))
    aid = os.environ['F07_ARTIFACT_ID']
    rid = os.environ['GITHUB_RUN_ID']
    attempt = os.environ['GITHUB_RUN_ATTEMPT']
    require(all(re.fullmatch('[1-9][0-9]{0,18}', v) is not None for v in (aid, rid, attempt)))
    digest = hex_value(os.environ['F07_ARTIFACT_DIGEST'].removeprefix('sha256:'), 64)
    # Fixed host and same-repository numeric artifact route; no user URL, proxy or redirects.
    request = urllib.request.Request('https://api.github.com/repos/'+repo+'/actions/artifacts/'+aid,
        headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'], 'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        require(response.status == 200)
        raw = response.read(65537)
    require(len(raw) <= 65536)
    receipt = validate_metadata(json.loads(raw, object_pairs_hook=unique), artifact_id=int(aid), digest=digest,
        run_id=int(rid), tested=tested, candidate=candidate, name='f07-synthetic-'+rid+'-'+attempt, now=datetime.now(timezone.utc))
    # Only closed metadata is printed; never headers, token, response body or URLs.
    print(encoded(receipt).decode(), end='')


def cleanup(root, runtime_only=False):
    root = canonical_root(root)
    parent = canonical_root(os.environ['RUNNER_TEMP'])
    require(root.parent == parent and re.fullmatch(r'f07-ci\.[A-Za-z0-9]{12}', root.name) is not None)
    allowed = {'runtime'} if runtime_only else {'runtime', 'upload', 'deps', 'native', 'sourcebuild'}
    require(set(p.name for p in root.iterdir()) <= {'runtime', 'upload', 'deps', 'native', 'sourcebuild'})
    if (root/'native').exists():
        validate_native_tree(root/'native', native_lock(), complete=False)
    if (root/'sourcebuild').exists():
        import native_source_build as source_build
        model=source_build.source_lock()['generated_output_model']
        source_build.validate_private_tree(root/'sourcebuild',model,complete=False)
    # Validate the entire bounded private tree before deleting anything. No links followed.
    paths = []
    for name in allowed:
        target = root/name
        if not target.exists():
            continue
        for base, dirs, files in os.walk(target, followlinks=False):
            for entry in [Path(base), *(Path(base)/n for n in dirs+files)]:
                info = entry.lstat()
                if entry.is_symlink():
                    if entry.is_relative_to(root/'sourcebuild'):
                        continue  # Exact source model/link targets validated above.
                    require(entry == root/'deps/lib64' and os.readlink(entry) == 'lib')
                    continue
                require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
                paths.append(entry)
                require(len(paths) <= 20000)
    require(sum(p.stat().st_size for p in paths if p.is_file()) <= 256*1048576)
    for name in allowed:
        if (root/name).exists():
            shutil.rmtree(root/name)
    if not runtime_only:
        root.rmdir()
    print('{"cleanup":"observed-owned-runtime"}' if runtime_only else '{"cleanup":"observed-owned-root"}')


# Root reviewed signed Ubuntu metadata and exact data archive membership.
NATIVE_LOCK_SHA256 = '246f1a7da1690b533e72e08640f7b3d18008b17835c9273813850d9093fd26f2'
PHASE = 'entry'
PHASES = {'entry', 'python-version', 'os-architecture', 'native-lock', 'native-download',
          'native-size-sha256', 'native-decode', 'native-extract', 'native-binary-notice',
          'private-bwrap-version', 'python-library', 'namespace', 'harness', 'cleanup'}


def diagnostic(phase, status):
    require(phase in PHASES and status in ('PASS', 'FAIL', 'START'))
    print(json.dumps({'scope':'f07-ci-bootstrap', 'phase':phase, 'status':status},
                     sort_keys=True, separators=(',', ':')), file=sys.stderr)


def phase(name):
    global PHASE
    require(name in PHASES)
    PHASE = name
    diagnostic(name, 'START')


def validate_native_lock(doc):
    # This is a closed immutable public manifest, not a generic package manager.
    require(type(doc) is dict and hashlib.sha256(encoded(doc)).hexdigest() == NATIVE_LOCK_SHA256,
            'native lock differs from root-reviewed bytes')
    return doc


def native_lock():
    path = ROOT/'tests/harness/native-ci.lock.json'
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16384 and not path.is_symlink())
    raw = path.read_bytes()
    doc = json.loads(raw, object_pairs_hook=unique)
    require(raw == encoded(doc))
    return validate_native_lock(doc)


def validate_native_platform(os_id, os_version, architecture, system):
    require((os_id, os_version, architecture, system) == ('ubuntu', '24.04', 'x86_64', 'Linux'),
            'unsupported native runner')


def validate_native_bytes(raw, lock):
    validate_native_lock(lock)
    expected = lock['package']
    require(type(raw) is bytes and len(raw) == expected['size'] and
            hashlib.sha256(raw).hexdigest() == expected['sha256'], 'native size or SHA256 mismatch')


def validate_native_members(members, lock):
    validate_native_lock(lock)
    require(type(members) is list and len(members) == lock['max_members'])
    require(encoded(members) == encoded(lock['members']), 'native tar member set differs')
    for item in members:
        require(type(item) is dict and set(item) == {'name', 'type', 'size', 'link'})
        name = item['name']
        require(name == '.' or (name.startswith('./') and
                re.fullmatch(r'[A-Za-z0-9_./-]+', name[2:]) is not None and
                all(part not in ('', '.', '..') for part in name[2:].split('/'))))
        require(item['type'] in ('0', '5') and item['link'] == '' and type(item['size']) is int)
    return members


def validate_native_tree(root, lock, complete=True):
    """Only the fresh private native subtree; no traversal or following links."""
    root = canonical_root(root)
    validate_native_lock(lock)
    allowed = {'payload':('5', 0), 'package.deb':('0', lock['package']['size'])}
    for item in lock['members']:
        if item['name'] != '.':
            allowed['payload/'+item['name'][2:]] = (item['type'], item['size'])
    seen = set()
    for base, dirs, files in os.walk(root, followlinks=False):
        for entry in [*(Path(base)/n for n in dirs+files)]:
            name = entry.relative_to(root).as_posix()
            require(name in allowed, 'unexpected native cleanup member')
            info = entry.lstat()
            kind, size = allowed[name]
            require(not entry.is_symlink() and info.st_nlink >= 1)
            require((kind == '5' and stat.S_ISDIR(info.st_mode)) or
                    (kind == '0' and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     (info.st_size == size if complete else 0 <= info.st_size <= size)))
            seen.add(name)
            require(len(seen) <= 31)
    require(not complete or seen == set(allowed))
    if complete:
        for name, digest in (('package.deb', lock['package']['sha256']),
                             ('payload/'+lock['package']['binary'], lock['package']['binary_sha256']),
                             ('payload/'+lock['package']['copyright'], lock['package']['copyright_sha256'])):
            require(hashlib.sha256((root/name).read_bytes()).hexdigest() == digest)


def extract_native_tar(raw, root, lock):
    import tarfile
    require(type(raw) is bytes and len(raw) <= lock['max_tar_bytes'])
    root = canonical_root(root)
    require(not list(root.iterdir()), 'native payload root not empty')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        infos = archive.getmembers()
        rows = [dict(name=m.name, type=m.type.decode('ascii'), size=m.size, link=m.linkname) for m in infos]
        validate_native_members(rows, lock)
        # Validate ALL entries before the first write. No extractall, links or control archive.
        require(all(not m.pax_headers and (m.type in (tarfile.REGTYPE, tarfile.DIRTYPE)) for m in infos))
        require(sum(m.size for m in infos) <= lock['max_tar_bytes'])
        for info in infos:
            if info.name == '.':
                continue
            path = root/info.name[2:]
            require(path.parent.resolve().is_relative_to(root))
            if info.isdir():
                path.mkdir(mode=0o755)
            else:
                stream = archive.extractfile(info)
                require(stream is not None)
                with stream:
                    data = stream.read(info.size+1)
                require(len(data) == info.size)
                with path.open('xb') as output:
                    require(output.write(data) == info.size)
                path.chmod(0o755 if info.name == './usr/bin/bwrap' else 0o644)


def python_library_path(prefix, libdir):
    prefix, libdir = Path(prefix), Path(libdir)
    approved = Path('/opt/hostedtoolcache/Python/3.12.3/x64')
    require(prefix == approved and prefix.resolve() == approved)
    require(libdir == approved/'lib' and libdir.resolve() == libdir and libdir.is_dir())
    library = libdir/'libpython3.12.so.1.0'
    require(library.is_file() and not library.is_symlink() and library.resolve().parent == libdir)
    return str(libdir)


def validate_namespace_exit(code):
    require(type(code) is int and code == 0, 'namespace or harness unsupported/failed')


def native_bootstrap(root):
    import platform
    import sysconfig
    phase('python-version')
    require(platform.python_version() == '3.12.3')
    diagnostic(PHASE, 'PASS')
    phase('os-architecture')
    os_release = platform.freedesktop_os_release()
    validate_native_platform(os_release.get('ID'), os_release.get('VERSION_ID'), platform.machine(), platform.system())
    diagnostic(PHASE, 'PASS')
    phase('native-lock')
    lock = native_lock()
    diagnostic(PHASE, 'PASS')
    root = canonical_root(root)
    parent = canonical_root(os.environ['RUNNER_TEMP'])
    require(root.parent == parent and re.fullmatch(r'f07-ci\.[A-Za-z0-9]{12}', root.name) is not None)
    native = root/'native'
    native.mkdir(mode=0o700)
    phase('native-download')
    # Exact reviewed HTTPS URL, no headers/credentials/proxies/redirects or index.
    request = urllib.request.Request(lock['package']['url'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=30) as response:
        require(response.status == 200)
        length = response.headers.get('Content-Length')
        require(length is None or length == str(lock['package']['size']))
        raw = response.read(lock['package']['size']+1)
    diagnostic(PHASE, 'PASS')
    phase('native-size-sha256')
    validate_native_bytes(raw, lock)
    with (native/'package.deb').open('xb') as stream:
        require(stream.write(raw) == len(raw))
    diagnostic(PHASE, 'PASS')
    phase('native-decode')
    # Read-only data decoder. NEVER dpkg -i, control extraction or maintainer scripts.
    decoded = subprocess.run(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(native/'package.deb')],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    require(decoded.returncode == 0 and len(decoded.stdout) <= lock['max_tar_bytes'])
    diagnostic(PHASE, 'PASS')
    phase('native-extract')
    payload = native/'payload'
    payload.mkdir(mode=0o700)
    extract_native_tar(decoded.stdout, payload, lock)
    diagnostic(PHASE, 'PASS')
    phase('native-binary-notice')
    validate_native_tree(native, lock)
    diagnostic(PHASE, 'PASS')
    phase('private-bwrap-version')
    version = subprocess.run([str(payload/lock['package']['binary']), '--version'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(version.returncode == 0 and version.stdout == b'bubblewrap 0.9.0\n')
    diagnostic(PHASE, 'PASS')
    phase('python-library')
    python_library_path(sys.base_prefix, sysconfig.get_config_var('LIBDIR'))
    diagnostic(PHASE, 'PASS')

# Output text is untrusted data. Only these two whole literals are root-approved
# SYNTHETIC TEXT classes, not observed policy errors or syscall errno evidence.
PERMISSION_TEXT = (
    b'bwrap: Creating new namespace failed: Operation not permitted\n',
    b'bwrap: Creating new namespace failed: Permission denied\n',
)
STDERR_PREFIX = 65536
STREAM_LIMIT = 1048576
DIAGNOSTIC_MAX = 4096


def classify_namespace_stderr(prefix, complete, truncated):
    require(type(prefix) is bytes and len(prefix) <= STDERR_PREFIX)
    require(type(complete) is bool and type(truncated) is bool)
    if not complete or truncated:
        return 'UNKNOWN', None
    if not prefix:
        return 'EMPTY', None
    if prefix in PERMISSION_TEXT:
        return 'NAMESPACE_PERMISSION_ERROR_TEXT', None
    # The entire canonical helper sequence may report a phase; no substring,
    # ANSI stripping, free-text field or claimed successful isolation is trusted.
    for name in sorted(PHASES):
        rows = [dict(scope='f07-ci-bootstrap', phase=name, status=value) for value in ('START', 'FAIL')]
        if prefix == b''.join(encoded(row) for row in rows):
            return 'INNER_HELPER_FAILURE_REPORTED', name
    return 'UNKNOWN', None


def validate_namespace_diagnostic(doc):
    fields = {'schema','status','reason','phase','inner_phase_reported','process_exit_code','process_signal',
              'errno','known_error_class','stderr_bytes_observed','stderr_prefix_bytes','stderr_prefix_sha256',
              'stderr_complete','stderr_truncated','stderr_limit_reached','stdout_limit_reached',
              'drain_incomplete','deadline_reached','child_reaped','tested_git_sha','pr_candidate_sha',
              'run_id','run_attempt'}
    require(type(doc) is dict and set(doc) == fields)
    require(doc['schema'] == 'f07-namespace-diagnostic-v1' and doc['status'] == 'FAIL')
    require(doc['phase'] == 'NAMESPACE_WRAPPER')
    require(doc['reason'] in {'CHILD_NONZERO','CHILD_SIGNAL','SPAWN_OS_ERROR','STREAM_IO_ERROR',
                              'DEADLINE','STREAM_LIMIT','DRAIN_INCOMPLETE','CHILD_REAP_INCOMPLETE'})
    require(doc['known_error_class'] in {'UNKNOWN','EMPTY','NAMESPACE_PERMISSION_ERROR_TEXT','INNER_HELPER_FAILURE_REPORTED'})
    require(doc['inner_phase_reported'] is None or doc['inner_phase_reported'] in PHASES)
    require((doc['inner_phase_reported'] is not None) == (doc['known_error_class'] == 'INNER_HELPER_FAILURE_REPORTED'))
    for key in ('stderr_complete','stderr_truncated','stderr_limit_reached','stdout_limit_reached',
                'drain_incomplete','deadline_reached','child_reaped'):
        require(type(doc[key]) is bool)
    number(doc['stderr_bytes_observed'], 0, STREAM_LIMIT)
    number(doc['stderr_prefix_bytes'], 0, STDERR_PREFIX)
    require(doc['stderr_prefix_bytes'] <= doc['stderr_bytes_observed'])
    require(doc['stderr_truncated'] == (doc['stderr_bytes_observed'] > doc['stderr_prefix_bytes']))
    require(not doc['stderr_limit_reached'] or doc['stderr_bytes_observed'] == STREAM_LIMIT)
    require(not doc['stderr_complete'] or not (doc['drain_incomplete'] or doc['stderr_limit_reached']))
    require(doc['known_error_class'] in ('UNKNOWN','EMPTY') or
            (doc['stderr_complete'] and not doc['stderr_truncated']))
    require(doc['known_error_class'] != 'EMPTY' or (doc['stderr_complete'] and doc['stderr_bytes_observed'] == 0))
    hex_value(doc['stderr_prefix_sha256'],64)
    if doc['stderr_prefix_bytes'] == 0: require(doc['stderr_prefix_sha256'] == hashlib.sha256(b'').hexdigest())
    for key, maximum in (('process_exit_code',255),('process_signal',64),('errno',4095)):
        if doc[key] is not None:
            number(doc[key], 0 if key == 'process_exit_code' else 1, maximum)
    require(doc['process_exit_code'] is None or doc['process_signal'] is None)
    if doc['reason'] == 'CHILD_NONZERO': require(doc['process_exit_code'] is not None and doc['process_exit_code'] > 0)
    if doc['reason'] == 'CHILD_SIGNAL': require(doc['process_signal'] is not None)
    if doc['reason'] == 'SPAWN_OS_ERROR':
        require(doc['process_exit_code'] is None and doc['process_signal'] is None and not doc['child_reaped'])
    if doc['errno'] is not None: require(doc['reason'] in ('SPAWN_OS_ERROR','STREAM_IO_ERROR'))
    if doc['reason'] == 'DEADLINE': require(doc['deadline_reached'])
    if doc['reason'] == 'STREAM_LIMIT': require(doc['stderr_limit_reached'] or doc['stdout_limit_reached'])
    if doc['reason'] == 'DRAIN_INCOMPLETE': require(doc['drain_incomplete'])
    if doc['reason'] == 'CHILD_REAP_INCOMPLETE': require(not doc['child_reaped'])
    hex_value(doc['tested_git_sha'],40);hex_value(doc['pr_candidate_sha'],40)
    number(doc['run_id']);number(doc['run_attempt'])
    require(len(encoded(doc)) <= DIAGNOSTIC_MAX)
    return doc


def read_namespace_pipe(descriptor):
    return os.read(descriptor,4096)


def capture_namespace_process(argv, timeout=600):
    """Fixed caller only. Nonblocking dual pipes; no full-output buffering/file."""
    import math
    import selectors
    import time
    require(type(timeout) in (int,float) and math.isfinite(timeout) and 0.1 <= timeout <= 600)
    started = time.monotonic()
    reserve = min(0.5, timeout/4)
    deadline = started + timeout - reserve
    state = dict(reason=None, code=None, errno=None, stderr=b'', stderr_count=0, stdout_count=0,
                 stderr_eof=False, stderr_limit=False, stdout_limit=False, drain=False, deadline=False, reaped=False)
    process = None
    selector = selectors.DefaultSelector()
    streams = []
    try:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, close_fds=True)
        except OSError as exc:
            state.update(reason='SPAWN_OS_ERROR', errno=exc.errno if type(exc.errno) is int and 1 <= exc.errno <= 4095 else None)
            return state
        for name, stream in (('stdout',process.stdout),('stderr',process.stderr)):
            streams.append(stream)
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,name)
        exited_at = None
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            code = process.poll()
            if code is not None and exited_at is None: exited_at = now
            if now >= deadline:
                state.update(reason='DEADLINE',deadline=True)
                break
            if exited_at is not None and now-exited_at >= 1:
                state.update(reason='DRAIN_INCOMPLETE',drain=True)
                break
            wait = min(0.05,deadline-now)
            if exited_at is not None: wait = min(wait,max(0,1-(now-exited_at)))
            try:
                ready = selector.select(wait) if selector.get_map() else []
            except InterruptedError:
                continue
            if not selector.get_map() and code is None: time.sleep(wait)
            for key,_ in ready:
                try:
                    chunk = read_namespace_pipe(key.fileobj.fileno())
                except (BlockingIOError,InterruptedError):
                    continue
                except OSError as exc:
                    state.update(reason='STREAM_IO_ERROR',errno=exc.errno if type(exc.errno) is int and 1 <= exc.errno <= 4095 else None)
                    break
                if not chunk:
                    if key.data == 'stderr': state['stderr_eof'] = True
                    selector.unregister(key.fileobj)
                    continue
                count = key.data+'_count'
                state[count] = min(STREAM_LIMIT,state[count]+len(chunk))
                if key.data == 'stderr':
                    state['stderr'] += chunk[:max(0,STDERR_PREFIX-len(state['stderr']))]
                if state[count] >= STREAM_LIMIT:
                    state[key.data+'_limit'] = True
                    state['reason'] = 'STREAM_LIMIT'
                    break
            if state['reason'] is not None: break
    except OSError as exc:
        state.update(reason='STREAM_IO_ERROR',errno=exc.errno if type(exc.errno) is int and 1 <= exc.errno <= 4095 else None)
    finally:
        selector.close()
        for stream in streams: stream.close()
        if process is not None:
            # Only this exact owned Popen child; no discovery, PID/name/group kill.
            if process.poll() is None:
                try: process.terminate()
                except ProcessLookupError: pass
                except OSError: state['reason'] = 'CHILD_REAP_INCOMPLETE'
                try: process.wait(timeout=reserve/2)
                except subprocess.TimeoutExpired:
                    try: process.kill()
                    except ProcessLookupError: pass
                    except OSError: state['reason'] = 'CHILD_REAP_INCOMPLETE'
                    try: process.wait(timeout=reserve/2)
                    except (subprocess.TimeoutExpired,OSError): state['reason'] = 'CHILD_REAP_INCOMPLETE'
                except OSError: state['reason'] = 'CHILD_REAP_INCOMPLETE'
            code = process.poll()
            state.update(code=code,reaped=code is not None)
    if state['reason'] is None and state['code'] != 0:
        state['reason'] = 'CHILD_SIGNAL' if state['code'] < 0 else 'CHILD_NONZERO'
    return state


def namespace_failure_receipt(state, tested, candidate, run_id, run_attempt):
    complete = state['stderr_eof'] and not state['stderr_limit'] and not state['drain']
    truncated = state['stderr_count'] > len(state['stderr'])
    error_class, reported = classify_namespace_stderr(state['stderr'],complete,truncated)
    code = state['code']
    doc = dict(schema='f07-namespace-diagnostic-v1',status='FAIL',reason=state['reason'],phase='NAMESPACE_WRAPPER',
        inner_phase_reported=reported,process_exit_code=code if type(code) is int and 0 <= code <= 255 else None,
        process_signal=-code if type(code) is int and -64 <= code < 0 else None,errno=state['errno'],
        known_error_class=error_class,stderr_bytes_observed=state['stderr_count'],stderr_prefix_bytes=len(state['stderr']),
        stderr_prefix_sha256=hashlib.sha256(state['stderr']).hexdigest(),stderr_complete=complete,
        stderr_truncated=truncated,stderr_limit_reached=state['stderr_limit'],stdout_limit_reached=state['stdout_limit'],
        drain_incomplete=state['drain'],deadline_reached=state['deadline'],child_reaped=state['reaped'],
        tested_git_sha=tested,pr_candidate_sha=candidate,run_id=run_id,run_attempt=run_attempt)
    return validate_namespace_diagnostic(doc)


SOURCE_BUILD_AUTHORIZATION_SHA256 = '85de32f8eba0691dc66168e4bcb49af9125c691ea9fc545a780fba74c845dba9'

def namespace_supervise(root, tested, candidate, run_id, run_attempt, native_variant='legacy-noble-v1'):
    import sysconfig
    root = canonical_root(root)
    parent = canonical_root(os.environ['RUNNER_TEMP'])
    require(root.parent == parent and re.fullmatch(r'f07-ci\.[A-Za-z0-9]{12}',root.name) is not None)
    hex_value(tested,40);hex_value(candidate,40)
    require(all(re.fullmatch('[1-9][0-9]{0,18}',v) is not None for v in (run_id,run_attempt)))
    number(int(run_id));number(int(run_attempt))
    if native_variant=='legacy-noble-v1':
        lock = native_lock();validate_native_tree(root/'native',lock)
        prefix=[str(root/'native/payload/usr/bin/bwrap')];timeout=600
    elif native_variant=='ubuntu-0.9.0-1ubuntu0.3-jammy-source-v1':
        import native_source_build as source_build
        prefix=source_build.runtime_prefix(root,SOURCE_BUILD_AUTHORIZATION_SHA256)
        timeout=source_build.runtime_budget(root)
    else:
        raise ValueError('unsupported explicit native variant')
    library = python_library_path(sys.base_prefix,sysconfig.get_config_var('LIBDIR'))
    # Same isolation/mount/environment argv as baseline427; no caller-supplied command.
    argv = [*prefix,'--unshare-all','--die-with-parent','--new-session',
        '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--symlink','usr/bin','/bin',
        '--ro-bind','/opt','/opt','--ro-bind','/etc/ld.so.cache','/etc/ld.so.cache','--proc','/proc','--dev','/dev',
        '--ro-bind',str(ROOT),str(ROOT),'--ro-bind',str(root/'deps'),str(root/'deps'),
        '--bind',str(root/'runtime'),str(root/'runtime'),'--bind',str(root/'upload'),str(root/'upload'),
        '--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','TMPDIR',str(root/'runtime'),
        '--setenv','PYTHONDONTWRITEBYTECODE','1','--setenv','F07_NETWORK_NAMESPACE_EXPECTED','1',
        '--setenv','LD_LIBRARY_PATH',library,'--chdir',str(ROOT),str(root/'deps/bin/python'),'-B',
        'tests/harness/ci_evidence.py','run',str(root/'upload'),tested,candidate]
    state = capture_namespace_process(argv,timeout=timeout)
    if state['reason'] is not None:
        try:
            print(encoded(namespace_failure_receipt(state,tested,candidate,int(run_id),int(run_attempt))).decode(),end='')
        except Exception:
            print('{"schema":"f07-namespace-diagnostic-v1","status":"FAIL","reason":"DIAGNOSTIC_INVALID"}')
        raise SystemExit(1)
    diagnostic('namespace','PASS')

def main():
    action, *args = sys.argv[1:]
    if action == 'suite':
        require(args in (['original'], ['helper']))
        print(encoded(suite(list(ORIGINAL) if args[0] == 'original' else ['test_ci_evidence','test_native_source_build'],
                            54 if args[0] == 'original' else None)).decode(), end='')
    elif action == 'source-inventory':
        import native_source_build as source_build
        print(source_build.canonical(source_build.inventory()).decode(),end='')
    elif action == 'source-bootstrap':
        import native_source_build as source_build
        try:
            source_build.source_bootstrap(*args,SOURCE_BUILD_AUTHORIZATION_SHA256)
        except source_build.QualificationHold as exc:
            print(source_build.canonical(dict(schema='f07-source-status-v1',status='HOLD',reason=str(exc))).decode(),end='')
            raise SystemExit(2)
    elif action == 'native-bootstrap':
        native_bootstrap(*args)
    elif action == 'python-library':
        import sysconfig
        phase('python-library')
        print(python_library_path(sys.base_prefix, sysconfig.get_config_var('LIBDIR')))
    elif action == 'namespace-supervise':
        phase('namespace')
        namespace_supervise(*args)
    elif action == 'namespace-result':
        phase('namespace')
        validate_namespace_exit(int(args[0]))
        diagnostic(PHASE, 'PASS')
    elif action == 'diagnostic':
        diagnostic(*args)
    elif action == 'run':
        phase('harness')
        run(*args)
    elif action == 'check':
        validate_bundle(*args, expected_sources=source_hashes())
    elif action == 'metadata':
        metadata(*args)
    elif action in ('cleanup', 'cleanup-runtime'):
        cleanup(*args, runtime_only=action == 'cleanup-runtime')
    else:
        raise ValueError('unknown action')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Fixed failure marker avoids urllib exception/header/path leakage.
        diagnostic(PHASE, 'FAIL')
        sys.exit(1)
