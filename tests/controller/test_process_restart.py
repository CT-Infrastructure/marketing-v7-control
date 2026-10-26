"""Opt-in, own-child process restart checks; see PROCESS_RESTART.md."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from test_local import LocalController, task, policy, result, proof, BASE, HEAD, MANIFEST

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
SOURCE_PATHS = ('tests/controller/test_process_restart.py',
                'tests/controller/test_process_revision.py', 'tests/controller/test_local.py',
                'orchestration/controller/local.py', 'tools/scheduler.py',
                'docs/orchestration/capacity/check_dispatch_inputs.py')


def revision(value):
    if type(value) is not str or re.fullmatch(r'[0-9a-f]{40}', value) is None or value == '0' * 40:
        raise ValueError('Expected a nonzero lowercase 40-hex source revision')
    return value


def source_hashes(root):
    hashes = {}
    for name in SOURCE_PATHS:
        path = root / name
        if any(p.is_symlink() or getattr(p, 'is_junction', lambda: False)()
               for p in (path, *path.parents)):
            raise ValueError('Linked source path forbidden')
        if not path.is_file() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('Source path is not a contained regular file')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('Duplicate provenance field')
        obj[key] = value
    return obj


def source_binding(root=ROOT, *, expected=None, manifest=None):
    """Check executor inputs, never authenticate them.

    The trusted executor supplies F11_PROCESS_EXPECTED_REVISION and, for exports,
    F11_PROCESS_SOURCE_MANIFEST (an absolute JSON file with source_revision and
    source_hashes for exactly SOURCE_PATHS). It must independently obtain these
    from its frozen revision and mount source read-only. An export declaration
    binds bytes but is NOT independent Git proof or a durability authorization.

    A candidate file digest is not a commit revision. In a checkout, the new
    regression file must already exist with these bytes at HEAD: an untracked
    or modified candidate fails the blob comparison. For an export, the executor
    must obtain revision AND hashes from the same frozen committed tree, not
    attach an ancestor revision to unpublished candidate bytes. This function
    cannot independently prove that external declaration; the evidence mode
    says so. After committing a candidate, rerun using its actual new HEAD and
    regenerated manifest before treating evidence as committed-revision proof.
    """
    root = Path(root)
    if not root.is_absolute() or root != root.resolve(strict=True):
        raise ValueError('Source root must be absolute and resolved')
    if expected is not None:
        revision(expected)
    hashes = source_hashes(root)
    declared = None
    if manifest is not None:
        if type(manifest) is not str or not manifest or not Path(manifest).is_absolute():
            raise ValueError('Manifest must be an explicit absolute executor path')
        declared = json.loads(Path(manifest).read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        if type(declared) is not dict or set(declared) != {'source_revision', 'source_hashes'}:
            raise ValueError('Malformed source manifest')
        revision(declared['source_revision'])
        covered = declared['source_hashes']
        if (type(covered) is not dict or set(covered) != set(SOURCE_PATHS)
                or any(type(v) is not str or re.fullmatch(r'[0-9a-f]{64}', v) is None
                       for v in covered.values()) or covered != hashes):
            raise ValueError('Source manifest coverage or bytes mismatch')
        if expected is None or declared['source_revision'] != expected:
            raise ValueError('Manifest needs matching executor expected revision')
    if (root / '.git').exists():
        # Ignore ambient cwd and Git routing/configuration environment. Linked
        # worktree .git files remain supported by git -C at this exact root.
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1')
        def git(*args):
            return subprocess.run(['git', '--no-replace-objects', '-C', str(root), *args],
                                  env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, check=True, timeout=15).stdout
        if Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve() != root:
            raise ValueError('Git checkout root mismatch')
        actual = revision(git('rev-parse', '--verify', 'HEAD^{commit}').decode('ascii').strip())
        if expected is not None and expected != actual:
            raise ValueError('Executor revision differs from checkout HEAD')
        for name, digest in hashes.items():
            if hashlib.sha256(git('show', actual + ':' + name)).hexdigest() != digest:
                raise ValueError('Relevant checkout source differs from HEAD')
        if git('rev-parse', '--verify', 'HEAD^{commit}').decode('ascii').strip() != actual:
            raise ValueError('Checkout advanced during provenance check')
        mode = 'checkout-git-head-and-blobs'
    else:
        if expected is None or declared is None:
            raise ValueError('Export requires executor revision and exact source manifest')
        actual = expected
        mode = 'executor-declared-export-with-verified-bytes'
    if source_hashes(root) != hashes:
        raise ValueError('Source changed during provenance check')
    return dict(source_revision=actual, source_hashes=hashes, source_provenance=mode)


def executor_binding():
    return source_binding(expected=os.environ.get('F11_PROCESS_EXPECTED_REVISION'),
                          manifest=os.environ.get('F11_PROCESS_SOURCE_MANIFEST'))


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def storage_root():
    durable = os.environ.get('F11_PROCESS_TEST_ROOT')
    temporary = os.environ.get('F11_PROCESS_TEMP_ROOT')
    if durable and temporary:
        raise ValueError('Select exactly one scratch mode')
    raw = durable or temporary
    if not raw:
        raise unittest.SkipTest('Dedicated scratch absent; durability NOT_RUN')
    path = Path(raw)
    require(path.is_absolute() and path.is_dir(), 'Scratch must be an existing absolute directory')
    require(not str(path).startswith(('\\\\', '//')), 'Network scratch forbidden')
    require(all(not p.is_symlink() and not getattr(p, 'is_junction', lambda: False)()
                for p in (path, *path.parents)), 'Linked scratch forbidden')
    path = path.resolve(strict=True)
    fs = 'unqualified-temporary'
    if durable:
        require(sys.platform == 'linux', 'Durable qualification requires Linux mount inspection')
        mounts = []
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            left, right = line.split(' - ', 1)
            fields = left.split()
            mount = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4]))
            if path == mount or mount in path.parents:
                mounts.append((len(mount.parts), right.split()[0]))
        require(bool(mounts), 'Cannot establish scratch filesystem')
        fs = max(mounts)[1]
        require(fs in {'ext4', 'xfs', 'btrfs'}, 'Scratch filesystem is not approved local durable storage')
    return path, ('PROCESS_RESTART_ONLY' if durable else 'NOT_RUN'), fs


def configuration(mode):
    tasks = [task('A', scope='src/shared/', locks=['synthetic-lock']),
             task('B', scope='src/shared/child/'),
             task('C', locks=['synthetic-lock']), task('D')]
    pol = policy(4 if mode in ('path', 'lock') else 1)
    if mode == 'cost':
        pol = policy(4)
        pol['total_cost_budget_usd'] = 1
    return tasks, pol


def snapshot(controller):
    status = controller.status()
    row = controller.record('A')
    return dict(record={k: row[k] for k in ('state', 'fence', 'attempts', 'lease_until',
                'base_revision', 'input_sha256', 'reserved_cost')},
                resources=status['resources_reserved'], reserved_usd=status['reserved_usd'],
                paths=controller.tasks['A']['write_paths'], locks=controller.tasks['A']['locks'])


def write_json(path, data):
    with path.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def child(role, directory, mode, exit_mode):
    tasks, pol = configuration(mode)
    now = [1000.0]
    controller = LocalController(directory / 'synthetic.sqlite3', tasks, pol,
                                 clock=lambda: now[0], fixture_only=True)
    if role == 'writer':
        packet = controller.claim('synthetic-author', BASE, 'A')
        require(packet is not None, 'Writer claim failed')
        controller.bind_process('A', packet['lease_token'], packet['fence'],
                                packet['input_sha256'], BASE, 'synthetic-writer')
        write_json(directory / 'before.json', dict(pid=os.getpid(), snapshot=snapshot(controller)))
        if exit_mode == 'abrupt':
            os._exit(23)  # Only this exact fixture child; all transactions already committed.
        return
    before = json.loads((directory / 'before.json').read_text())
    after = snapshot(controller)
    require(after == before['snapshot'], 'Restart changed persisted reservations/identity')
    require(after['record']['state'] == 'RUNNING', 'Current attempt lost')
    target = {'path': 'B', 'lock': 'C', 'capacity': 'D', 'cost': 'D'}[mode]
    require(controller.claim('conflicting-author', BASE, target) is None, 'Conflicting admission succeeded')
    # Read the synthetic bearer only in child memory; never serialize it into evidence.
    with controller._connection() as db:
        token = db.execute("SELECT token FROM tasks WHERE key='A'").fetchone()[0]
    packet = dict(task_key='A', lease_token=token, fence=after['record']['fence'],
                  input_sha256=after['record']['input_sha256'], base_revision=BASE, task=tasks[0])
    stale = result(packet)
    stale['fence'] += 1
    try:
        controller.finish(stale, reconciliation=proof(packet, 'synthetic-writer'),
                          candidate_revision=HEAD, manifest_sha256=MANIFEST)
    except ValueError:
        pass
    else:
        raise AssertionError('Stale completion accepted')
    require(snapshot(controller) == after, 'Rejected completion changed reservations')
    now[0] = 1011.0  # Deterministic expiry; no wall-clock sleeps.
    expired = snapshot(controller)
    expected = json.loads(json.dumps(after))
    expected['record']['state'] = 'ORPHANED'
    require(expired == expected, 'Expiry released or changed reservations')
    require(controller.claim('conflicting-author', BASE, target) is None, 'Quarantine admitted conflict')
    require(snapshot(controller) == expired, 'Admission changed quarantine')
    write_json(directory / 'verified.json', dict(pid=os.getpid(), before=after, expired=expired,
               comparisons=dict(restart_equal=True, stale_rejected=True, conflict_rejected=True,
                                quarantine_retained=True)))


class ProcessRestartTests(unittest.TestCase):
    def run_child(self, role, directory, mode, exit_mode):
        child_env = {k: v for k, v in os.environ.items() if k not in ('PYTHONPATH', 'PYTHONHOME')}
        child_env['PYTHONDONTWRITEBYTECODE'] = '1'
        proc = subprocess.Popen([sys.executable, '-B', str(HERE), role, str(directory), mode, exit_mode],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=child_env, cwd=str(ROOT))
        try:
            code = proc.wait(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()  # Popen handle for this fixture child only; never a PID search/group kill.
            proc.wait(timeout=10)
            self.fail('Exact fixture child timed out and was killed/reaped')
        return dict(pid=proc.pid, exit_code=code)

    def test_restart_reservations_in_distinct_processes(self):
        scratch, durability, filesystem = storage_root()
        binding = executor_binding()
        # Retain evidence and synthetic DBs for independent review; no cleanup of supplied scratch.
        directory = Path(tempfile.mkdtemp(prefix='f11-process-', dir=scratch))
        evidence = dict(**binding, durability=durability, filesystem=filesystem,
                        power_loss='NOT_RUN', multi_host='NOT_RUN', cases=[])
        evidence['source_binding_complete'] = False
        try:
            for exit_mode in ('clean', 'abrupt'):
                for mode in ('path', 'lock', 'capacity', 'cost'):
                    with self.subTest(exit_mode=exit_mode, reservation=mode):
                        case_dir = directory / (exit_mode + '-' + mode)
                        case_dir.mkdir()
                        case = dict(exit_mode=exit_mode, reservation=mode)
                        evidence['cases'].append(case)
                        self.assertEqual(executor_binding(), binding)
                        case['writer'] = self.run_child('writer', case_dir, mode, exit_mode)
                        self.assertEqual(case['writer']['exit_code'], 23 if exit_mode == 'abrupt' else 0)
                        case['verifier'] = self.run_child('verifier', case_dir, mode, exit_mode)
                        self.assertEqual(case['verifier']['exit_code'], 0)
                        checked = json.loads((case_dir/'verified.json').read_text())
                        self.assertEqual(checked['pid'], case['verifier']['pid'])
                        self.assertEqual(json.loads((case_dir/'before.json').read_text())['pid'], case['writer']['pid'])
                        self.assertNotEqual(case['writer']['pid'], case['verifier']['pid'])
                        case['comparison'] = checked
                        self.assertEqual(executor_binding(), binding)
            evidence['source_binding_complete'] = True
        finally:
            write_json(directory/'process-evidence.json', evidence)


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] in ('writer', 'verifier'):
        executor_binding()
        child(sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        unittest.main()
