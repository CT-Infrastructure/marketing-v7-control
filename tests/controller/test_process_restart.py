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

SOURCE_REVISION = '5761f6e4b1d1986c3f8cd55e3279921336f3cc92'
HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]


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
        # Retain evidence and synthetic DBs for independent review; no cleanup of supplied scratch.
        directory = Path(tempfile.mkdtemp(prefix='f11-process-', dir=scratch))
        evidence = dict(source_revision=SOURCE_REVISION, durability=durability, filesystem=filesystem,
                        power_loss='NOT_RUN', multi_host='NOT_RUN', cases=[])
        evidence['source_hashes'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (HERE, HERE.with_name('test_local.py'), ROOT/'orchestration/controller/local.py',
                      ROOT/'tools/scheduler.py')}
        try:
            for exit_mode in ('clean', 'abrupt'):
                for mode in ('path', 'lock', 'capacity', 'cost'):
                    with self.subTest(exit_mode=exit_mode, reservation=mode):
                        case_dir = directory / (exit_mode + '-' + mode)
                        case_dir.mkdir()
                        case = dict(exit_mode=exit_mode, reservation=mode)
                        evidence['cases'].append(case)
                        case['writer'] = self.run_child('writer', case_dir, mode, exit_mode)
                        self.assertEqual(case['writer']['exit_code'], 23 if exit_mode == 'abrupt' else 0)
                        case['verifier'] = self.run_child('verifier', case_dir, mode, exit_mode)
                        self.assertEqual(case['verifier']['exit_code'], 0)
                        checked = json.loads((case_dir/'verified.json').read_text())
                        self.assertEqual(checked['pid'], case['verifier']['pid'])
                        self.assertEqual(json.loads((case_dir/'before.json').read_text())['pid'], case['writer']['pid'])
                        self.assertNotEqual(case['writer']['pid'], case['verifier']['pid'])
                        case['comparison'] = checked
        finally:
            write_json(directory/'process-evidence.json', evidence)


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] in ('writer', 'verifier'):
        child(sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        unittest.main()