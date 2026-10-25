"""Trusted local wrapper over tools/scheduler.py; never launch processes or providers.

All inputs to proof/receipt methods must be authenticated by the calling controller.
Private SQLite only. These objects must never be exposed as worker RPC endpoints.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sqlite3
import time

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location('_f11_reference_scheduler', ROOT / 'tools/scheduler.py')
_REFERENCE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_REFERENCE)
_CAP_SPEC = importlib.util.spec_from_file_location('_f11_capacity_inputs', ROOT / 'docs/orchestration/capacity/check_dispatch_inputs.py')
_CAPACITY = importlib.util.module_from_spec(_CAP_SPEC)
_CAP_SPEC.loader.exec_module(_CAPACITY)
canonical_hash = _REFERENCE.canonical_hash


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def string(value):
    return type(value) is str and 0 < len(value) <= 4096 and '\x00' not in value


def sha(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def revision(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value) is not None


def number(value):
    return _CAPACITY.number(value)


def exact(value, fields, label):
    require(type(value) is dict and set(value) == set(fields.split()), 'Malformed ' + label)


AUTHORITY = 'independent reviewer + trusted integration controller'
CODE_KINDS = {'foundation', 'component', 'implementation', 'test-authoring', 'preservation', 'provider'}
RUNTIME_KINDS = {'verification', 'integration'}


def acceptance_requirement(task):
    require(task.get('completion_authority') == AUTHORITY, 'Missing or unsupported completion authority')
    kind = task.get('kind')
    require(kind in CODE_KINDS | RUNTIME_KINDS | {'selection', 'human-gate'}, 'Missing or unsupported task kind')
    if kind in {'selection', 'human-gate'} or task.get('manual'):
        return None
    declared = task.get('evidence_level')
    if kind in CODE_KINDS:
        require(declared in (None, 'CODE_MERGED', 'CODE_MERGED_ONLY'), 'Code task cannot substitute runtime-only evidence')
        return ('CODE_MERGED', 'verified-github-merge')
    require(declared in (None, 'SANDBOX_QUALIFIED', 'SANDBOX_QUALIFIED_ONLY'), 'Runtime task requires independent executor evidence')
    return ('SANDBOX_QUALIFIED', 'verified-independent-executor')

def result_digest(result):
    """Bind sanitized result content plus attempt identity; never include bearer token."""
    return canonical_hash({k: v for k, v in result.items() if k != 'lease_token'})


def validate_result(result, task):
    required = set('task_key lease_token fence input_sha256 base_revision status summary changed_paths tests artifacts blockers'.split())
    require(type(result) is dict and required <= set(result) <= required | {'actual_cost_usd'}, 'Malformed result fields')
    require(all(string(result[k]) for k in ('task_key', 'lease_token', 'summary')), 'Malformed result strings')
    require(type(result['fence']) is int and result['fence'] >= 1, 'Malformed result fence')
    require(sha(result['input_sha256']) and revision(result['base_revision']), 'Malformed result identity')
    require(result['task_key'] == task['key'], 'Wrong task')
    require(result['status'] in ('ready_for_review', 'blocked', 'failed'), 'Invalid result state')
    for key in ('changed_paths', 'tests', 'artifacts', 'blockers'):
        require(type(result[key]) is list, 'Malformed result list')
    require(all(string(p) and _REFERENCE.path_owned(p, task.get('write_paths', [])) for p in result['changed_paths']), 'Result path outside scope')
    require(len(set(result['changed_paths'])) == len(result['changed_paths']), 'Duplicate changed path')
    require(all(string(item) for item in result['blockers']), 'Malformed blocker')
    for test in result['tests']:
        exact(test, 'command exit_code environment', 'test result')
        require(string(test['command']) and string(test['environment']) and type(test['exit_code']) is int, 'Malformed test result')
    artifact_paths = []
    for artifact in result['artifacts']:
        exact(artifact, 'path sha256', 'artifact')
        require(string(artifact['path']) and sha(artifact['sha256']), 'Malformed artifact')
        require(_REFERENCE.safe_relative(artifact['path']) == artifact['path'].rstrip('/') and not artifact['path'].endswith('/'), 'Noncanonical artifact path')
        artifact_paths.append(artifact['path'])
    require(len(set(artifact_paths)) == len(artifact_paths), 'Duplicate artifact path')
    if 'actual_cost_usd' in result:
        require(number(result['actual_cost_usd']), 'Invalid untrusted reported cost')
    require(len(json.dumps(result, allow_nan=False)) <= 1024 * 1024, 'Oversized result')


F11_SCHEMA_VERSION = '2'


def preflight_existing_ledger(database, fixture_only):
    """Read-only refusal precedes reference schema setup, mkdir, chmod or writes."""
    path = Path(database)
    require(not path.is_symlink() and not getattr(path, 'is_junction', lambda: False)(), 'Linked ledger is forbidden')
    if not path.exists():
        return
    require(path.is_file(), 'Existing ledger must be a regular file')
    expected_mode = 'offline-fixture' if fixture_only else 'trusted-live-admission'
    try:
        with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            table = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone()
            require(table is not None, 'Unmarked ledger requires reviewed migration')
            mode = db.execute("SELECT value FROM metadata WHERE key='f11_mode'").fetchone()
            version = db.execute("SELECT value FROM metadata WHERE key='f11_schema_version'").fetchone()
            require(mode is not None and mode[0] == expected_mode, 'Unmarked or incompatible ledger mode requires reviewed migration')
            require(version is not None and version[0] == F11_SCHEMA_VERSION, 'Unmarked or incompatible ledger version requires reviewed migration')
            columns = {row[1] for row in db.execute('PRAGMA table_info(f11_attempts)')}
            require('launch_ref' in columns, 'Missing durable launch schema requires reviewed migration')
    except sqlite3.DatabaseError:
        raise ValueError('Unreadable or incompatible ledger requires reviewed migration') from None

class LocalController(_REFERENCE.Scheduler):
    """Reuse the bundled ledger, graph, claim ordering and atomic reservations."""
    def __init__(self, database, tasks, policy, clock=time.time, *, fixture_only=False, dispatch_inputs=None, measurements=None, trusted_admission_ref=None):
        require(type(fixture_only) is bool, 'Fixture mode must be Boolean')
        preflight_existing_ledger(database, fixture_only)
        self.fixture_only = fixture_only
        self.dispatch_inputs = copy.deepcopy(dispatch_inputs)
        self.measurements = copy.deepcopy(measurements)
        self.trusted_admission_ref = trusted_admission_ref
        tasks, policy = copy.deepcopy(tasks), copy.deepcopy(policy)
        require(type(tasks) is list and type(policy) is dict, 'Invalid configuration')
        for key in ('max_workers', 'lease_seconds', 'max_attempts'):
            require(type(policy.get(key)) is int and policy[key] > 0, 'Invalid integer policy')
        for key in ('max_cost_per_task_usd', 'total_cost_budget_usd'):
            require(number(policy.get(key)), 'Invalid budget')
        require(type(policy.get('capacities')) is dict and bool(policy['capacities']), 'Missing capacities')
        require(all(string(k) and number(v) for k, v in policy['capacities'].items()), 'Invalid capacities')
        for task in tasks:
            require(type(task) is dict and string(task.get('key')), 'Invalid task')
            acceptance_requirement(task)
            require(type(task.get('resources')) is dict, 'Missing resource reservation')
            require(set(task['resources']) <= set(policy['capacities']) and all(number(v) for v in task['resources'].values()), 'Unknown or invalid task resource')
            for key in ('write_paths', 'locks', 'depends_on'):
                require(type(task.get(key, [])) is list and all(string(v) for v in task.get(key, [])), 'Invalid task list')
                require(len(set(task.get(key, []))) == len(task.get(key, [])), 'Duplicate task list entry')
            for key in ('manual', 'enabled_by_default'):
                if key in task:
                    require(type(task[key]) is bool, 'Invalid task flag')
        super().__init__(database, tasks, policy, clock=clock)
        self._configuration = canonical_hash([self.tasks, self.policy, self.fixture_only, self.dispatch_inputs, self.measurements, self.trusted_admission_ref])
        with self._connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS f11_attempts (
                task_key TEXT NOT NULL, fence INTEGER NOT NULL, input_sha256 TEXT NOT NULL,
                base_revision TEXT NOT NULL, launch_ref TEXT NOT NULL, process_ref TEXT,
                candidate_revision TEXT, manifest_sha256 TEXT, result_sha256 TEXT,
                reconciliation TEXT, PRIMARY KEY (task_key, fence))''')
            columns = {r['name'] for r in db.execute('PRAGMA table_info(f11_attempts)')}
            require('launch_ref' in columns, 'Old wrapper schema requires reviewed migration, not implicit adoption')
            # The reference claim UPDATE and this INSERT share one SQLite transaction.
            db.execute('''CREATE TRIGGER IF NOT EXISTS f11_atomic_claim
                AFTER UPDATE OF state, fence ON tasks
                WHEN NEW.state='RUNNING' AND (OLD.state!='RUNNING' OR OLD.fence!=NEW.fence)
                BEGIN
                  INSERT INTO f11_attempts(task_key,fence,input_sha256,base_revision,launch_ref)
                  VALUES(NEW.key,NEW.fence,NEW.input_sha256,NEW.base_revision,'launch:' || NEW.input_sha256);
                END''')
            mode = 'offline-fixture' if fixture_only else 'trusted-live-admission'
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute("SELECT value FROM metadata WHERE key='f11_mode'").fetchone()
            require(prior is None or prior[0] == mode, 'Fixture/live ledger mode cannot change')
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('f11_mode', ?)", (mode,))
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('f11_schema_version', ?)", (F11_SCHEMA_VERSION,))
            db.commit()

    def _config(self):
        require(canonical_hash([self.tasks, self.policy, self.fixture_only, self.dispatch_inputs, self.measurements, self.trusted_admission_ref]) == self._configuration, 'Mutable configuration changed; reviewed migration required')

    @contextlib.contextmanager
    def _transaction(self):
        """Persist expiry even if the requested operation fails; rollback its writes."""
        self._config()
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._expire(db)
            db.execute('SAVEPOINT operation')
            try:
                yield db
            except Exception:
                db.execute('ROLLBACK TO operation')
                db.execute('RELEASE operation')
                self._expire(db)
                db.commit()
                raise
            else:
                db.execute('RELEASE operation')
                db.commit()

    def _current(self, db, key, token, fence):
        row = db.execute('SELECT * FROM tasks WHERE key=?', (key,)).fetchone()
        require(type(fence) is int and fence >= 1 and string(token), 'Malformed lease identity')
        require(row is not None and row['state'] == 'RUNNING' and row['token'] == token and row['fence'] == fence and row['lease_until'] > self.clock(), 'Stale or expired attempt')
        return row

    def claim(self, agent, base_revision, requested_key=None):
        self._config()
        require(string(agent) and revision(base_revision), 'Immutable revision and agent required')
        if not self.fixture_only:
            require(string(self.trusted_admission_ref), 'Trusted external admission verification required')
            require(self.measurements is not None, 'Measured capacity input required')
            require(not _CAPACITY.blockers(self.dispatch_inputs, self.measurements), 'F08 dispatch inputs remain HOLD')
        if requested_key is not None:
            require(requested_key in self.tasks, 'Unknown task request')
        # Reference claim uses BEGIN IMMEDIATE for resources, paths and explicit locks.
        return super().claim(agent, base_revision, requested_key)

    def _runnable(self, rows, agent=None):
        return [key for key in super()._runnable(rows, agent) if acceptance_requirement(self.tasks[key]) is not None]

    def status(self):
        self._config()
        return super().status()

    def heartbeat(self, key, token, fence):
        with self._transaction() as db:
            self._current(db, key, token, fence)
            db.execute('UPDATE tasks SET lease_until=?,updated=? WHERE key=?', (self.clock()+self.policy['lease_seconds'], self.clock(), key))

    def bind_process(self, key, token, fence, input_sha256, base_revision, process_ref):
        """Trusted launcher binds a durable job/launch-attempt ID before external work."""
        require(string(process_ref), 'Process or launch-attempt reference required')
        with self._transaction() as db:
            row = self._current(db, key, token, fence)
            require(row['input_sha256'] == input_sha256 and row['base_revision'] == base_revision, 'Wrong launch input')
            old = db.execute('SELECT * FROM f11_attempts WHERE task_key=? AND fence=?', (key, fence)).fetchone()
            require(old is not None and old['input_sha256']==input_sha256 and old['base_revision']==base_revision, 'Missing atomic launch attempt')
            require(old['process_ref'] is None or old['process_ref']==process_ref, 'Process binding cannot be replaced')
            db.execute('UPDATE f11_attempts SET process_ref=? WHERE task_key=? AND fence=?', (process_ref,key,fence))
            self._event(db, key, 'PROCESS_BOUND', {'fence':fence})

    def _proof(self, db, row, proof):
        attempt = db.execute('SELECT * FROM f11_attempts WHERE task_key=? AND fence=?', (row['key'], row['fence'])).fetchone()
        require(attempt is not None, 'Missing durable launch attempt; reviewed migration required')
        common = 'task_key fence input_sha256 base_revision effects_reconciled verified_by evidence_ref'
        if attempt['process_ref'] is None:
            exact(proof, common + ' launch_ref no_launch_confirmed', 'positive no-launch reconciliation')
            require(proof['no_launch_confirmed'] is True and proof['launch_ref']==attempt['launch_ref'], 'Positive independent no-launch proof required')
        else:
            exact(proof, common + ' process_ref terminated', 'process reconciliation')
            require(proof['terminated'] is True and proof['process_ref']==attempt['process_ref'], 'Positive bound-process termination proof required')
        require(proof['effects_reconciled'] is True, 'Positive external outcome reconciliation required')
        require(string(proof['verified_by']) and proof['verified_by'] != row['agent'] and string(proof['evidence_ref']), 'Independent trusted proof references required')
        require(type(proof['fence']) is int and all(proof[k] == row[k] for k in ('fence', 'input_sha256', 'base_revision')) and proof['task_key'] == row['key'], 'Wrong reconciliation attempt')
        return attempt
    def finish(self, result, *, reconciliation, candidate_revision, manifest_sha256, trusted_cost=None):
        # Validation belongs inside the savepoint so rejected late/malformed results still persist expiry.
        with self._transaction() as db:
            require(type(result) is dict and string(result.get('task_key')) and result['task_key'] in self.tasks, 'Unknown result task')
            validate_result(result, self.tasks[result['task_key']])
            row = self._current(db, result['task_key'], result['lease_token'], result['fence'])
            require(result['input_sha256'] == row['input_sha256'] and result['base_revision'] == row['base_revision'], 'Wrong immutable result input')
            require(revision(candidate_revision) and sha(manifest_sha256), 'Trusted candidate revision/manifest binding required')
            attempt=self._proof(db, row, reconciliation)
            require(attempt['process_ref'] is not None, 'A result requires a bound process; no-launch proof is recovery-only')
            require(trusted_cost is None or number(trusted_cost), 'Invalid trusted cost')
            self._settle(db, row, trusted_cost)
            sanitized = {k:v for k,v in result.items() if k != 'lease_token'}
            digest = result_digest(result)
            db.execute('UPDATE f11_attempts SET candidate_revision=?,manifest_sha256=?,result_sha256=?,reconciliation=? WHERE task_key=? AND fence=?', (candidate_revision, manifest_sha256, digest, json.dumps(reconciliation,sort_keys=True),row['key'],row['fence']))
            state = 'REVIEW' if result['status'] == 'ready_for_review' else 'BLOCKED'
            db.execute('UPDATE tasks SET state=?,result=?,token=NULL,lease_until=NULL,updated=? WHERE key=?', (state,json.dumps(sanitized,sort_keys=True),self.clock(),row['key']))
            self._event(db,row['key'],'RESULT',{'state':state,'fence':row['fence'],'result_sha256':digest})

    def reconcile_orphan(self, key, proof, retry=False, trusted_cost=None):
        require(type(retry) is bool, 'Retry flag must be Boolean')
        with self._transaction() as db:
            row=db.execute('SELECT * FROM tasks WHERE key=?',(key,)).fetchone()
            require(row is not None and row['state']=='ORPHANED','Task is not orphaned')
            self._proof(db,row,proof)
            require(trusted_cost is None or number(trusted_cost),'Invalid trusted cost')
            self._settle(db,row,trusted_cost)
            state='BACKLOG' if retry and row['attempts']<self.policy['max_attempts'] else 'BLOCKED'
            db.execute('UPDATE f11_attempts SET reconciliation=? WHERE task_key=? AND fence=?',(json.dumps(proof,sort_keys=True),key,row['fence']))
            db.execute('UPDATE tasks SET state=?,token=NULL,lease_until=NULL,updated=?,error=? WHERE key=?',(state,self.clock(),'Reconciled orphan',key))
            self._event(db,key,'ORPHAN_RECONCILED',{'state':state,'fence':row['fence']})

    def accept(self, key, receipt):
        with self._transaction() as db:
            exact(receipt,'task_key fence input_sha256 base_revision revision candidate_revision manifest_sha256 result_sha256 graph_sha256 policy_sha256 verified_by independent_review checks_verified evidence_level source verification_ref','acceptance receipt')
            row=db.execute('SELECT * FROM tasks WHERE key=?',(key,)).fetchone()
            require(row is not None and row['state']=='REVIEW' and not self.tasks[key].get('manual'),'Only candidate review may be accepted by this adapter')
            attempt=db.execute('SELECT * FROM f11_attempts WHERE task_key=? AND fence=?',(key,row['fence'])).fetchone()
            require(attempt is not None,'Missing candidate binding')
            require(receipt['task_key']==key and type(receipt['fence']) is int and receipt['fence']==row['fence'],'Wrong acceptance attempt')
            require(receipt['input_sha256']==row['input_sha256'] and receipt['base_revision']==row['base_revision'],'Wrong acceptance input')
            require(receipt['graph_sha256']==self.graph_hash and receipt['policy_sha256']==self.policy_hash,'Wrong acceptance configuration')
            require(revision(receipt['revision']) and receipt['candidate_revision']==attempt['candidate_revision'] and receipt['manifest_sha256']==attempt['manifest_sha256'] and receipt['result_sha256']==attempt['result_sha256'],'Wrong candidate/evidence identity')
            require(receipt['independent_review'] is True and receipt['checks_verified'] is True,'Positive independent checks required')
            require(string(receipt['verified_by']) and receipt['verified_by']!=row['agent'] and string(receipt['verification_ref']),'Independent verifier required')
            require((receipt['evidence_level'],receipt['source'])==acceptance_requirement(self.tasks[key]),'Evidence level/source does not satisfy task kind and authority')
            require(all(db.execute('SELECT state FROM tasks WHERE key=?',(dep,)).fetchone()[0]=='ACCEPTED' for dep in self.tasks[key].get('depends_on',[])),'Unaccepted prerequisite')
            db.execute('UPDATE tasks SET state=?,receipt=?,updated=? WHERE key=?',('ACCEPTED',json.dumps(receipt,sort_keys=True),self.clock(),key))
            self._event(db,key,'ACCEPTED',{'revision':receipt['revision'],'fence':row['fence'],'level':receipt['evidence_level']})
