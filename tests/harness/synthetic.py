"""Synthetic F07 fixtures. No sockets, provider SDKs, listeners or production DBs."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('f07_accepted_core', ROOT/'contracts/core/validate.py')
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
FIXTURES = ROOT/'tests/fixtures/shared'
SYNTHETIC_CALLBACK_KEY = b'f07-public-synthetic-test-material-not-a-credential'
ENDPOINTS = {
    'fake://wordpress/publish': ('WordPress', 'synthetic-wordpress-site'),
    'fake://postiz/publish': ('Postiz', 'synthetic-social-account'),
    'fake://mautic/send': ('Mautic', 'synthetic-mail-account'),
    'fake://voice/call': ('voice', 'synthetic-voice-account'),
    'fake://payments/charge': ('payments', 'synthetic-payment-account'),
    'fake://ads/spend': ('ads', 'synthetic-ad-account'),
}

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def scenario():
    return json.loads((FIXTURES/'scenario.json').read_text(encoding='utf-8-sig'))

class NetworkDenied(ValueError):
    pass

class FakeClock:
    def __init__(self, now='2026-10-25T12:10:00Z'):
        core.Draft202012Validator(core.SCHEMAS['common']['$defs']['datetime'], format_checker=core.FORMATS).validate(now)
        self._now = core.instant(now)
        if self._now.tzinfo is None:
            raise ValueError('timezone required')
    def now(self):
        return self._now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    def advance(self, seconds):
        if type(seconds) is not int or seconds < 0:
            raise ValueError('nonnegative integer seconds required')
        self._now += timedelta(seconds=seconds)

class FakeAuthority:
    """Synthetic OpenProject snapshot store, never an authorization implementation."""
    def __init__(self, approvals):
        self._approvals = {}
        self.available = True
        for approval in approvals:
            core.validate('approval-reference', approval)
            key = approval['approval_id']
            if key in self._approvals:
                raise ValueError('duplicate approval')
            self._approvals[key] = copy.deepcopy(approval)
    def get(self, key):
        if not self.available:
            raise ValueError('synthetic authority unavailable: HOLD')
        if key not in self._approvals:
            raise ValueError('unknown synthetic approval')
        return copy.deepcopy(self._approvals[key])
    def revoke(self, key):
        self._approvals[key]['status'] = 'REVOKED'

class FakeModel:
    def __init__(self):
        self.responses = json.loads((FIXTURES/'model-responses.json').read_text(encoding='utf-8-sig'))
    def respond(self, case):
        if case not in self.responses:
            raise ValueError('unconfigured model case: HOLD')
        return copy.deepcopy(self.responses[case])

class FakeProvider:
    """Exact in-process endpoint registry. It cannot fall back to HTTP or DNS."""
    MODES = {'ACCEPT', 'REJECT', 'TIMEOUT_AFTER_ACCEPT', 'TIMEOUT_BEFORE_ACCEPT'}
    def __init__(self, mode='ACCEPT'):
        if mode not in self.MODES:
            raise ValueError('unknown fake outcome')
        self.mode = mode
        self.calls = []
        self._objects = {}
    def destination(self, endpoint):
        # A fake prefix is insufficient: reject credentials, query, fragments and variants.
        parsed = urlsplit(endpoint)
        if parsed.scheme != 'fake' or endpoint not in ENDPOINTS:
            raise NetworkDenied('only exact in-process synthetic endpoints are allowed')
        return ENDPOINTS[endpoint]
    def request(self, endpoint, key, client_id, payload):
        provider, destination = self.destination(endpoint)
        if not client_id.startswith('synthetic-'):
            raise ValueError('synthetic identities only')
        self.calls.append((endpoint, key, client_id))
        if self.mode == 'REJECT':
            return None
        if self.mode != 'TIMEOUT_BEFORE_ACCEPT':
            self._objects[key] = {
                'provider': provider, 'destination': destination, 'client_id': client_id,
                'action_key': key, 'provider_object_ref': 'synthetic-object-'+hashlib.sha256(key.encode()).hexdigest()[:16],
            }
        if self.mode.startswith('TIMEOUT_'):
            raise TimeoutError('synthetic ambiguous result; must reconcile')
        return copy.deepcopy(self._objects[key])
    def readback(self, key):
        return copy.deepcopy(self._objects.get(key))
    def callback(self, key, clock, event_id='synthetic-callback-1'):
        obj = self.readback(key)
        if obj is None:
            raise ValueError('no synthetic object')
        body = encoded(dict(obj, event_id=event_id, occurred_at=clock.now()))
        signature = hmac.new(SYNTHETIC_CALLBACK_KEY, body, hashlib.sha256).hexdigest()
        return body, signature

class Harness:
    """Disposable SQLite and fake providers only; deliberately not production persistence."""
    def __init__(self, temp_root, clock=None, provider=None):
        parent = Path(temp_root)
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError('existing nonsymlink disposable parent required')
        self._temp = tempfile.TemporaryDirectory(prefix='f07-', dir=parent.resolve())
        self.directory = Path(self._temp.name)
        self.db = sqlite3.connect(self.directory/'synthetic.sqlite')
        self.db.executescript('''
          CREATE TABLE actions(action_key TEXT PRIMARY KEY, receipt TEXT NOT NULL);
          CREATE TABLE history(receipt_id TEXT PRIMARY KEY, action_key TEXT NOT NULL, receipt TEXT NOT NULL);
          CREATE TABLE callbacks(provider TEXT, client_id TEXT, event_id TEXT, action_key TEXT NOT NULL, PRIMARY KEY(provider,client_id,event_id));
        ''')
        self.clock = clock or FakeClock()
        self.provider = provider or FakeProvider()
        self.authority = FakeAuthority([scenario()['approval']])
        self.sequence = 0
        self.closed = False
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.close()
    def close(self):
        if not self.closed:
            self.db.close()
            self._temp.cleanup()
            self.closed = True
    def receipt(self, key):
        row = self.db.execute('SELECT receipt FROM actions WHERE action_key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None
    def _next_id(self):
        self.sequence += 1
        return 'synthetic-receipt-'+str(self.sequence)
    def _save(self, receipt, initial=False):
        core.validate('action-receipt', receipt)
        with self.db:
            if initial:
                self.db.execute('INSERT INTO actions VALUES (?,?)', (receipt['action_key'], encoded(receipt).decode()))
            else:
                self.db.execute('UPDATE actions SET receipt=? WHERE action_key=?', (encoded(receipt).decode(), receipt['action_key']))
            self.db.execute('INSERT INTO history VALUES (?,?,?)', (receipt['receipt_id'], receipt['action_key'], encoded(receipt).decode()))
        return copy.deepcopy(receipt)
    def _transition(self, previous, **changes):
        current = dict(previous, receipt_id=self._next_id(), recorded_at=self.clock.now(), **changes)
        core.check_transition(previous, current)
        return self._save(current)
    def submit(self, identity, approval_id, endpoint='fake://wordpress/publish', payload=None):
        # Deny a real endpoint before touching the DB, approval authority, or fake provider.
        provider, destination = self.provider.destination(endpoint)
        key = core.action_key(identity)
        if identity['source_system'] != provider or not identity['client_id'].startswith('synthetic-'):
            raise ValueError('wrong provider or nonsynthetic identity')
        existing = self.receipt(key)
        if existing is not None:
            if existing['destination'] != destination:
                raise ValueError('key reused across destinations')
            return existing  # Includes UNKNOWN and NOT_OCCURRED: never automatic replay.
        approval = self.authority.get(approval_id)
        core.check_approval(approval, client_id=identity['client_id'], approved_revision=identity['approved_revision'],
                            asset_sha256s=scenario()['approval']['asset_sha256s'], destination=destination,
                            action_scope=identity['action_scope'], now=self.clock.now())
        if identity['action_scope'] != 'publish:'+destination:
            raise ValueError('action scope must bind the exact fake destination')
        held = dict(schema_version='1.0', receipt_id=self._next_id(), action_identity=copy.deepcopy(identity),
                    action_key=key, event_id=identity['source_event_id'], correlation_id='synthetic-correlation',
                    approval_ref=None, destination=destination, attempt=1, recorded_at=self.clock.now(),
                    status='HELD', provider_object_ref=None, evidence_ref='synthetic-evidence',
                    reconciliation_ref=None, outbound_state='HOLD', reservation_retained=True,
                    reconciliation_outcome=None)
        self._save(held, initial=True)
        submitted = self._transition(held, status='SUBMITTED', approval_ref=approval_id)
        try:
            obj = self.provider.request(endpoint, key, identity['client_id'], payload or {})
        except TimeoutError:
            return self._transition(submitted, status='UNKNOWN')
        if obj is None:
            return self._transition(submitted, status='REJECTED', reservation_retained=False)
        return self._transition(submitted, status='ACCEPTED', provider_object_ref=obj['provider_object_ref'], outbound_state='CONFIRMED')
    def reconcile(self, key):
        previous = self.receipt(key)
        if previous is None or previous['status'] not in ('UNKNOWN','ACCEPTED'):
            raise ValueError('only uncertain or accepted actions require readback')
        obj = self.provider.readback(key)
        if obj is None:
            return self._transition(previous, status='RECONCILED', reconciliation_ref='synthetic-readback',
                                    reconciliation_outcome='NOT_OCCURRED', reservation_retained=False)
        if obj['client_id'] != previous['action_identity']['client_id'] or obj['destination'] != previous['destination']:
            raise ValueError('cross-client/destination readback')
        return self._transition(previous, status='RECONCILED', reconciliation_ref='synthetic-readback',
                                reconciliation_outcome='OCCURRED', provider_object_ref=obj['provider_object_ref'],
                                outbound_state='CONFIRMED', reservation_retained=True)
    def consume_callback(self, body, signature):
        if type(body) is not bytes or len(body)>8192 or type(signature) is not str:
            raise ValueError('bounded signed bytes required')
        expected = hmac.new(SYNTHETIC_CALLBACK_KEY, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError('invalid synthetic signature')
        def unique_fields(pairs):
            fields = {}
            for key, value in pairs:
                if key in fields:
                    raise ValueError('duplicate callback field')
                fields[key] = value
            return fields
        doc = json.loads(body, object_pairs_hook=unique_fields)
        if type(doc) is not dict or set(doc)!={'provider','destination','client_id','action_key','provider_object_ref','event_id','occurred_at'}:
            raise ValueError('malformed callback')
        if any(type(v) is not str or not v for v in doc.values()):
            raise ValueError('callback fields must be nonempty strings')
        core.Draft202012Validator(core.SCHEMAS['common']['$defs']['datetime'], format_checker=core.FORMATS).validate(doc['occurred_at'])
        age=(core.instant(self.clock.now())-core.instant(doc['occurred_at'])).total_seconds()
        if not 0<=age<=300:
            raise ValueError('stale/future callback')
        receipt=self.receipt(doc['action_key'])
        if receipt is None:
            raise ValueError('unknown callback action')
        if (doc['client_id'] != receipt['action_identity']['client_id'] or
                doc['provider'] != receipt['action_identity']['source_system'] or
                doc['destination'] != receipt['destination']):
            raise ValueError('callback does not belong to receipt')
        obj=self.provider.readback(doc['action_key'])
        if obj is None or any(doc[k]!=obj[k] for k in ('provider','destination','client_id','action_key','provider_object_ref')):
            raise ValueError('callback identity mismatch')
        seen=self.db.execute('SELECT action_key FROM callbacks WHERE provider=? AND client_id=? AND event_id=?',
                             (doc['provider'],doc['client_id'],doc['event_id'])).fetchone()
        if seen:
            if seen[0] != doc['action_key']:
                raise ValueError('callback event replayed for another action')
            return receipt
        result=self.reconcile(doc['action_key'])
        with self.db:
            self.db.execute('INSERT INTO callbacks VALUES (?,?,?,?)',(doc['provider'],doc['client_id'],doc['event_id'],doc['action_key']))
        return result


