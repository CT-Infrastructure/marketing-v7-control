"""Offline reference checks. Validation is not authorization or a dispatch service."""
import hashlib
import json
from datetime import datetime
from pathlib import Path, PurePosixPath
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / 'schemas' / 'runtime'
SCHEMAS = {p.stem.removesuffix('.schema'): json.loads(p.read_text(encoding='utf-8')) for p in SCHEMA_ROOT.glob('*.schema.json')}
REGISTRY = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in SCHEMAS.values())
FORMATS = FormatChecker()

@FORMATS.checks('date-time', raises=(ValueError, TypeError))
def valid_datetime(value):
    if not isinstance(value, str):
        return True
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.tzinfo is not None

FIELDS = ('client_id', 'source_system', 'source_event_id', 'action_scope', 'approved_revision')

def validate(kind, value):
    Draft202012Validator(SCHEMAS[kind], registry=REGISTRY, format_checker=FORMATS).validate(value)
    if kind == 'event-envelope' and instant(value['received_at']) < instant(value['occurred_at']):
        raise ValueError('received_at precedes occurred_at')
    if kind == 'approval-reference' and instant(value['expires_at']) <= instant(value['approved_at']):
        raise ValueError('approval expiry must follow approval')
    if kind == 'action-receipt':
        if value['event_id'] != value['action_identity']['source_event_id']:
            raise ValueError('receipt event does not match action source event')
        if value['action_key'] != action_key(value['action_identity']):
            raise ValueError('action key mismatch')
    if kind == 'evidence-manifest':
        if len({c['id'] for c in value['cases']}) != len(value['cases']):
            raise ValueError('duplicate case IDs')
        for path in value['artifact_hashes']:
            p = PurePosixPath(path)
            if p.is_absolute() or '..' in p.parts or '\\' in path or ':' in path or not p.parts:
                raise ValueError('artifact path must be relative and contained')
    return value

def instant(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def action_key(identity):
    Draft202012Validator(SCHEMAS['common']['$defs']['action_identity'], registry=REGISTRY).validate(identity)
    data = json.dumps([identity[k] for k in FIELDS], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return 'sha256:' + hashlib.sha256(data).hexdigest()

def check_approval(approval, *, client_id, approved_revision, asset_sha256s, destination, action_scope, now):
    validate('approval-reference', approval)
    Draft202012Validator(SCHEMAS['common']['$defs']['datetime'], format_checker=FORMATS).validate(now)
    expected = {'client_id': client_id, 'approved_revision': approved_revision, 'destination': destination, 'action_scope': action_scope}
    if any(approval[k] != v for k, v in expected.items()) or set(approval['asset_sha256s']) != set(asset_sha256s):
        raise ValueError('approval binding mismatch')
    if approval['status'] != 'APPROVED' or not instant(approval['approved_at']) <= instant(now) < instant(approval['expires_at']):
        raise ValueError('approval is stale, future, or revoked')
    return True

def check_transition(previous, current):
    """Check append-only receipt linkage, not external truth or database atomicity."""
    validate('action-receipt', previous)
    validate('action-receipt', current)
    for field in ('action_key', 'action_identity', 'event_id', 'correlation_id', 'approval_ref', 'destination'):
        if previous[field] != current[field]:
            raise ValueError('receipt identity changed')
    if previous['provider_object_ref'] is not None and current['provider_object_ref'] != previous['provider_object_ref']:
        raise ValueError('established provider object identity changed')
    if current['receipt_id'] == previous['receipt_id'] or instant(current['recorded_at']) < instant(previous['recorded_at']):
        raise ValueError('receipt is not a new chronological record')
    allowed = {'HELD': {'SUBMITTED'}, 'SUBMITTED': {'ACCEPTED', 'REJECTED', 'UNKNOWN'}, 'UNKNOWN': {'RECONCILED'}, 'ACCEPTED': {'RECONCILED'}, 'REJECTED': set(), 'RECONCILED': set()}
    if current['status'] not in allowed[previous['status']]:
        raise ValueError('forbidden transition; UNKNOWN cannot be retried')
    if current['attempt'] != previous['attempt']:
        raise ValueError('a transition cannot create a retry attempt')
    return True
