"""Offline policy oracle, not deployed authorization or isolation enforcement."""
import hashlib
import hmac
import json
from pathlib import Path

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text(encoding='utf-8-sig'))

def capability(role, action, authority):
    # Authority must come from authenticated controller context, never source text.
    return (authority == 'trusted_packet' and isinstance(role, str)
            and isinstance(action, str)
            and action in POLICY['capabilities'].get(role, []))

def export_allowed(classification, sink, approved=False, synthetic=False):
    if classification not in POLICY['classes'] or type(approved) is not bool or type(synthetic) is not bool:
        return False
    if classification == 'public':
        return approved and sink in ('public_issue', 'shared_log', 'private_store')
    if classification == 'internal':
        return sink == 'private_store' or (synthetic and approved and sink in ('public_issue', 'shared_log'))
    # Confidential needs tenant authorization via private_read, not generic export.
    return False

def inherit_classification(labels):
    """Unknown or empty provenance cannot be downgraded into an exportable class."""
    if not isinstance(labels, (list, tuple)) or not labels:
        return None
    if any(not isinstance(label, str) or label not in POLICY['classes'] for label in labels):
        return None
    return max(labels, key=POLICY['classes'].index)


def reclassify(labels, requested):
    """Only unchanged or stricter labels here; owner-reviewed downgrade is external."""
    inherited = inherit_classification(labels)
    if inherited is None or requested not in POLICY['classes']:
        return None
    return requested if POLICY['classes'].index(requested) >= POLICY['classes'].index(inherited) else None


def private_read(role, classification, authenticated_tenant, object_tenant):
    return (capability(role, 'private_read', 'trusted_packet')
            and classification in ('internal', 'confidential')
            and isinstance(authenticated_tenant, str) and bool(authenticated_tenant)
            and authenticated_tenant == object_tenant)

def fetch_mock(role, url, authority='trusted_packet'):
    # Exact literals only, with no DNS/network access. Real SSRF enforcement is a separate gate.
    return capability(role, 'fetch_mock', authority) and url in POLICY['mock_targets']

def dispatch(role, request, approval, *, eligible=False, reconciled=False, outcome=None, eligibility_channel=None):
    # Offline review of a verified approval context. Does not authenticate approval objects.
    keys = ('tenant', 'revision', 'destination', 'channel', 'asset_set_hash', 'action_scope')
    if not capability(role, 'evaluate_dispatch', 'trusted_packet'):
        return False
    if not isinstance(request, dict) or not isinstance(approval, dict):
        return False
    if (request.get('channel') not in POLICY['supported_channels']
            or eligibility_channel != request.get('channel')
            or eligible is not True or reconciled is not True or outcome != 'confirmed'):
        return False
    if approval.get('human_verified') is not True or approval.get('expired') is not False:
        return False
    return all(isinstance(request.get(k), str) and bool(request[k])
               and request[k] == approval.get(k) for k in keys)

def webhook(role, body, signature, timestamp, now, event_id, authenticated_tenant, payload_tenant, seen, key, *, source_system='synthetic-default', authenticated_source='synthetic-default'):
    # Single-process synthetic replay set only. Production needs atomic durable deduplication.
    if not capability(role, 'verify_webhook', 'trusted_packet'):
        return False
    if not isinstance(body, bytes) or len(body) > POLICY['webhook_max_bytes']:
        return False
    if type(timestamp) is not int or type(now) is not int or not 0 <= now - timestamp <= POLICY['webhook_max_age_seconds']:
        return False
    if not isinstance(event_id, str) or not event_id :
        return False
    if not isinstance(authenticated_tenant, str) or not authenticated_tenant or authenticated_tenant != payload_tenant:
        return False
    if (not isinstance(source_system, str) or not source_system
            or source_system != authenticated_source):
        return False
    replay_key = (authenticated_tenant, authenticated_source, event_id)
    if replay_key in seen:
        return False
    if (not isinstance(key, bytes) or not key or not isinstance(signature, str)
            or len(signature) != 64 or any(c not in '0123456789abcdef' for c in signature)):
        return False
    # Bind synthetic event, time, tenant and raw bytes. Not any provider's wire protocol.
    message = json.dumps([event_id, timestamp, payload_tenant], separators=(',', ':')).encode() + b'\n' + body
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    seen.add(replay_key)
    return True

