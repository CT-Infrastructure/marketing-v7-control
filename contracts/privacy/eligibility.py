"""Offline F16 eligibility contract. No IO, legal decision, or dispatch authority."""
from dataclasses import dataclass
from datetime import datetime
import re

CHANNELS = frozenset({'email', 'phone', 'sms', 'tracking', 'audience_export'})
AUTHORITIES = {'email': 'Mautic', 'phone': 'PostgreSQL.telephone', 'sms': 'Mautic.sms',
               'tracking': 'tracking-consent-authority', 'audience_export': 'Mautic.audience-permission'}
REVIEW_ROLES = {'jurisdiction': 'privacy_reviewer', 'provider': 'provider_compliance_reviewer'}


@dataclass(frozen=True)
class Request:
    client_ref: str
    subject_ref: str
    channel: str
    purpose: str
    account_ref: str
    jurisdiction: str
    provider_ref: str
    now: str
    max_age_seconds: int
    asset_refs: tuple = ()


@dataclass(frozen=True)
class Permission:
    client_ref: str
    subject_ref: str
    channel: str
    purpose: str
    account_ref: str
    jurisdiction: str
    provider_ref: str
    source_authority: str
    granted: bool
    revoked: bool
    authority_available: bool
    valid_from: str
    expires_at: str
    observed_at: str
    evidence_ref: str


@dataclass(frozen=True)
class Review:
    kind: str
    client_ref: str
    channel: str
    purpose: str
    account_ref: str
    jurisdiction: str
    provider_ref: str
    status: str
    revoked: bool
    reviewer_role: str
    observed_at: str
    expires_at: str
    evidence_ref: str


@dataclass(frozen=True)
class Lifecycle:
    client_ref: str
    subject_ref: str
    deleted: bool
    suppressed: bool
    authority_available: bool
    observed_at: str
    retention_until: str | None
    authority_generation: int
    applied_generation: int
    restore_epoch: str | None
    replay_complete: bool
    replay_evidence_ref: str | None
    evidence_ref: str


@dataclass(frozen=True)
class AssetRight:
    asset_ref: str
    client_ref: str
    purpose: str
    account_ref: str
    revoked: bool
    valid_from: str
    expires_at: str
    observed_at: str
    evidence_ref: str


@dataclass(frozen=True)
class Decision:
    status: str
    reason: str
    responsible_role: str | None = None
    outbound_state: str = 'HOLD'


def identifier(value):
    return type(value) is str and re.fullmatch(r'[^\s\x00-\x1f\x7f]+', value) is not None


def instant(value):
    if type(value) is not str or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value) is None:
        raise ValueError('invalid UTC instant')
    return datetime.fromisoformat(value[:-1] + '+00:00')


def fresh(observed, now, max_age):
    age = (now - instant(observed)).total_seconds()
    return 0 <= age <= max_age


def binding_matches(record, request, fields):
    return all(getattr(record, key) == getattr(request, key) for key in fields)


BINDINGS = ('client_ref', 'channel', 'purpose', 'account_ref', 'jurisdiction', 'provider_ref')


def evaluate(request, permission, lifecycle, reviews=(), rights=()):
    """Consume caller-authenticated current snapshots; never fetch or invent them.

    Snapshot classes alone are not authentication. A trusted caller must verify
    native evidence, current revocation, reviewer authority and source bindings.
    """
    deny = lambda reason: Decision('DENY', reason)
    try:
        if type(request) is not Request or request.channel not in CHANNELS:
            return deny('INVALID_REQUEST')
        if not all(identifier(getattr(request, field)) for field in BINDINGS + ('subject_ref',)):
            return deny('INVALID_REQUEST')
        if type(request.max_age_seconds) is not int or request.max_age_seconds <= 0:
            return deny('INVALID_FRESHNESS_POLICY')
        if type(request.asset_refs) is not tuple or not all(identifier(x) for x in request.asset_refs) or len(set(request.asset_refs)) != len(request.asset_refs):
            return deny('INVALID_ASSET_SET')
        now = instant(request.now)
        if type(permission) is not Permission:
            return deny('MISSING_PERMISSION')
        if not binding_matches(permission, request, BINDINGS + ('subject_ref',)) or permission.source_authority != AUTHORITIES[request.channel]:
            return deny('PERMISSION_BINDING_MISMATCH')
        if permission.granted is not True or permission.revoked is not False or permission.authority_available is not True:
            return deny('PERMISSION_DENIED_OR_UNAVAILABLE')
        if not identifier(permission.evidence_ref) or not fresh(permission.observed_at, now, request.max_age_seconds) or not instant(permission.valid_from) <= now < instant(permission.expires_at):
            return deny('PERMISSION_STALE_OR_INVALID')
        if type(lifecycle) is not Lifecycle or not binding_matches(lifecycle, request, ('client_ref', 'subject_ref')):
            return deny('MISSING_LIFECYCLE_STATE')
        if lifecycle.deleted is not False or lifecycle.suppressed is not False or lifecycle.authority_available is not True:
            return deny('DELETED_SUPPRESSED_OR_UNAVAILABLE')
        if not identifier(lifecycle.evidence_ref) or not fresh(lifecycle.observed_at, now, request.max_age_seconds):
            return deny('STALE_LIFECYCLE_STATE')
        if any(type(x) is not int or x < 0 for x in (lifecycle.authority_generation, lifecycle.applied_generation)) or lifecycle.applied_generation != lifecycle.authority_generation:
            return deny('UNAPPLIED_REVOCATION_OR_DELETION')
        if type(lifecycle.replay_complete) is not bool:
            return deny('INVALID_REPLAY_STATE')
        if lifecycle.restore_epoch is not None:
            if not identifier(lifecycle.restore_epoch) or lifecycle.replay_complete is not True or not identifier(lifecycle.replay_evidence_ref):
                return deny('RESTORE_REPLAY_REQUIRED')
        if lifecycle.retention_until is None:
            return Decision('HOLD', 'RETENTION_POLICY_UNKNOWN', 'privacy_reviewer')
        if now >= instant(lifecycle.retention_until):
            return deny('RETENTION_EXPIRED')
        if type(reviews) is not tuple or any(type(x) is not Review for x in reviews):
            return deny('INVALID_REVIEW_EVIDENCE')
        for kind, role in REVIEW_ROLES.items():
            matches = [r for r in reviews if r.kind == kind]
            if len(matches) != 1:
                return Decision('HOLD', 'REVIEW_MISSING_OR_AMBIGUOUS', role)
            review = matches[0]
            if (not binding_matches(review, request, BINDINGS) or review.status != 'APPROVED'
                    or review.revoked is not False or review.reviewer_role != role
                    or not identifier(review.evidence_ref) or not fresh(review.observed_at, now, request.max_age_seconds)
                    or not now < instant(review.expires_at)):
                return Decision('HOLD', 'REVIEW_UNRESOLVED', role)
        if any(r.kind not in REVIEW_ROLES for r in reviews):
            return deny('UNKNOWN_REVIEW_KIND')
        if type(rights) is not tuple or any(type(x) is not AssetRight for x in rights):
            return deny('INVALID_RIGHTS_EVIDENCE')
        if len(rights) != len(request.asset_refs) or {r.asset_ref for r in rights} != set(request.asset_refs):
            return deny('MISSING_OR_AMBIGUOUS_ASSET_RIGHTS')
        for right in rights:
            if (not binding_matches(right, request, ('client_ref', 'purpose', 'account_ref'))
                    or right.revoked is not False or not identifier(right.evidence_ref)
                    or not fresh(right.observed_at, now, request.max_age_seconds)
                    or not instant(right.valid_from) <= now < instant(right.expires_at)):
                return deny('ASSET_RIGHTS_EXPIRED_OR_INVALID')
        return Decision('ELIGIBLE_OFFLINE', 'SNAPSHOTS_SATISFY_CONTRACT')
    except (ValueError, TypeError, AttributeError, OverflowError):
        return deny('MALFORMED_EVIDENCE')
