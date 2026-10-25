"""Synthetic capability checks only: no real authentication or credential issuance.

The trusted launcher/issuer supplies immutable grants and authenticated contexts.
Untrusted callers cannot construct either through request JSON. Runtime integration,
durable revocation and cross-process replay protection require separate qualification.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import re
from threading import Lock

POLICY = json.loads((Path(__file__).resolve().parents[2] / "policies/secrets/roles.v1.json").read_text(encoding="utf-8"))
ROLES = {key: frozenset(value) for key, value in POLICY["roles"].items()}
MAX_TTL = POLICY["max_lifetime_seconds"]


def require(condition):
    if not condition:
        raise ValueError("credential contract denied")  # Never echo input or references.


def identifier(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", value) is not None


@dataclass(frozen=True)
class Grant:
    reference: str
    subject: str
    role: str
    task_id: str
    fence: int
    resource: str
    audience: str
    scopes: tuple
    issued_at: int
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class Context:
    subject: str
    task_id: str
    fence: int
    audience: str
    lease_until: int
    active: bool


def validate_grant(grant):
    require(type(grant) is Grant)
    require(all(identifier(getattr(grant, field)) for field in
                ("reference", "subject", "role", "task_id", "resource", "audience")))
    require(grant.role in ROLES)
    require(type(grant.fence) is int and grant.fence > 0)
    require(type(grant.scopes) is tuple and len(grant.scopes) > 0 and
            all(type(scope) is str for scope in grant.scopes))
    require(len(set(grant.scopes)) == len(grant.scopes) and set(grant.scopes) <= ROLES[grant.role])
    require(type(grant.issued_at) is int and type(grant.expires_at) is int)
    require(0 <= grant.issued_at < grant.expires_at and grant.expires_at - grant.issued_at <= MAX_TTL)
    require(type(grant.revoked) is bool)


class SyntheticBroker:
    """In-memory contract fixture. References are not bearer credentials."""
    def __init__(self, grants):
        self._grants = {}
        self._revoked = set()
        self._used = set()
        self._lock = Lock()
        for grant in grants:
            validate_grant(grant)
            require(grant.reference not in self._grants)
            self._grants[grant.reference] = grant

    def revoke(self, reference):
        # Trusted control-plane operation only; not a worker endpoint.
        require(type(reference) is str and reference in self._grants)
        with self._lock:
            self._revoked.add(reference)

    def authorize(self, reference, request, *, context, now, authority_available=False):
        require(type(authority_available) is bool and authority_available is True)
        require(type(now) is int and now >= 0)
        require(type(context) is Context and context.active is True)
        require(all(identifier(getattr(context, field)) for field in ("subject", "task_id", "audience")))
        require(type(context.fence) is int and context.fence > 0)
        require(type(context.lease_until) is int and now < context.lease_until)
        require(type(reference) is str and reference in self._grants)
        require(type(request) is dict and set(request) == {"schema_version", "role", "scope", "resource", "nonce"})
        require(request["schema_version"] == "1.0")
        require(all(identifier(request[key]) for key in ("role", "scope", "resource", "nonce")))
        with self._lock:
            grant = self._grants[reference]
            validate_grant(grant)
            require(grant.revoked is False and reference not in self._revoked)
            require(grant.issued_at <= now < grant.expires_at)
            require((grant.subject, grant.task_id, grant.fence, grant.audience) ==
                    (context.subject, context.task_id, context.fence, context.audience))
            require(grant.expires_at <= context.lease_until)
            require(request["role"] == grant.role and request["scope"] in grant.scopes and request["resource"] == grant.resource)
            replay_key = (reference, request["nonce"])
            require(replay_key not in self._used)
            self._used.add(replay_key)
            return {"decision": "SIMULATED_ALLOW", "scope": request["scope"], "external_effects": "HOLD"}
