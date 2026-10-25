"""Offline adapter contract helpers. No network, native writes, or production store.

The in-memory Journal is a synthetic reference, not a durable runtime ledger.
Core envelope/receipt validation belongs to F04 before these adapter checks.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path

CATALOG = json.loads(Path(__file__).with_name("catalog.v1.json").read_text(encoding="utf-8"))
ADAPTERS = {item["adapter"]: item for item in CATALOG["adapters"]}
ERRORS = {
    "INVALID_REQUEST": "REJECTED", "AUTHENTICATION": "REJECTED",
    "PERMISSION": "REJECTED", "POLICY_HOLD": "HELD", "CONFLICT": "HELD",
    "NOT_FOUND": "REJECTED", "UNSUPPORTED_CAPABILITY": "HELD",
    "RATE_LIMITED_BEFORE_SUBMIT": "HELD", "TRANSIENT_BEFORE_SUBMIT": "HELD",
    "TIMEOUT_AFTER_SUBMIT": "UNKNOWN", "AMBIGUOUS_RESPONSE": "UNKNOWN",
    "MALFORMED_CALLBACK": "HELD", "STALE_EVIDENCE": "HELD",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_request(request):
    """Validate adapter-local intent after the F04 schemas have been checked."""
    require(type(request) is dict, "request must be an object")
    require(set(request) == {"schema_version", "adapter", "action", "account_ref",
                             "action_key", "expected_revision", "payload_ref",
                             "outbound_state"}, "unexpected or missing request fields")
    require(request["schema_version"] == "1.0", "unsupported adapter version")
    for field in ("adapter", "action", "account_ref", "action_key", "payload_ref"):
        require(type(request[field]) is str and bool(request[field].strip()), field)
    require(request["adapter"] in ADAPTERS, "unknown native owner")
    adapter = ADAPTERS[request["adapter"]]
    require(request["action"] in {a["name"] for a in adapter["actions"]}, "action not owned by adapter")
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", request["action_key"]) is not None, "F04 sha256-prefixed action key required")
    require(request["expected_revision"] is None or
            (type(request["expected_revision"]) is str and bool(request["expected_revision"].strip())), "invalid revision")
    require(request["outbound_state"] == "HOLD", "offline contract cannot authorize effects")
    return adapter


def error_decision(code, *, submitted):
    require(type(submitted) is bool, "submitted must be an exact boolean")
    require(code in ERRORS, "unknown error category")
    # Once delivery may have occurred, a transport failure never proves absence.
    if submitted and code in {"NOT_FOUND", "RATE_LIMITED_BEFORE_SUBMIT", "TRANSIENT_BEFORE_SUBMIT",
                              "TIMEOUT_AFTER_SUBMIT", "AMBIGUOUS_RESPONSE",
                              "MALFORMED_CALLBACK", "STALE_EVIDENCE"}:
        return "UNKNOWN"
    return ERRORS[code]


class Journal:
    """Synthetic account-scoped reservation/reconciliation behavior only."""
    def __init__(self):
        self.actions = {}
        self.callbacks = set()

    def reserve(self, request):
        validate_request(request)
        key = (request["adapter"], request["account_ref"], request["action_key"])
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if key in self.actions:
            require(self.actions[key]["fingerprint"] == fingerprint, "idempotency key reused for changed intent")
            return "REUSE_RECEIPT"  # Includes UNKNOWN: this is never submit permission.
        self.actions[key] = {"fingerprint": fingerprint, "status": "HELD", "provider_object_ref": None, "reservation_retained": True}
        return "RESERVED_HELD"

    def record_submitted(self, key):
        """Record simulated admission only; never dispatch an external action."""
        require(key in self.actions and self.actions[key]["status"] == "HELD", "held reservation required")
        self.actions[key]["status"] = "SUBMITTED"

    def record_unknown(self, key):
        require(key in self.actions and self.actions[key]["status"] == "SUBMITTED", "submitted reservation required")
        self.actions[key]["status"] = "UNKNOWN"

    def reconcile(self, key, *, outcome, evidence_ref, provider_object_ref=None):
        require(key in self.actions and self.actions[key]["status"] == "UNKNOWN", "only unresolved effects reconcile")
        require(type(evidence_ref) is str and bool(evidence_ref.strip()), "readback evidence required")
        require(outcome in {"OCCURRED", "NOT_OCCURRED"}, "ambiguous readback remains UNKNOWN")
        if outcome == "OCCURRED":
            require(type(provider_object_ref) is str and bool(provider_object_ref.strip()), "native object identity required")
        else:
            require(provider_object_ref is None, "absence cannot identify an occurred object")
        self.actions[key].update(status="RECONCILED", outcome=outcome,
                                 provider_object_ref=provider_object_ref, evidence_ref=evidence_ref,
                                 reservation_retained=(outcome == "OCCURRED"))
        return "REUSE_RECEIPT" if outcome == "OCCURRED" else "HOLD_FOR_NEW_AUTHORIZATION"


@dataclass(frozen=True)
class CallbackProof:
    """Produced by an allowlisted release-specific verifier, never from JSON."""
    authenticated: bool
    adapter: str
    account_ref: str
    provider_object_ref: str
    event_id: str
    occurred_at: int


def accept_callback(raw_body, headers, *, verifier, expected, now, max_age, journal):
    """Authenticate original bytes before applying a matching callback receipt.

    verifier is a trusted configured implementation, never a request parameter.
    Durable runtime implementations must atomically persist replay ID + receipt.
    """
    require(type(raw_body) is bytes, "original body bytes required")
    require(type(now) is int and type(max_age) is int and max_age > 0, "trusted clock window required")
    proof = verifier(raw_body, headers)
    require(type(proof) is CallbackProof and proof.authenticated is True, "callback authentication failed")
    require(type(expected) is tuple and len(expected) == 3 and
            all(type(value) is str and bool(value.strip()) for value in expected), "expected identity required")
    require(all(type(value) is str and bool(value.strip()) for value in
                (proof.adapter, proof.account_ref, proof.provider_object_ref)), "callback identity required")
    require((proof.adapter, proof.account_ref, proof.provider_object_ref) == expected, "callback destination mismatch")
    require(type(proof.occurred_at) is int and 0 <= now - proof.occurred_at <= max_age, "stale or future callback")
    require(type(proof.event_id) is str and bool(proof.event_id.strip()), "event identity required")
    replay_key = (proof.adapter, proof.account_ref, proof.event_id)
    if replay_key in journal.callbacks:
        return "DUPLICATE_NO_EFFECT"
    journal.callbacks.add(replay_key)
    return "VERIFIED_RECEIPT_ONLY"  # Never a business approval or retry authorization.
