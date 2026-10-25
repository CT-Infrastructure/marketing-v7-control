"""Synthetic contract tests: no native app, provider network, or real credentials."""
import copy
import hashlib
import hmac
import json
import unittest

from contract import ADAPTERS, CATALOG, CallbackProof, Journal, accept_callback, error_decision, validate_request


def request(adapter="wordpress", action="post.draft", account="synthetic-account"):
    # The same compact JSON tuple construction as the coordinated F04 contract.
    identity = ["synthetic-client", "synthetic-source", "event-1", action, "revision-1"]
    key = "sha256:" + hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return dict(schema_version="1.0", adapter=adapter, action=action, account_ref=account,
                action_key=key, expected_revision=None, payload_ref="synthetic/payload-1", outbound_state="HOLD")


class ContractTests(unittest.TestCase):
    def test_native_owner_boundaries(self):
        self.assertEqual(set(ADAPTERS), {"mautic", "wordpress", "postiz", "openproject", "resourcespace", "matomo", "serpbear", "asterisk", "providers"})
        for owner, definition in ADAPTERS.items():
            self.assertFalse(definition["direct_native_table_writes"])
            self.assertIsNone(definition["release"])
            for action in definition["actions"]:
                self.assertEqual(action["owner"], owner)
                validate_request(request(owner, action["name"]))
        self.assertIn("MariaDB", ADAPTERS["mautic"]["native_dependencies"])
        self.assertIn("Temporal", ADAPTERS["postiz"]["native_dependencies"])
        self.assertEqual(CATALOG["orchestrator"], "Activepieces")

    def test_f04_action_key_fixture_format(self):
        # Frozen vector from F04 contracts/core/fixtures/action-receipt.json.
        # The tuple is the actual fixture identity; this tests the shared wire key.
        identity = ["synthetic-client", "WordPress", "synthetic-event-0001", "publish", "revision-1"]
        expected = "sha256:275e4b76af8e7b725800806b12a12535175a726a7c39d4fad63012706b0a7e2f"
        computed = "sha256:" + hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(computed, expected)
        item = request(); item["action_key"] = expected
        validate_request(item)
        for value in [expected[7:], "SHA256:" + expected[7:], "sha512:" + expected[7:],
                      expected[:-1], expected + "0", expected + "\n", "sha256:" + "A" * 64]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_request(dict(item, action_key=value))

    def test_unknown_requires_submitted_transition(self):
        journal = Journal(); item = request(); journal.reserve(item)
        key = (item["adapter"], item["account_ref"], item["action_key"])
        with self.assertRaises(ValueError): journal.record_unknown(key)
        journal.record_submitted(key); journal.record_unknown(key)
        self.assertEqual(journal.actions[key]["status"], "UNKNOWN")

    def test_no_cross_owner_or_arbitrary_action(self):
        for owner, action in [("wordpress", "campaign.queue"), ("postiz", "transport.submit"),
                              ("mautic", "sql.execute"), ("providers", "post.publish")]:
            with self.subTest(owner=owner, action=action), self.assertRaises(ValueError):
                validate_request(request(owner, action))

    def test_invalid_contract_types_and_authority(self):
        for field, values in {"schema_version": [1, "2.0"], "outbound_state": ["CONFIRMED", True],
                              "account_ref": [None, "", [], True], "action_key": ["0", "G" * 64],
                              "expected_revision": [False, 1, ""]}.items():
            for value in values:
                item = request(); item[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_request(item)
        item = request(); item["approved"] = True
        with self.assertRaises(ValueError): validate_request(item)

    def test_duplicate_intent_reuses_receipt(self):
        journal = Journal(); item = request()
        self.assertEqual(journal.reserve(item), "RESERVED_HELD")
        self.assertEqual(journal.reserve(copy.deepcopy(item)), "REUSE_RECEIPT")
        self.assertEqual(len(journal.actions), 1)

    def test_changed_payload_cannot_reuse_key(self):
        journal = Journal(); item = request(); journal.reserve(item)
        for field, value in [("payload_ref", "synthetic/changed"), ("expected_revision", "r2")]:
            changed = dict(item, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError): journal.reserve(changed)

    def test_account_namespaces_do_not_collide(self):
        journal = Journal(); journal.reserve(request()); journal.reserve(request(account="other-synthetic-account"))
        self.assertEqual(len(journal.actions), 2)

    def test_unknown_retains_identity_and_blocks_resubmit(self):
        journal = Journal(); item = request(); journal.reserve(item)
        key = (item["adapter"], item["account_ref"], item["action_key"])
        journal.record_submitted(key); journal.record_unknown(key)
        self.assertEqual(journal.reserve(item), "REUSE_RECEIPT")
        self.assertEqual(journal.actions[key]["status"], "UNKNOWN")
        self.assertTrue(journal.actions[key]["reservation_retained"])
        with self.assertRaises(ValueError): journal.reconcile(key, outcome="PENDING", evidence_ref="synthetic/readback")
        self.assertEqual(journal.reconcile(key, outcome="OCCURRED", evidence_ref="synthetic/readback", provider_object_ref="native-1"), "REUSE_RECEIPT")
        with self.assertRaises(ValueError): journal.record_submitted(key)

    def test_absence_still_needs_new_authorization(self):
        journal = Journal(); item = request(); journal.reserve(item)
        key = (item["adapter"], item["account_ref"], item["action_key"]); journal.record_submitted(key); journal.record_unknown(key)
        with self.assertRaises(ValueError): journal.reconcile(key, outcome="NOT_OCCURRED", evidence_ref="")
        with self.assertRaises(ValueError): journal.reconcile(key, outcome="NOT_OCCURRED", evidence_ref="synthetic/readback", provider_object_ref="native-1")
        self.assertEqual(journal.reconcile(key, outcome="NOT_OCCURRED", evidence_ref="synthetic/readback"), "HOLD_FOR_NEW_AUTHORIZATION")
        self.assertFalse(journal.actions[key]["reservation_retained"])
        self.assertEqual(journal.reserve(item), "REUSE_RECEIPT")

    def test_error_classification_preserves_uncertainty(self):
        self.assertEqual(error_decision("TRANSIENT_BEFORE_SUBMIT", submitted=False), "HELD")
        self.assertEqual(error_decision("TRANSIENT_BEFORE_SUBMIT", submitted=True), "UNKNOWN")
        self.assertEqual(error_decision("TIMEOUT_AFTER_SUBMIT", submitted=True), "UNKNOWN")
        self.assertEqual(error_decision("PERMISSION", submitted=False), "REJECTED")
        self.assertEqual(error_decision("NOT_FOUND", submitted=False), "REJECTED")
        self.assertEqual(error_decision("NOT_FOUND", submitted=True), "UNKNOWN")
        for invalid in ["false", 0, None]:
            with self.assertRaises(ValueError): error_decision("PERMISSION", submitted=invalid)

    def callback(self, *, changes=None, tamper=False, journal=None):
        payload = dict(adapter="postiz", account_ref="synthetic-account", provider_object_ref="native-1", event_id="callback-1", occurred_at=100)
        payload.update(changes or {})
        body = json.dumps(payload).encode()
        # A test-only protocol: not a claim about any product signature format.
        key = b"public-synthetic-test-key"
        signature = hmac.new(key, body, hashlib.sha256).hexdigest()
        if tamper: body += b" "
        def verify(raw, headers):
            valid = hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).hexdigest(), headers["test-signature"])
            if not valid: return CallbackProof(False, "", "", "", "", 0)
            return CallbackProof(True, **json.loads(raw))
        return accept_callback(body, {"test-signature": signature}, verifier=verify,
                               expected=("postiz", "synthetic-account", "native-1"), now=110, max_age=30,
                               journal=journal or Journal())

    def test_callback_authentication_and_replay(self):
        journal = Journal()
        self.assertEqual(self.callback(journal=journal), "VERIFIED_RECEIPT_ONLY")
        self.assertEqual(self.callback(journal=journal), "DUPLICATE_NO_EFFECT")
        with self.assertRaises(ValueError): self.callback(tamper=True)

    def test_callback_scope_and_freshness(self):
        for change in [{"account_ref": "other-account"}, {"adapter": "mautic"},
                       {"provider_object_ref": "other-object"}, {"occurred_at": 79},
                       {"occurred_at": 111}, {"occurred_at": True}, {"event_id": ""}]:
            with self.subTest(change=change), self.assertRaises(ValueError): self.callback(changes=change)

    def test_payload_cannot_supply_verification_proof(self):
        with self.assertRaises(ValueError):
            accept_callback(b"{}", {}, verifier=lambda *_: {"authenticated": True},
                            expected=("postiz", "synthetic-account", "native-1"), now=110,
                            max_age=30, journal=Journal())


if __name__ == "__main__":
    unittest.main()
