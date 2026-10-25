"""Only synthetic references and deliberately fake credentials; no external I/O."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import unittest

from broker import Context, Grant, ROLES, SyntheticBroker
from redaction import MARKER, redact


def grant(**changes):
    value = Grant("synthetic-grant", "synthetic-worker", "coding_worker", "F10-test", 1,
                  "repo:synthetic/control", "synthetic-artifacts", ("artifact.write",), 100, 200)
    return replace(value, **changes)


def context(**changes):
    return replace(Context("synthetic-worker", "F10-test", 1, "synthetic-artifacts", 250, True), **changes)


def request(**changes):
    return dict({"schema_version": "1.0", "role": "coding_worker", "scope": "artifact.write",
                 "resource": "repo:synthetic/control", "nonce": "synthetic-operation-1"}, **changes)


def check(broker=None, item=None, **changes):
    return (broker or SyntheticBroker([grant()])).authorize("synthetic-grant", item or request(),
            context=changes.pop("context", context()), now=changes.pop("now", 150),
            authority_available=changes.pop("authority_available", True), **changes)


class BrokerTests(unittest.TestCase):
    def test_valid_capability_is_only_simulated(self):
        self.assertEqual(check(), {"decision": "SIMULATED_ALLOW", "scope": "artifact.write", "external_effects": "HOLD"})

    def test_roles_are_separate_and_workers_have_no_credentials(self):
        self.assertEqual(ROLES["coding_worker"], {"source.read", "artifact.write"})
        self.assertNotIn("github.repository.admin", ROLES["integrator"])
        self.assertNotIn("github.merge.request", ROLES["reviewer"])
        self.assertNotIn("github.branch.write", ROLES["metadata_coordinator"])
        for scope in ["github.repository.admin", "age.private_key", "smtp.credential", "sip.credential",
                      "payment.credential", "deploy.token", "model.api_key"]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                SyntheticBroker([grant(scopes=(scope,))])

    def test_each_role_uses_only_its_preapproved_scope(self):
        for role, scopes in ROLES.items():
            for scope in scopes:
                with self.subTest(role=role, scope=scope):
                    broker = SyntheticBroker([grant(role=role, scopes=(scope,))])
                    decision = check(broker=broker, item=request(role=role, scope=scope))
                    self.assertEqual(decision["external_effects"], "HOLD")

    def test_forged_role_scope_or_extra_authority_is_denied(self):
        for change in [{"role": "bootstrap_admin"}, {"scope": "github.repository.admin"},
                       {"scope": "*"}, {"approved": True}, {"schema_version": "2.0"}]:
            with self.subTest(change=change), self.assertRaises(ValueError): check(item=request(**change))

    def test_cross_subject_task_fence_audience_resource_denied(self):
        for change in [{"subject": "other"}, {"task_id": "other"}, {"fence": 2},
                       {"audience": "other"}, {"active": False}]:
            with self.subTest(change=change), self.assertRaises(ValueError): check(context=context(**change))
        with self.assertRaises(ValueError): check(item=request(resource="repo:synthetic/other"))
        with self.assertRaises(ValueError):
            SyntheticBroker([grant()]).authorize("forged-grant", request(), context=context(), now=150, authority_available=True)

    def test_expiry_future_issue_and_lease_boundaries(self):
        for now in [99, 200, 201]:
            with self.subTest(now=now), self.assertRaises(ValueError): check(now=now)
        self.assertEqual(check(now=100)["decision"], "SIMULATED_ALLOW")
        self.assertEqual(check(now=199)["decision"], "SIMULATED_ALLOW")
        with self.assertRaises(ValueError): check(context=context(lease_until=150))
        with self.assertRaises(ValueError): check(context=context(lease_until=199))

    def test_revocation_and_authority_outage_fail_closed(self):
        broker = SyntheticBroker([grant()]); check(broker=broker)
        broker.revoke("synthetic-grant")
        with self.assertRaises(ValueError): check(broker=broker, item=request(nonce="after-revocation"))
        with self.assertRaises(ValueError): check(broker=SyntheticBroker([grant(revoked=True)]))
        for available in [False, None, "true", 1]:
            with self.subTest(available=available), self.assertRaises(ValueError): check(authority_available=available)
        with self.assertRaises(ValueError):
            SyntheticBroker([grant()]).authorize("synthetic-grant", request(), context=context(), now=150)

    def test_malformed_types_are_not_truthy_authority(self):
        for change in [{"fence": True}, {"issued_at": False}, {"expires_at": 200.0},
                       {"revoked": "false"}, {"scopes": "artifact.write"}, {"scopes": ()},
                       {"scopes": ("artifact.write", "artifact.write")}, {"resource": "*"},
                       {"subject": "bad subject"}, {"expires_at": 401}]:
            with self.subTest(change=change), self.assertRaises(ValueError): SyntheticBroker([grant(**change)])
        for now in [True, 150.0, "150", None]:
            with self.subTest(now=now), self.assertRaises(ValueError): check(now=now)
        for change in [{"active": 1}, {"fence": True}, {"lease_until": 250.0}]:
            with self.subTest(change=change), self.assertRaises(ValueError): check(context=context(**change))
        for change in [{"nonce": []}, {"scope": True}, {"role": None}]:
            with self.subTest(change=change), self.assertRaises(ValueError): check(item=request(**change))
        with self.assertRaises(ValueError): check(context={"active": True})

    def test_replay_is_atomic_within_one_process(self):
        broker = SyntheticBroker([grant()])
        def attempt(_):
            try:
                check(broker=broker)
                return "allowed"
            except ValueError:
                return "denied"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [1, 2]))
        self.assertEqual(sorted(results), ["allowed", "denied"])
        self.assertEqual(check(broker=broker, item=request(nonce="new-operation"))["decision"], "SIMULATED_ALLOW")

    def test_denials_do_not_echo_untrusted_input(self):
        fake = "deliberately-sensitive-input"
        try:
            check(item=request(scope=fake))
        except ValueError as error:
            self.assertNotIn(fake, str(error))
        else:
            self.fail("unexpected allow")


class RedactionTests(unittest.TestCase):
    def fake_values(self):
        return ["ghp_" + "A" * 36, "github_pat_" + "b" * 60,
                "sk-proj-" + "c" * 48, "AGE-SECRET-KEY-" + "D" * 48,
                "eyJzeW50aGV0aWMiOiJ0cnVlIn0.eyJpZCI6InRlc3QifQ.fakeSignature123",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END OPENSSH PRIVATE KEY-----"]

    def test_fake_secrets_redacted_across_prompt_log_artifact(self):
        for surface in ["prompt", "log", "artifact"]:
            for fake in self.fake_values():
                with self.subTest(surface=surface):
                    safe = redact({"surface": surface, "message": "before " + fake + " after"})
                    self.assertNotIn(fake, json.dumps(safe))
                    self.assertIn(MARKER, safe["message"])

    def test_authorization_urls_and_assignments(self):
        for fake in ["Bearer SYNTHETICbearer123", "Basic U1lOVEhFVElDOkZBS0U=",
                     "smtp://synthetic:fake-password@mail.invalid", "postgresql://synthetic:fake-password@db.invalid/x",
                     "password=fake-password", 'api_key="fake-api-value"', "SIP_PASSWORD='fake-sip-value'",
                     '"password": "fake-json-password"']:
            with self.subTest(kind=fake.split(':')[0]):
                self.assertNotIn("fake-password", redact(fake))
                self.assertNotIn("fake-api-value", redact(fake))
                self.assertNotIn("fake-sip-value", redact(fake))
                self.assertNotIn("fake-json-password", redact(fake))
                self.assertIn(MARKER, redact(fake))

    def test_quoted_assignment_escapes_and_delimiters(self):
        # Escaped quotes and backslashes belong to the value, not its boundary.
        cases = [
            ('password="synthetic-head\\"SYNTHETIC_TAIL"; status=ok', '; status=ok'),
            ("password='synthetic-head\\'SYNTHETIC_TAIL'; status=ok", '; status=ok'),
            ('password="synthetic-head\\\\\\"SYNTHETIC_TAIL"; status=ok', '; status=ok'),
            ('password="synthetic-head\\\\"; status=ok', '; status=ok'),
            ('password="synthetic, ; spaced value"; status=ok', '; status=ok'),
            ('password=""; status=ok', '; status=ok'),
        ]
        for surface in ("prompt", "log", "artifact"):
            for payload, suffix in cases:
                with self.subTest(surface=surface, payload=payload):
                    safe = redact({"surface": surface, "message": payload})
                    self.assertEqual(safe, {"surface": surface, "message": MARKER + suffix})
        # JSON serialization introduces escapes for both quote and backslash.
        for value in ('synthetic-"SYNTHETIC_TAIL', 'synthetic-\\"SYNTHETIC_TAIL'):
            payload = json.dumps({"password": value, "status": "ok"})
            self.assertEqual(json.loads(redact(payload)), {"password": MARKER, "status": "ok"})

    def test_bearer_complete_alphabet_and_surrounding_text(self):
        token = "SYNTHETIC-._~+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=="
        for surface in ("prompt", "log", "artifact"):
            for scheme in ("Bearer", "bearer", "BEARER"):
                with self.subTest(surface=surface, scheme=scheme):
                    safe = redact({"surface": surface, "message": "before " + scheme + " " + token + "; after"})
                    self.assertEqual(safe, {"surface": surface, "message": "before " + MARKER + "; after"})

    def test_sensitive_label_matrix_in_structured_and_serialized_forms(self):
        labels = ["password", "passwd", "authorization", "token", "secret"]
        for parts in (("private", "key"), ("api", "key"), ("client", "secret"),
                      ("access", "token"), ("refresh", "token"),
                      ("smtp", "credential"), ("sip", "credential"),
                      ("payment", "credential"), ("payment", "token"), ("deploy", "token")):
            labels.extend(separator.join(parts) for separator in ("", "_", "-"))
        for label in labels:
            for spelling in (label, label.upper()):
                with self.subTest(label=spelling):
                    self.assertEqual(redact({spelling: "synthetic-value"}), {spelling: MARKER})
                    for separator in ("=", ": "):
                        payload = spelling + separator + "synthetic-value; status=ok"
                        self.assertEqual(redact(payload), MARKER + "; status=ok")
                    payload = json.dumps({spelling: 'synthetic-"TAIL', "status": "ok"})
                    for surface in ("prompt", "log", "artifact"):
                        self.assertEqual(redact({"surface": surface, "message": payload}),
                                         {"surface": surface,
                                          "message": json.dumps({spelling: MARKER, "status": "ok"})})

    def test_ordinary_assignment_words_are_preserved(self):
        for label in ("secretary", "tokenizer", "secretion", "private", "access",
                      "deployment", "key", "status", "client_secretary"):
            with self.subTest(label=label):
                payload = label + "=synthetic-public; status=ok"
                self.assertEqual(redact(payload), payload)
                payload = json.dumps({label: "synthetic-public"})
                self.assertEqual(redact({"message": payload}), {"message": payload})

    def test_serialized_composites_redact_recursively(self):
        marker = "SYNTHETIC_COMPOSITE_VALUE"
        for label in ("api_key", "password", "payment_token", "PAYMENT-TOKEN"):
            for composite in ({"nested": marker, "items": [marker]}, [marker, {"nested": marker}]):
                value = {label: composite, "status": "ok", "count": 2}
                with self.subTest(label=label, composite_type=type(composite).__name__):
                    self.assertEqual(json.loads(redact(json.dumps(value))), {label: MARKER, "status": "ok", "count": 2})
                    self.assertEqual(redact(value), {label: MARKER, "status": "ok", "count": 2})
        payload = [{"api_key": {"nested": marker}}, {"public": [1, 2]}]
        self.assertEqual(json.loads(redact(json.dumps(payload))), [{"api_key": MARKER}, {"public": [1, 2]}])

    def test_embedded_json_message_is_redacted(self):
        marker = "SYNTHETIC_EMBEDDED_VALUE"
        message = json.dumps({"password": [marker, {"nested": marker}], "status": "ok"})
        for surface in ("prompt", "log", "artifact"):
            payload = json.dumps({"surface": surface, "message": message})
            safe = json.loads(redact(payload))
            self.assertEqual(safe["surface"], surface)
            self.assertEqual(json.loads(safe["message"]), {"password": MARKER, "status": "ok"})
            self.assertNotIn(marker, json.dumps(safe))

    def test_unparseable_sensitive_composites_fail_closed(self):
        marker = "SYNTHETIC_UNPARSED_VALUE"
        for message in ('prefix api_key={"nested":"' + marker + '","tail":1}; suffix',
                        'password=["' + marker + '", {"tail":1}] trailing text',
                        "'payment_token': {'nested': '" + marker + "'}",
                        '{"api_key": {"nested": "' + marker + '"',
                        '[{"password": ["' + marker + '"]}] extra'):
            for surface in ("prompt", "log", "artifact"):
                with self.subTest(surface=surface, message=message):
                    self.assertEqual(redact({"surface": surface, "message": message}),
                                     {"surface": surface, "message": MARKER})

    def test_json_recursion_bounds_and_ordinary_data(self):
        ordinary = {"client_secretary": "public", "status": "ok", "items": [1, False, None, {"name": "public"}]}
        self.assertEqual(json.loads(redact(json.dumps(ordinary))), ordinary)
        self.assertEqual(redact(ordinary), ordinary)
        nested = "SYNTHETIC_DEEP_VALUE"
        for _ in range(20): nested = [nested]
        self.assertNotIn("SYNTHETIC_DEEP_VALUE", redact(json.dumps(nested)))
        self.assertEqual(redact("x" * 65537), MARKER)

    def test_nested_sensitive_fields_and_opaque_values(self):
        data = {"safe_ref": "sops:synthetic-service", "records": [{"SMTP_PASSWORD": "fake"},
                {"api_key": {"nested": "fake"}}, {"message": b"opaque-fake"}]}
        safe = redact(data)
        self.assertEqual(safe["safe_ref"], "sops:synthetic-service")
        self.assertEqual(safe["records"], [{"SMTP_PASSWORD": MARKER}, {"api_key": MARKER}, {"message": MARKER}])
        self.assertEqual(redact({1: "opaque"}), MARKER)

    def test_deep_payload_and_safe_content(self):
        nested = "deliberately-unlabelled"
        for _ in range(20): nested = [nested]
        self.assertNotIn("deliberately-unlabelled", json.dumps(redact(nested)))
        self.assertEqual(redact({"count": 1, "enabled": False, "none": None, "message": "synthetic normal text"}),
                         {"count": 1, "enabled": False, "none": None, "message": "synthetic normal text"})


    def test_malformed_json_unicode_escaped_keys_are_not_leaked(self):
        marker='SYNTHETIC_ESCAPED_KEY_COMPOSITE'
        for key in (r'payment_\u0074oken', r'paym\u0065nt_token', r'\u0070assword', r'api_\u006bey'):
            for message in ('{"'+key+'":{"nested":["'+marker+'"]},broken',
                            '{"'+key+'":["'+marker+'", {"tail":[',
                            'prefix {"'+key+'":"'+marker+'"} suffix'):
                for surface in ('prompt','log','artifact'):
                    with self.subTest(key=key,surface=surface):
                        self.assertEqual(redact({'surface':surface,'message':message}),
                                         {'surface':surface,'message':MARKER})
        ordinary=r'prefix {"client_\u0073ecretary":[1,2]} suffix'
        self.assertEqual(redact(ordinary),ordinary)
    def test_unterminated_quoted_text_stays_within_input_bound(self):
        text='"'+('\\"'*16000)
        self.assertLess(len(text),65536)
        self.assertEqual(redact(text),text)
    def test_stray_quote_prefix_does_not_hide_escaped_sensitive_keys(self):
        payloads=(r'prefix "broken {"\u0070assword":{"nested":["SYNTHETIC_REVIEW_VALUE"]}} suffix',
                  r'prefix "broken {"api_\u006bey":["SYNTHETIC_REVIEW_VALUE"]} suffix')
        for payload in payloads:
            for surface in ('prompt','log','artifact'):
                with self.subTest(surface=surface,payload=payload):
                    self.assertEqual(redact({'surface':surface,'message':payload}),
                                     {'surface':surface,'message':MARKER})
        ordinary=r'prefix "broken {"client_\u0073ecretary":["synthetic-public"]} suffix'
        self.assertEqual(redact(ordinary),ordinary)
        long_payload=('"ordinary" '*5000)+payloads[0]
        self.assertLess(len(long_payload),65536)
        self.assertEqual(redact(long_payload),MARKER)
    def test_all_adjacent_quote_boundaries_detect_sensitive_component_keys(self):
        keys=(r':\u0070assword',r':api_\u006bey',r'ops:payment_\u0074oken')
        prefixes=('prefix "broken {', 'prefix "broken [ ', r'prefix "\q {')
        for prefix in prefixes:
            for key in keys:
                for separator in (':',' : ','\t:\n'):
                    payload=prefix+'"'+key+'"'+separator+'{"nested":["SYNTHETIC_ADJACENT_QUOTE_VALUE"]}} suffix'
                    for surface in ('prompt','log','artifact'):
                        with self.subTest(prefix=prefix,key=key,separator=separator,surface=surface):
                            self.assertEqual(redact({'surface':surface,'message':payload}),
                                             {'surface':surface,'message':MARKER})
        ordinary=r'prefix "broken {":client_\u0073ecretary":{"nested":["synthetic-public"]}} suffix'
        self.assertEqual(redact(ordinary),ordinary)

    def test_many_nonsensitive_quote_colon_boundaries_remain_bounded(self):
        prefix='"ordinary": '*4000
        payload=prefix+r'prefix "broken {":\u0070assword":{"nested":["SYNTHETIC_ADJACENT_QUOTE_VALUE"]}} suffix'
        self.assertLess(len(payload),65536)
        self.assertEqual(redact(payload),MARKER)
        ordinary=prefix+r'prefix "broken {":client_\u0073ecretary":[1,2]} suffix'
        self.assertEqual(redact(ordinary),ordinary)
if __name__ == "__main__":
    unittest.main()




