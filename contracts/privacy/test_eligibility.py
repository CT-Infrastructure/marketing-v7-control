"""Synthetic tests authored for root execution only; no live subjects/providers."""
from dataclasses import replace
import json
from pathlib import Path
import unittest

from eligibility import (AssetRight, AUTHORITIES, CHANNELS, Lifecycle, Permission,
                         Request, Review, REVIEW_ROLES, evaluate)

FIXTURE = json.loads(Path(__file__).with_name('synthetic-fixture.json').read_text(encoding='utf-8-sig'))


def make(channel='email'):
    f = FIXTURE
    binding = {key: f[key] for key in ('client_ref', 'purpose', 'account_ref', 'jurisdiction', 'provider_ref')}
    binding['channel'] = channel
    request = Request(**binding, subject_ref=f['subject_ref'], now=f['now'], max_age_seconds=f['max_age_seconds'])
    permission = Permission(**binding, subject_ref=f['subject_ref'], source_authority=AUTHORITIES[channel],
                            granted=True, revoked=False, authority_available=True,
                            valid_from=f['valid_from'], expires_at=f['expires_at'],
                            observed_at=f['observed_at'], evidence_ref='synthetic-permission')
    lifecycle = Lifecycle(f['client_ref'], f['subject_ref'], False, False, True, f['observed_at'],
                          f['retention_until'], 3, 3, None, False, None, 'synthetic-lifecycle')
    reviews = tuple(Review(**binding, kind=kind, status='APPROVED', revoked=False, reviewer_role=role,
                           observed_at=f['observed_at'], expires_at=f['expires_at'], evidence_ref='synthetic-'+kind)
                    for kind, role in REVIEW_ROLES.items())
    return request, permission, lifecycle, reviews


class PrivacyTests(unittest.TestCase):
    def test_each_channel_requires_its_own_complete_evidence(self):
        for channel in CHANNELS:
            with self.subTest(channel=channel):
                decision=evaluate(*make(channel))
                self.assertEqual('ELIGIBLE_OFFLINE', decision.status)
                self.assertEqual('HOLD', decision.outbound_state)

    def test_no_cross_channel_inference(self):
        for requested in CHANNELS:
            for granted in CHANNELS - {requested}:
                request, _, lifecycle, reviews = make(requested)
                permission = make(granted)[1]
                with self.subTest(requested=requested, granted=granted):
                    self.assertEqual('DENY', evaluate(request, permission, lifecycle, reviews).status)

    def test_missing_false_revoked_and_truthy_permission_deny(self):
        request, permission, lifecycle, reviews=make()
        for candidate in (None, replace(permission, granted=False), replace(permission, revoked=True),
                          replace(permission, granted='true'), replace(permission, revoked=0),
                          replace(permission, authority_available=False), replace(permission, authority_available=1)):
            self.assertEqual('DENY', evaluate(request,candidate,lifecycle,reviews).status)

    def test_each_permission_binding_and_authority_must_match(self):
        request, permission, lifecycle, reviews=make()
        for key in ('client_ref','subject_ref','purpose','account_ref','jurisdiction','provider_ref','source_authority'):
            with self.subTest(key=key):
                self.assertEqual('DENY',evaluate(request,replace(permission,**{key:'wrong'}),lifecycle,reviews).status)

    def test_permission_staleness_and_exclusive_expiry(self):
        request, permission, lifecycle, reviews=make()
        for changes in ({'observed_at':'2026-10-25T11:58:59Z'}, {'observed_at':'2026-10-25T12:00:01Z'},
                        {'expires_at':request.now}, {'valid_from':'2026-10-25T12:00:01Z'}, {'evidence_ref':''}):
            self.assertEqual('DENY',evaluate(request,replace(permission,**changes),lifecycle,reviews).status)

    def test_review_unknown_or_unqualified_holds_with_responsible_role(self):
        request, permission, lifecycle, reviews=make()
        for index, role in enumerate(REVIEW_ROLES.values()):
            remaining=reviews[:index]+reviews[index+1:]
            result=evaluate(request,permission,lifecycle,remaining)
            self.assertEqual(('HOLD',role),(result.status,result.responsible_role))
            for changes in ({'status':'UNKNOWN'}, {'reviewer_role':'model'}, {'revoked':True},
                            {'expires_at':request.now}, {'account_ref':'wrong'}, {'evidence_ref':''}):
                altered=tuple(replace(r,**changes) if i==index else r for i,r in enumerate(reviews))
                self.assertEqual('HOLD',evaluate(request,permission,lifecycle,altered).status)

    def test_suppression_deletion_and_authority_unavailable_deny(self):
        request, permission, lifecycle, reviews=make()
        for changes in ({'suppressed':True},{'deleted':True},{'deleted':0},{'authority_available':False},
                        {'observed_at':'2026-10-25T11:00:00Z'}, {'client_ref':'wrong'}):
            self.assertEqual('DENY',evaluate(request,permission,replace(lifecycle,**changes),reviews).status)
        self.assertEqual('DENY',evaluate(request,permission,None,reviews).status)

    def test_retention_unknown_holds_and_expiry_denies(self):
        request, permission, lifecycle, reviews=make()
        decision=evaluate(request,permission,replace(lifecycle,retention_until=None),reviews)
        self.assertEqual(('HOLD','privacy_reviewer'),(decision.status,decision.responsible_role))
        self.assertEqual('DENY',evaluate(request,permission,replace(lifecycle,retention_until=request.now),reviews).status)

    def test_restore_requires_replay_of_current_generation(self):
        request, permission, lifecycle, reviews=make()
        restored=replace(lifecycle,restore_epoch='synthetic-restore')
        self.assertEqual('DENY',evaluate(request,permission,restored,reviews).status)
        replayed=replace(restored,replay_complete=True,replay_evidence_ref='synthetic-replay')
        self.assertEqual('ELIGIBLE_OFFLINE',evaluate(request,permission,replayed,reviews).status)
        for changes in ({'applied_generation':2},{'authority_generation':4},{'replay_complete':'true'},
                        {'replay_evidence_ref':None},{'suppressed':True},{'deleted':True}):
            self.assertEqual('DENY',evaluate(request,permission,replace(replayed,**changes),reviews).status)

    def test_revocation_generation_malformed_types_deny(self):
        request, permission, lifecycle, reviews=make()
        for changes in ({'applied_generation':True},{'authority_generation':'3'}, {'applied_generation':-1},
                        {'applied_generation':4}):
            self.assertEqual('DENY',evaluate(request,permission,replace(lifecycle,**changes),reviews).status)

    def test_asset_rights_missing_expired_revoked_and_changed_scope_deny(self):
        request, permission, lifecycle, reviews=make()
        request=replace(request,asset_refs=('synthetic-asset',))
        right=AssetRight('synthetic-asset',request.client_ref,request.purpose,request.account_ref,False,
                         FIXTURE['valid_from'],FIXTURE['expires_at'],FIXTURE['observed_at'],'synthetic-right')
        self.assertEqual('DENY',evaluate(request,permission,lifecycle,reviews).status)
        self.assertEqual('ELIGIBLE_OFFLINE',evaluate(request,permission,lifecycle,reviews,(right,)).status)
        for changes in ({'expires_at':request.now},{'revoked':True},{'purpose':'wrong'},{'account_ref':'wrong'},
                        {'observed_at':'2026-10-25T11:00:00Z'}):
            self.assertEqual('DENY',evaluate(request,permission,lifecycle,reviews,(replace(right,**changes),)).status)
        self.assertEqual('DENY',evaluate(request,permission,lifecycle,reviews,(right,right)).status)

    def test_strict_request_types_and_utc_datetime(self):
        request, permission, lifecycle, reviews=make()
        for changes in ({'max_age_seconds':True},{'max_age_seconds':0},{'now':'2026-10-25T12:00:00'},
                        {'now':'2026-10-25T12:00:00Z\n'},{'now':'2026-02-30T12:00:00Z'},
                        {'asset_refs':[]},{'subject_ref':'bad\nsubject'},{'channel':'social'}):
            self.assertEqual('DENY',evaluate(replace(request,**changes),permission,lifecycle,reviews).status)

    def test_no_extra_engagement_or_claimed_approval_fields(self):
        with self.assertRaises(TypeError): Request(**{'engagement':True})
        request, permission, lifecycle, reviews=make()
        self.assertEqual('DENY',evaluate(request,permission,lifecycle,list(reviews)).status)


if __name__ == '__main__': unittest.main()
