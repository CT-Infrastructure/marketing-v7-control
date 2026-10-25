"""Constructed examples only: no identities, approvals or runtime claims are real."""
import copy
from evidence_policy import COMMON, EXTRA, digest

IDENTITY={'commit':'a'*40,'dependency_lock_sha256':'b'*64,'environment_sha256':'c'*64}
NOW='2026-10-25T12:00:00Z'


def receipt(kind,subject,outcome='PASS',actor='synthetic-executor'):
    return dict(kind=kind,identity=copy.deepcopy(IDENTITY),subject=subject,actor_ref=actor,
                verified_by='synthetic-independent-verifier',outcome=outcome,artifact_sha256='d'*64,
                issued_at=NOW,expires_at='2026-10-25T13:00:00Z')


def evidence_fixture(level='CODE_MERGED'):
    expected=dict(identity=copy.deepcopy(IDENTITY),now=NOW,level=level,plan_ref='synthetic-plan',required_case_ids=['synthetic-case'],production_scope=None)
    claim=dict(schema_version='1.0',level=level,identity=copy.deepcopy(IDENTITY),author_ref='synthetic-author',plan_ref='synthetic-plan',cases=[dict(case_id='synthetic-case',status='PASS',executor_ref='synthetic-executor',evidence_ref='synthetic-case-receipt')],supporting={},production=None)
    trusted={'synthetic-case-receipt':receipt('test_execution','synthetic-case')}
    for key,kind in {**COMMON,**EXTRA[level]}.items():
        reference='synthetic-'+key;claim['supporting'][key]=reference;trusted[reference]=receipt(kind,'synthetic-plan')
    if level=='PRODUCTION_APPROVED':
        expected['production_scope']=dict(target_ref='synthetic-target',channel='synthetic-channel',limits_sha256='e'*64)
        claim['production']=dict(approval_ref='synthetic-human-approval',**expected['production_scope'])
        trusted['synthetic-human-approval']=receipt('human_production_approval',digest({'plan_ref':'synthetic-plan',**expected['production_scope']}),actor='synthetic-human-role')
    return claim,expected,trusted


def recovery_fixture():
    expected=dict(identity=copy.deepcopy(IDENTITY),now=NOW,restore_id='synthetic-restore',backup_generation='synthetic-generation',suppression_cutoff=NOW,remote_effect_ids=['synthetic-effect'],credential_refs=['synthetic-credential'])
    record=dict(schema_version='1.0',identity=copy.deepcopy(IDENTITY),restore_id='synthetic-restore',author_ref='synthetic-author',state='HOLD',
                backup=dict(generation_ref='synthetic-generation',manifest_sha256='f'*64,created_at='2026-10-25T10:00:00Z',restore_test_ref='synthetic-restore-proof'),
                restored_at='2026-10-25T11:00:00Z',hold_ref='synthetic-hold-proof',
                suppression=dict(after_backup='synthetic-generation',through=NOW,replay_ref='synthetic-suppression-proof'),
                remote_effects=[dict(effect_id='synthetic-effect',outcome='NOT_OCCURRED',readback_ref='synthetic-readback')],
                credentials=[dict(credential_ref='synthetic-credential',broker_ref='synthetic-broker',scope_ref='synthetic-scope',access_test_ref='synthetic-access-proof')])
    backup_subject=digest(dict(restore_id=record['restore_id'],generation_ref=record['backup']['generation_ref'],manifest_sha256=record['backup']['manifest_sha256'],created_at=record['backup']['created_at'],restored_at=record['restored_at']))
    suppression_subject=digest(dict(restore_id=record['restore_id'],after_backup=record['suppression']['after_backup'],through=record['suppression']['through']))
    credential_subject=digest(dict(restore_id=record['restore_id'],**{k:v for k,v in record['credentials'][0].items() if k!='access_test_ref'}))
    trusted={'synthetic-restore-proof':receipt('restore_execution',backup_subject),
             'synthetic-hold-proof':receipt('restore_hold',record['restore_id']),
             'synthetic-suppression-proof':receipt('suppression_replay',suppression_subject),
             'synthetic-readback':receipt('authoritative_remote_readback','synthetic-effect',outcome='NOT_OCCURRED'),
             'synthetic-access-proof':receipt('credential_access_test',credential_subject)}
    return record,expected,trusted
