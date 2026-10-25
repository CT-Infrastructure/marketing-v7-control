"""F18 v1.0 pure recovery eligibility; every return keeps the restored system in HOLD."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'policies/evidence'))
from evidence_policy import exact, require, ref, sha, identity, instant, digest, verified_receipt


def evaluate_recovery(record, expected, trusted_receipts):
    exact(expected,'identity now restore_id backup_generation suppression_cutoff remote_effect_ids credential_refs')
    identity(expected['identity'])
    now=instant(expected['now']);cutoff=instant(expected['suppression_cutoff'])
    require(cutoff<=now,'Suppression cutoff cannot be future')
    require(ref(expected['restore_id']) and ref(expected['backup_generation']),'Expected restore/generation required')
    for field in ('remote_effect_ids','credential_refs'):
        require(type(expected[field]) is list and all(ref(x) for x in expected[field]) and len(set(expected[field]))==len(expected[field]),'Expected reconciliation list invalid')
    require(bool(expected['credential_refs']),'At least one independently tested credential required')
    exact(record,'schema_version identity restore_id author_ref state backup restored_at hold_ref suppression remote_effects credentials')
    require(record['schema_version']=='1.0' and record['state']=='HOLD','Restore must remain HOLD')
    identity(record['identity'])
    require(record['identity']==expected['identity'] and record['restore_id']==expected['restore_id'],'Wrong restore identity')
    require(ref(record['author_ref']),'Recovery author required')
    backup=record['backup'];exact(backup,'generation_ref manifest_sha256 created_at restore_test_ref')
    require(backup['generation_ref']==expected['backup_generation'] and sha(backup['manifest_sha256']),'Wrong backup generation/manifest')
    created,restored=instant(backup['created_at']),instant(record['restored_at'])
    require(created<=restored<=now,'Invalid backup/restore chronology')
    backup_subject=digest({'restore_id':record['restore_id'],'generation_ref':backup['generation_ref'],'manifest_sha256':backup['manifest_sha256'],'created_at':backup['created_at'],'restored_at':record['restored_at']})
    verified_receipt(backup['restore_test_ref'],'restore_execution',backup_subject,expected,trusted_receipts,record['author_ref'])
    verified_receipt(record['hold_ref'],'restore_hold',record['restore_id'],expected,trusted_receipts,record['author_ref'])
    suppression=record['suppression'];exact(suppression,'after_backup through replay_ref')
    through=instant(suppression['through'])
    require(suppression['after_backup']==backup['generation_ref'] and max(created,restored,cutoff)<=through<=now,'Post-backup suppression replay is incomplete or stale')
    subject=digest({'restore_id':record['restore_id'],'after_backup':suppression['after_backup'],'through':suppression['through']})
    receipt=verified_receipt(suppression['replay_ref'],'suppression_replay',subject,expected,trusted_receipts,record['author_ref'])
    require(instant(receipt['issued_at'])>=through,'Replay evidence predates checkpoint')
    require(type(record['remote_effects']) is list,'Remote effect list required')
    seen=set()
    for effect in record['remote_effects']:
        exact(effect,'effect_id outcome readback_ref')
        require(ref(effect['effect_id']) and effect['effect_id'] not in seen,'Duplicate/invalid effect')
        seen.add(effect['effect_id'])
        require(effect['outcome'] in ('OCCURRED','NOT_OCCURRED'),'UNKNOWN remote outcome retains HOLD')
        receipt=verified_receipt(effect['readback_ref'],'authoritative_remote_readback',effect['effect_id'],expected,trusted_receipts,record['author_ref'],outcome=effect['outcome'])
        require(instant(receipt['issued_at'])>=restored,'Readback predates restore')
    require(seen==set(expected['remote_effect_ids']),'Missing remote effects or unreviewed scope')
    require(type(record['credentials']) is list,'Credential proofs required')
    seen=set()
    for credential in record['credentials']:
        exact(credential,'credential_ref broker_ref scope_ref access_test_ref')
        require(all(ref(credential[k]) for k in credential),'Only nonsecret references allowed')
        require(credential['credential_ref'] not in seen,'Duplicate credential proof')
        seen.add(credential['credential_ref'])
        subject=digest({'restore_id':record['restore_id'],**{k:v for k,v in credential.items() if k!='access_test_ref'}})
        receipt=verified_receipt(credential['access_test_ref'],'credential_access_test',subject,expected,trusted_receipts,record['author_ref'])
        require(instant(receipt['issued_at'])>=restored,'Credential test predates restore')
    require(seen==set(expected['credential_refs']),'Missing required credential usability test')
    return {'release_eligible_for_human_review':True,'state':'HOLD','production_authorized':False,'automatic_retry_allowed':False}
