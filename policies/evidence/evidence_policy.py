"""F18 v1.0 offline evidence eligibility; never authenticate or award a level."""
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

LEVELS = ('CODE_MERGED','SANDBOX_QUALIFIED','STAGING_QUALIFIED','PRODUCTION_APPROVED')
COMMON = {'merge':'code_merge','review':'independent_review','locks':'dependency_locks','environment':'environment_capture'}
EXTRA = {'CODE_MERGED':{},'SANDBOX_QUALIFIED':{'sandbox':'sandbox_boundary'},
         'STAGING_QUALIFIED':{'staging':'staging_boundary'},
         'PRODUCTION_APPROVED':{'staging':'staging_boundary','recovery':'recovery_qualification'}}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, fields):
    require(type(value) is dict and set(value)==set(fields.split()), 'Missing or unknown contract field')


def ref(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value) is not None


def sha(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}',value) is not None


def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z',value) is not None,'UTC instant required')
    return datetime.fromisoformat(value.replace('Z','+00:00'))


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()


def identity(value):
    exact(value,'commit dependency_lock_sha256 environment_sha256')
    require(type(value['commit']) is str and re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}',value['commit']) is not None,'Immutable commit required')
    require(sha(value['dependency_lock_sha256']) and sha(value['environment_sha256']),'Lock/environment hash required')


def verified_receipt(reference, kind, subject, expected, trusted_receipts, author, *, outcome='PASS', actor=None):
    """trusted_receipts is populated ONLY by independently authenticated controller I/O."""
    require(ref(reference) and type(trusted_receipts) is dict and reference in trusted_receipts,'Verified receipt missing')
    receipt=trusted_receipts[reference]
    exact(receipt,'kind identity subject actor_ref verified_by outcome artifact_sha256 issued_at expires_at')
    identity(receipt['identity'])
    require(receipt['identity']==expected['identity'],'Stale receipt identity')
    require(receipt['kind']==kind and receipt['subject']==subject and receipt['outcome']==outcome,'Receipt purpose or outcome mismatch')
    require(ref(receipt['actor_ref']) and ref(receipt['verified_by']) and receipt['actor_ref']!=author and receipt['verified_by']!=author,'Evidence is not independent of author')
    if actor is not None:
        require(receipt['actor_ref']==actor,'Wrong evidence executor')
    require(sha(receipt['artifact_sha256']),'Receipt artifact hash required')
    issued,expires,now=instant(receipt['issued_at']),instant(receipt['expires_at']),instant(expected['now'])
    require(issued<=now<expires,'Receipt is stale or future')
    return receipt


def evaluate_evidence(claim, expected, trusted_receipts):
    """Check a trusted plan's exact scope. Does not mutate registry or grant approval."""
    exact(expected,'identity now level plan_ref required_case_ids production_scope')
    identity(expected['identity']); instant(expected['now'])
    require(expected['level'] in LEVELS and ref(expected['plan_ref']),'Unknown level/plan')
    ids=expected['required_case_ids']
    require(type(ids) is list and bool(ids) and all(ref(x) for x in ids) and len(set(ids))==len(ids),'Explicit required case set required')
    exact(claim,'schema_version level identity author_ref plan_ref cases supporting production')
    require(claim['schema_version']=='1.0' and claim['level']==expected['level'],'Wrong version/level')
    identity(claim['identity'])
    require(claim['identity']==expected['identity'] and claim['plan_ref']==expected['plan_ref'],'Stale claim or plan')
    require(ref(claim['author_ref']),'Author reference required')
    require(type(claim['cases']) is list,'Cases must be a list')
    seen=set()
    for case in claim['cases']:
        exact(case,'case_id status executor_ref evidence_ref')
        require(ref(case['case_id']) and case['case_id'] not in seen,'Invalid/duplicate case')
        seen.add(case['case_id'])
        require(case['status']=='PASS','FAIL/NOT_RUN/NOT_APPLICABLE cannot qualify without a separate reviewed plan')
        require(ref(case['executor_ref']),'Independent executor required')
        verified_receipt(case['evidence_ref'],'test_execution',case['case_id'],expected,trusted_receipts,claim['author_ref'],actor=case['executor_ref'])
    require(seen==set(ids),'Case coverage differs from trusted plan')
    requirements={**COMMON,**EXTRA[claim['level']]}
    require(type(claim['supporting']) is dict and set(claim['supporting'])==set(requirements),'Required level evidence missing')
    for key,kind in requirements.items():
        verified_receipt(claim['supporting'][key],kind,claim['plan_ref'],expected,trusted_receipts,claim['author_ref'])
    if claim['level']=='PRODUCTION_APPROVED':
        production=claim['production']
        exact(production,'approval_ref target_ref channel limits_sha256')
        require(ref(production['target_ref']) and ref(production['channel']) and sha(production['limits_sha256']),'Production scope missing')
        scope={k:v for k,v in production.items() if k!='approval_ref'}
        require(scope==expected['production_scope'],'Wrong expected production scope')
        subject=digest({'plan_ref':claim['plan_ref'],**scope})
        verified_receipt(production['approval_ref'],'human_production_approval',subject,expected,trusted_receipts,claim['author_ref'])
    else:
        require(claim['production'] is None and expected['production_scope'] is None,'Lower level cannot assert production approval')
    return {'eligible_for_independent_decision':True,'requested_level':claim['level'],'level_awarded':None,'production_action_authorized':False}


def validate_register(register, root):
    """Compare the complete original/traceability ID set; no runtime status promotion."""
    exact(register,'schema_version records')
    require(register['schema_version']=='1.0' and type(register['records']) is list,'Invalid register')
    root=Path(root)
    with (root/'reference/acceptance/Original_Acceptance_Matrix.csv').open(encoding='utf-8-sig',newline='') as file:
        originals=list(csv.DictReader(file))
    with (root/'backlog/acceptance_traceability.csv').open(encoding='utf-8-sig',newline='') as file:
        traced=list(csv.DictReader(file))
    source={r['test_id']:r for r in originals}; trace={r['source_test_id']:r for r in traced}
    require(len(source)==len(originals)==len(trace)==len(traced)==576,'Original/traceability IDs must be unique and complete')
    require(set(source)==set(trace),'Original/traceability ID mismatch')
    seen=set(); blockers=0
    for row in register['records']:
        exact(row,'source_test_id source_workflow_id workflow_id test source_annotation runtime_status verification_issue verifier_role assigned_person evidence_ref')
        key=row['source_test_id'];require(key in source and key not in seen,'Unknown/duplicate original ID');seen.add(key)
        src,tr=source[key],trace[key]
        require(row['source_workflow_id']==src['workflow_id'] and row['workflow_id']==tr['workflow_id'] and row['test']==src['test'],'Source mapping changed')
        require(row['source_annotation']==src['status'],'Source annotation changed')
        blockers+=row['source_annotation']=='OPEN_SOURCE_BLOCKER'
        require(row['runtime_status']=='NOT_RUN' and row['evidence_ref'] is None,'Unexecuted runtime case promoted')
        require(row['verification_issue']==tr['verification_issue'] and row['verifier_role']=='Independent executor for '+tr['verification_issue'],'Verifier mapping changed')
        require(row['assigned_person'] is None,'Named human assignment was not supplied')
    require(seen==set(source) and blockers==12,'Missing original cases/source blockers')
    return {'runtime_total':576,'runtime_not_run':576,'source_open_blockers':12,'runtime_pass':0}
