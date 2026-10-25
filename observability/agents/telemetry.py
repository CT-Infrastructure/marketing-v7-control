"""F17 offline telemetry projections. No controller database or network access."""
from __future__ import annotations
from datetime import timedelta
import copy
from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import json
import math
from pathlib import Path
from jsonschema.exceptions import ValidationError
import re

ROOT=Path(__file__).resolve().parents[2]

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

core=load_module('f17_core',ROOT/'contracts/core/validate.py')
f08=load_module('f17_capacity',ROOT/'docs/orchestration/capacity/check_dispatch_inputs.py')
DISPATCH_KEYS=set(json.loads((ROOT/'docs/orchestration/capacity/dispatch-inputs.json').read_text()))
STATES=('BACKLOG','READY','RUNNING','REVIEW','BLOCKED','ORPHANED','ACCEPTED','FAILED')
RESOURCES=('cpu','memory_mib','disk_gib','gpu_vram_mib','gpu','slots','integration')
ROLES=('implementation','review')
MEASURES=('calls','input_tokens','output_tokens')
MAX_BYTES=524288
MAX_TASKS=128
MAX_ATTEMPTS=512
CRITICAL_EVIDENCE_STATES=('READY','RUNNING','REVIEW')
FRESHNESS_SECONDS=120


def require(condition):
    if not condition:raise ValueError('invalid bounded telemetry input')

def shape(value,keys):
    require(type(value) is dict and set(value)==set(keys))

def count(value,nullable=False):
    if nullable and value is None:return
    require(type(value) is int and 0<=value<=10**12)

def time(value):
    try:
        core.Draft202012Validator(core.SCHEMAS['common']['$defs']['datetime'],format_checker=core.FORMATS).validate(value)
    except ValidationError:
        raise ValueError('invalid telemetry timestamp') from None
    return core.instant(value)

def amount(value):
    if value is None:return None
    require(type(value) is str and len(value)<=64)
    try:
        core.Draft202012Validator(core.SCHEMAS['common']['$defs']['money']).validate({'amount':value,'currency':'USD'})
    except ValidationError:
        raise ValueError('invalid telemetry amount') from None
    try:result=Decimal(value)
    except InvalidOperation as exc:raise ValueError('invalid bounded amount') from exc
    require(result.is_finite() and 0<=result<=Decimal('1000000000'))
    return result

def safe_ref(value,kind,nullable=False):
    if nullable and value is None:return
    patterns={'task':r'task:[A-Z0-9][A-Z0-9-]{0,63}', 'agent':r'agent:[a-z0-9-]{1,64}',
              'input':r'sha256:[a-f0-9]{64}', 'base':r'git:[a-f0-9]{40}',
              'result':r'artifact:[a-f0-9]{64}'}
    require(type(value) is str and re.fullmatch(patterns[kind],value) is not None)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)

def read_snapshot(path):
    with Path(path).open('rb') as stream:
        raw=stream.read(MAX_BYTES+1)
    require(len(raw)<=MAX_BYTES)
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value);value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid numeric constant')))

def validate(snapshot,now):
    shape(snapshot,('schema_version','sequence','observed_at','emergency_stop','dispatch_inputs','tasks','resources','accounting','model_usage'))
    require(snapshot['schema_version']=='1.0')
    count(snapshot['sequence']);require(snapshot['sequence']>0)
    current=time(now);observed=time(snapshot['observed_at']);require(observed<=current)
    require(type(snapshot['emergency_stop']) is bool)
    shape(snapshot['dispatch_inputs'],DISPATCH_KEYS)
    require(len(canonical(snapshot['dispatch_inputs']))<8192)
    # Reuse F08's checks; their static blocker names are never raw source values.
    dispatch_blockers=f08.blockers(snapshot['dispatch_inputs'])
    for key in ('total_spend_usd','per_task_spend_usd'):
        value=snapshot['dispatch_inputs'][key]
        if value is not None:require(f08.number(value) and value<=1000000000)
    tasks=snapshot['tasks'];require(type(tasks) is list and len(tasks)<=MAX_TASKS)
    refs=set()
    for task in tasks:
        shape(task,('task_ref','agent_ref','input_ref','base_ref','result_ref','state','queued_at','lease_until','merge_wait_since','evidence_at'))
        for key,kind,nullable in [('task_ref','task',False),('agent_ref','agent',True),('input_ref','input',False),('base_ref','base',False),('result_ref','result',True)]:
            safe_ref(task[key],kind,nullable)
        require(task['task_ref'] not in refs);refs.add(task['task_ref'])
        require(task['state'] in STATES)
        for key in ('queued_at','merge_wait_since','evidence_at'):
            if task[key] is not None:require(time(task[key])<=observed)
        if task['lease_until'] is not None:time(task['lease_until'])
        if task['state'] in ('RUNNING','ORPHANED'):
            require(task['agent_ref'] is not None and task['lease_until'] is not None)
        if task['state']=='REVIEW':require(task['merge_wait_since'] is not None)
        if task['state'] in ('BACKLOG','READY'):require(task['queued_at'] is not None)
    shape(snapshot['resources'],RESOURCES)
    for resource in snapshot['resources'].values():
        shape(resource,('capacity','allocated'))
        for value in resource.values():count(value,nullable=True)
    shape(snapshot['accounting'],('api_spent_usd','api_reserved_usd','subscription_task_limit','subscription_tasks_used','subscription_tasks_reserved','requested_subscription_tasks'))
    for key in ('api_spent_usd','api_reserved_usd'):amount(snapshot['accounting'][key])
    for key in ('subscription_task_limit','subscription_tasks_used','subscription_tasks_reserved'):count(snapshot['accounting'][key],nullable=True)
    count(snapshot['accounting']['requested_subscription_tasks']);require(snapshot['accounting']['requested_subscription_tasks']>0)
    shape(snapshot['model_usage'],ROLES)
    for role in ROLES:
        shape(snapshot['model_usage'][role],MEASURES)
        for value in snapshot['model_usage'][role].values():count(value,nullable=True)
    require(len(canonical(snapshot).encode())<=MAX_BYTES)
    return current,observed,dispatch_blockers

def render(snapshot,now,previous=None):
    current,observed,dispatch_blockers=validate(snapshot,now)
    digest=hashlib.sha256(canonical(snapshot).encode()).hexdigest()
    attempt_bindings={}
    if previous is not None:
        shape(previous,('sequence','snapshot_sha256','observed_at','attempt_bindings'))
        count(previous['sequence']);safe_ref('sha256:'+previous['snapshot_sha256'],'input')
        require(snapshot['sequence']>=previous['sequence'] and observed>=time(previous['observed_at']))
        if snapshot['sequence']==previous['sequence']:require(digest==previous['snapshot_sha256'])
        require(type(previous['attempt_bindings']) is dict and len(previous['attempt_bindings'])<=MAX_ATTEMPTS)
        for attempt_ref,binding in previous['attempt_bindings'].items():
            safe_ref(attempt_ref,'task');shape(binding,('input_ref','base_ref'))
            safe_ref(binding['input_ref'],'input');safe_ref(binding['base_ref'],'base')
            attempt_bindings[attempt_ref]=dict(binding)
    for task in snapshot['tasks']:
        binding={key:task[key] for key in ('input_ref','base_ref')}
        previous_binding=attempt_bindings.get(task['task_ref'])
        require(previous_binding is None or previous_binding==binding)
        attempt_bindings[task['task_ref']]=binding
    require(len(attempt_bindings)<=MAX_ATTEMPTS)
    cursor={'sequence':snapshot['sequence'],'snapshot_sha256':digest,'observed_at':snapshot['observed_at'],
            'attempt_bindings':attempt_bindings}
    counts={state:0 for state in STATES}
    details=[];active_leases=0;expired_running=0;queue_ages=[];merge_ages=[];evidence_ages=[];missing_evidence=0
    for task in snapshot['tasks']:
        state=task['state'];counts[state]+=1
        queue_age=(current-time(task['queued_at'])).total_seconds() if state in ('BACKLOG','READY') else None
        merge_age=(current-time(task['merge_wait_since'])).total_seconds() if state=='REVIEW' else None
        evidence_age=(current-time(task['evidence_at'])).total_seconds() if task['evidence_at'] else None
        if queue_age is not None:queue_ages.append(queue_age)
        if merge_age is not None:merge_ages.append(merge_age)
        if evidence_age is not None:evidence_ages.append(evidence_age)
        else:missing_evidence+=1
        if state=='RUNNING':
            if time(task['lease_until'])>current:active_leases+=1
            else:expired_running+=1
        details.append({k:task[k] for k in ('task_ref','agent_ref','input_ref','base_ref','result_ref','state')}|
                       {'queue_age_seconds':queue_age,'merge_wait_seconds':merge_age,'evidence_age_seconds':evidence_age})
    pressure={}
    for resource,row in snapshot['resources'].items():
        cap,allocated=row['capacity'],row['allocated']
        pressure[resource]=None if cap is None or allocated is None else (0 if cap==allocated==0 else (None if cap==0 else allocated/cap))
    accounting=snapshot['accounting'];spent=amount(accounting['api_spent_usd']);reserved=amount(accounting['api_reserved_usd'])
    reasons=[]
    if dispatch_blockers:reasons.append('capacity_inputs_held')
    if snapshot['emergency_stop']:reasons.append('emergency_stop')
    if (current-observed).total_seconds()>FRESHNESS_SECONDS:reasons.append('stale_snapshot')
    for task in snapshot['tasks']:
        if task['state'] in CRITICAL_EVIDENCE_STATES:
            if task['evidence_at'] is None:
                reasons.append('prerequisite_evidence_missing')
            elif (current-time(task['evidence_at'])).total_seconds()>FRESHNESS_SECONDS:
                reasons.append('prerequisite_evidence_stale')
    for resource in ('cpu','memory_mib','slots'):
        capacity=snapshot['resources'][resource]['capacity']
        if capacity is None or capacity<=0:reasons.append('required_resource_capacity_unavailable')
    slots=snapshot['resources']['slots']
    if (slots['capacity'] is not None and slots['allocated'] is not None and
            accounting['requested_subscription_tasks']>slots['capacity']-slots['allocated']):
        reasons.append('insufficient_execution_slots')
    if counts['ORPHANED'] or expired_running:reasons.append('reconciliation_required')
    if any(value is None for value in pressure.values()):reasons.append('resource_observation_unset')
    if any(value is not None and value>=1 for value in pressure.values()):reasons.append('resource_pressure')
    if any(row['capacity']==0 and row['allocated'] not in (0,None) for row in snapshot['resources'].values()):reasons.append('resource_overallocated')
    cap=snapshot['dispatch_inputs']['total_spend_usd']
    if spent is None or reserved is None or not f08.number(cap):reasons.append('api_accounting_unset')
    elif spent+reserved>Decimal(str(cap)):reasons.append('api_budget_exceeded')
    sub=[accounting[k] for k in ('subscription_task_limit','subscription_tasks_used','subscription_tasks_reserved')]
    if any(value is None for value in sub):reasons.append('subscription_quota_unset')
    elif sub[1]+sub[2]>=sub[0] or sub[1]+sub[2]+accounting['requested_subscription_tasks']>sub[0]:reasons.append('subscription_budget_exhausted')
    report={'schema_version':'1.0','observed_at':snapshot['observed_at'],'rendered_at':now,'cursor':cursor,
            'counts':counts,'snapshot_age_seconds':(current-observed).total_seconds(),'active_leases':active_leases,'expired_running_leases':expired_running,
            'queue_oldest_age_seconds':max(queue_ages,default=0),'merge_wait_oldest_seconds':max(merge_ages,default=0),
            'evidence_oldest_age_seconds':max(evidence_ages) if evidence_ages else None,'missing_evidence_count':missing_evidence,
            'resource_pressure_ratio':pressure,'model_usage':copy.deepcopy(snapshot['model_usage']),
            'accounting':copy.deepcopy(accounting),'billing_mode':'ChatGPT subscription','api_budget_authorized_usd':cap if f08.number(cap) else None,
            'admission_signal':not reasons,'admission_hold_reasons':sorted(set(reasons)),
            'dispatch_authorized':False,'next_step':'trusted_admission_required','tasks':details}
    require(len(canonical(report).encode())<=MAX_BYTES)
    return report

def prometheus(report):
    # No task refs, agent refs, model names, paths or arbitrary input strings become labels.
    lines=['# F17 bounded snapshot gauges; no dispatch authority']
    def gauge(name,value,labels=''):
        if value is None:return
        require(type(value) in (int,float,Decimal) and math.isfinite(value) and 0<=value<=10**12)
        lines.append(name+labels+' '+format(value,'f') if isinstance(value,Decimal) else name+labels+' '+str(value))
    for state in STATES:gauge('agent_tasks',report['counts'][state],'{state="'+state+'"}')
    for key in ('snapshot_age_seconds','active_leases','expired_running_leases','queue_oldest_age_seconds','merge_wait_oldest_seconds','missing_evidence_count'):
        gauge('agent_'+key,report[key])
    gauge('agent_evidence_age_known',int(report['evidence_oldest_age_seconds'] is not None))
    gauge('agent_evidence_oldest_age_seconds',report['evidence_oldest_age_seconds'])
    for resource in RESOURCES:
        value=report['resource_pressure_ratio'][resource]
        gauge('agent_resource_pressure_known',int(value is not None),'{resource="'+resource+'"}')
        gauge('agent_resource_pressure_ratio',value,'{resource="'+resource+'"}')
    for role in ROLES:
        for measure in MEASURES:
            value=report['model_usage'][role][measure];labels='{role="'+role+'",measure="'+measure+'"}'
            gauge('agent_model_usage_known',int(value is not None),labels)
            gauge('agent_model_usage',value,labels)
    for key in ('api_spent_usd','api_reserved_usd'):
        value=amount(report['accounting'][key]);gauge('agent_'+key+'_known',int(value is not None));gauge('agent_'+key,value)
    for key in ('subscription_task_limit','subscription_tasks_used','subscription_tasks_reserved'):
        value=report['accounting'][key];gauge('agent_'+key+'_known',int(value is not None));gauge('agent_'+key,value)
    gauge('agent_api_budget_authorized_usd_known',int(report['api_budget_authorized_usd'] is not None))
    gauge('agent_api_budget_authorized_usd',report['api_budget_authorized_usd'])
    gauge('agent_requested_subscription_tasks',report['accounting']['requested_subscription_tasks'])
    gauge('agent_admission_signal',int(report['admission_signal']))
    gauge('agent_dispatch_authorized',0)
    result='\n'.join(lines)+'\n';require(len(result.encode())<=32768)
    return result





