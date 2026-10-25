#!/usr/bin/env python3
"""Bounded provider-neutral Podman launcher. Disabled until real adapter qualification.

No actual provider CLI is assumed. The approved container image/argv implements the
file protocol; provider rate/cost/remote-cancellation guarantees must be qualified.
"""
from __future__ import annotations
import argparse, concurrent.futures, json, os, re, subprocess, threading, time
from pathlib import Path
from scheduler import Scheduler
from workspace import export_git, inventory, verify_result, digest
ROOT=Path(__file__).resolve().parents[1]

def validate_live_policy(policy: dict):
    required_flags=['operator_authorized','capacity_measured','agent_cost_ceiling_enforced_by_adapter',
                    'provider_rate_limits_enforced_by_adapter','workspace_quota_enforced']
    if policy.get('mode')!='real' or any(policy.get(k) is not True for k in required_flags):
        raise ValueError('Real execution is disabled until measured budgets, sandbox, provider limits and G02 authorization are qualified')
    if not policy.get('approval_ref'):raise ValueError('Missing verified operator authorization reference')
    if policy.get('cost_enforcement_boundary') not in ['provider-account','trusted-egress-broker']:
        raise ValueError('Spend ceiling must be enforced outside the untrusted worker, not only by its own CLI')
    if policy.get('production_actions_allowed') is not False:raise ValueError('Production actions are not supported by this launcher')
    image=policy.get('agent_image_digest') or ''
    if not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',image):raise ValueError('Exact approved agent image digest required')
    argv=policy.get('agent_argv')
    if not isinstance(argv,list) or not argv or any(not isinstance(x,str) or '\x00' in x for x in argv):raise ValueError('Trusted argv adapter required')
    network=policy.get('network','none')
    if network!='none' and (not re.fullmatch(r'v7-agent-[a-z0-9-]+',network) or not policy.get('network_approval_ref')):
        raise ValueError('Only network none or a qualified named isolated egress network is permitted')
    maximum=policy.get('provider_limits',{}).get('max_concurrent_requests')
    if not isinstance(maximum,int) or maximum<policy['max_workers']:raise ValueError('Provider concurrent task cap is unqualified or below max_workers')
    secret=policy.get('provider_secret_name')
    if secret and not re.fullmatch(r'v7-agent-[a-z0-9-]+',secret):raise ValueError('Only an approved narrow provider secret name is permitted')
    if policy.get('heartbeat_seconds',0)<=0 or policy['heartbeat_seconds']>=policy['lease_seconds']/2:
        raise ValueError('Heartbeat must be safely below lease expiry')

def podman_check():
    data=json.loads(subprocess.run(['podman','info','--format','json'],check=True,capture_output=True,text=True,timeout=30).stdout)
    host=data.get('host',{})
    if host.get('security',{}).get('rootless') is not True or str(host.get('cgroupVersion')) not in ['v2','2']:
        raise ValueError('Rootless Podman with validated cgroup v2 is required')

def command(packet: dict, policy: dict, job: Path) -> list[str]:
    if packet['task']['resources'].get('gpu',0):raise ValueError('GPU agent execution requires a separately qualified adapter; this reference launcher is CPU-only')
    name=f"v7-agent-{packet['task_key'].lower()}-{packet['fence']}"
    workspace=job/'workspace';output=job/'out';taskdir=job/'task'
    args=['podman','run','--rm','--pull=never','--name',name,'--read-only','--userns=keep-id',
          '--user',f'{os.getuid()}:{os.getgid()}','--cap-drop=ALL','--security-opt=no-new-privileges',
          '--network',policy.get('network','none'),'--pids-limit=256',
          '--cpus',str(packet['task']['resources'].get('cpu',1)),
          '--memory',str(packet['task']['resources'].get('memory_mib',1024))+'m',
          '--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=512m','--tmpfs','/run:rw,nosuid,nodev,size=32m',
          '--volume',f'{workspace}:/workspace:ro,Z','--volume',f'{taskdir}:/task:ro,Z',
          '--volume',f'{output}:/out:rw,Z','--workdir','/workspace',
          '--env','OUTBOUND_EFFECTS=HOLD','--env','TASK_PACKET=/task/task.json','--env','TASK_RESULT=/out/result.json']
    for relative in packet['task']['write_paths']:
        p=workspace/relative
        if relative.endswith('/'):p.mkdir(parents=True,exist_ok=True)
        else:p.parent.mkdir(parents=True,exist_ok=True);p.touch(exist_ok=True)
        args+=['--volume',f'{p}:/workspace/{relative.rstrip("/")}:rw,Z']
    if policy.get('provider_secret_name'):
        args+=['--secret',policy['provider_secret_name']+',type=mount,target=agent_provider_token']
    args += [policy['agent_image_digest'],*policy['agent_argv']]
    return args

def ensure_gone(name: str):
    # The container engine is controlled by the trusted launcher, never mounted to the worker.
    r=subprocess.run(['podman','rm','--force','--ignore',name],capture_output=True,text=True,timeout=30)
    if r.returncode:raise RuntimeError('Container termination not confirmed; keep orphan reservation')
    q=subprocess.run(['podman','container','exists',name],capture_output=True,timeout=15)
    if q.returncode!=1:raise RuntimeError('Container absence not positively confirmed')

def run_one(packet: dict, policy: dict, s: Scheduler, source: Path, control: Path):
    job=control/'jobs'/f"{packet['task_key']}-{packet['fence']}"
    if job.exists():raise RuntimeError('Attempt directory already exists; reconcile rather than reuse')
    job.mkdir(parents=True,mode=0o700)
    for name in ['workspace','out','task']:(job/name).mkdir(mode=0o700)
    started=False;proc=None;container_name=f"v7-agent-{packet['task_key'].lower()}-{packet['fence']}"
    try:
        export_git(source,packet['base_revision'],job/'workspace',policy.get('max_context_bytes',100*1024*1024))
        taskbody=job/'workspace'/packet['task']['body_path']
        if packet['task'].get('body_sha256') and digest(taskbody)!=packet['task']['body_sha256']:
            raise ValueError('Source issue body differs from reviewed task graph')
        (job/'task'/'task.json').write_text(json.dumps(packet,indent=2))
        args=command(packet,policy,job)  # materializes only allowed writable scopes
        before=inventory(job/'workspace',policy.get('max_context_bytes',100*1024*1024))
        overflow=threading.Event();stop_drain=threading.Event()
        proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        started=True
        def drain():
            total=0
            with (job/'private-agent.log').open('wb') as log:
                while True:
                    block=proc.stdout.read(8192)
                    if not block:break
                    total+=len(block)
                    if total<=policy.get('max_log_bytes',2*1024*1024):log.write(block)
                    else:overflow.set()
        reader=threading.Thread(target=drain,daemon=True);reader.start()
        start=time.monotonic();last=0.0
        while proc.poll() is None:
            now=time.monotonic()
            if overflow.is_set() or now-start>policy['task_timeout_seconds'] or (control/'STOP').exists() or s.status()['stopped']:
                raise RuntimeError('Stop, timeout, log limit or revoked control policy')
            if now-last>=policy['heartbeat_seconds']:
                inventory(job/'workspace',policy.get('max_output_bytes',100*1024*1024))
                inventory(job/'out',policy.get('max_output_bytes',100*1024*1024))
                s.heartbeat(packet['task_key'],packet['lease_token'],packet['fence']);last=now
            time.sleep(0.5)
        reader.join(timeout=10)
        if reader.is_alive():raise RuntimeError('Agent process output did not close')
        ensure_gone(container_name)
        if proc.returncode:raise RuntimeError('Agent adapter exited unsuccessfully')
        result=verify_result(packet,job/'workspace',job/'out',before,policy.get('max_output_bytes',100*1024*1024))
        s.finish(result) # unknown actual usage conservatively charges the cost reservation
        return {'task_key':packet['task_key'],'state':'REVIEW_OR_BLOCKED','job_directory':str(job)}
    except Exception as exc:
        if started:
            # Even successful local termination does not prove remote submission outcome.
            try:ensure_gone(container_name)
            except Exception:pass
            if proc and proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
            s.quarantine(packet['task_key'],str(exc))
            return {'task_key':packet['task_key'],'state':'ORPHANED','reason':str(exc)}
        result={k:packet[k] for k in ['task_key','lease_token','fence','input_sha256','base_revision']}
        result.update(status='blocked',summary='Prelaunch blocker',changed_paths=[],tests=[],artifacts=[],blockers=[str(exc)])
        s.finish(result,trusted_cost=0)
        return {'task_key':packet['task_key'],'state':'BLOCKED','reason':str(exc)}

def source_contains_prerequisites(source: Path, base: str, scheduler: Scheduler, key: str) -> bool:
    """Do not give a dependent agent a stale checkout missing accepted work."""
    if not re.fullmatch(r'[a-f0-9]{40}',base):raise ValueError('Trusted immutable Git base required')
    for dep in scheduler.tasks[key].get('depends_on',[]):
        row=scheduler.record(dep)
        if row['state']!='ACCEPTED' or not row.get('receipt'):return False
        receipt=json.loads(row['receipt']);revision=receipt.get('revision','')
        if not re.fullmatch(r'[a-f0-9]{40}',revision):return False
        q=subprocess.run(['git','-C',str(source),'merge-base','--is-ancestor',revision,base],capture_output=True,timeout=15)
        if q.returncode!=0:return False
    return True

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy',required=True);p.add_argument('--source',required=True)
    p.add_argument('--graph',default=str(ROOT/'orchestration/task_graph.json'))
    p.add_argument('--control',default=str(ROOT/'.control'));p.add_argument('--watch',action='store_true')
    a=p.parse_args();policy=json.loads(Path(a.policy).read_text());validate_live_policy(policy);podman_check()
    source=Path(a.source).resolve();control=Path(a.control).resolve()
    # Controller data MUST NOT be inside a source export or an agent-owned directory.
    control.mkdir(parents=True,exist_ok=True,mode=0o700);control.chmod(0o700)
    tasks=json.loads(Path(a.graph).read_text())['tasks'];s=Scheduler(control/'state.sqlite3',tasks,policy)
    seq=0;pending=set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=policy['max_workers']) as pool:
        while True:
            if (control/'STOP').exists():s.stop('STOP file present')
            for f in list(pending):
                if f.done():print(json.dumps(f.result()),flush=True);pending.remove(f)
            while len(pending)<policy['max_workers'] and not s.status()['stopped']:
                base=subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],check=True,text=True,capture_output=True,timeout=15).stdout.strip()
                seq+=1;agent=f'isolated-worker-{os.getpid()}-{seq}'
                packet=None
                for key in s.status()['ready']:
                    if source_contains_prerequisites(source,base,s,key):
                        packet=s.claim(agent,base,requested_key=key)
                        if packet is not None:break
                if packet is None:break
                pending.add(pool.submit(run_one,packet,policy,s,source,control))
                print(json.dumps({'event':'LAUNCH_SUBMITTED','task_key':packet['task_key'],'fence':packet['fence']}),flush=True)
            if not pending and (not a.watch or s.status()['stopped']):break
            time.sleep(1 if pending else 5)
    summary=s.status();summary.pop('tasks',None);print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
