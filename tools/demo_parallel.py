#!/usr/bin/env python3
"""Synthetic concurrency demonstration. No LLM, GitHub or real workflow execution."""
from __future__ import annotations
import argparse, concurrent.futures, json, tempfile, threading, time
from pathlib import Path
from scheduler import Scheduler

def result(packet):
    return {'task_key':packet['task_key'],'lease_token':packet['lease_token'],'fence':packet['fence'],
            'input_sha256':packet['input_sha256'],'base_revision':packet['base_revision'],
            'status':'ready_for_review','summary':'Synthetic demo only','changed_paths':[], 'tests':[], 'artifacts':[], 'blockers':[]}
def run_demo(workers=8):
    tasks=[]
    for n in range(24):
        tasks.append({'key':f'DEMO-{n:02}','depends_on':[] if n<20 else [f'DEMO-{n-20:02}'],
                      'write_paths':[f'demo/{n}/'],'locks':['exclusive-demo'] if n in [3,4] else [],
                      'resources':{'cpu':1,'memory_mib':32,'gpu':0,'slots':1,'integration':0},
                      'priority':'P1','manual':False,'enabled_by_default':True})
    policy={'max_workers':workers,'capacities':{'cpu':workers,'memory_mib':workers*64,'gpu':0,'slots':workers,'integration':1},
            'lease_seconds':60,'max_attempts':2,'max_cost_per_task_usd':0,'total_cost_budget_usd':0}
    active=0;peak=0;guard=threading.Lock()
    with tempfile.TemporaryDirectory() as tmp:
        s=Scheduler(Path(tmp)/'demo.sqlite3',tasks,policy)
        def worker(packet):
            nonlocal active,peak
            with guard: active+=1;peak=max(peak,active)
            time.sleep(0.035)
            s.finish(result(packet),trusted_cost=0)
            # Explicit synthetic acceptance is never used for the real graph.
            s.accept(packet['task_key'],{'task_key':packet['task_key'],'verified_by':'synthetic-reviewer','independent_review':True,
                     'checks_verified':True,'revision':'DEMO-NOT-A-COMMIT','graph_sha256':s.graph_hash,
                     'evidence_level':'CODE_MERGED','source':'synthetic-demo'})
            with guard: active-=1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            pending=set();seq=0
            while True:
                pending={f for f in pending if not f.done() or f.result() is not None}
                while len(pending)<workers:
                    packet=s.claim(f'demo-worker-{seq}','DEMO-BASE');seq+=1
                    if packet is None:break
                    pending.add(pool.submit(worker,packet))
                if not pending:break
                done,_=concurrent.futures.wait(pending,return_when=concurrent.futures.FIRST_COMPLETED)
                for f in done:f.result();pending.remove(f)
        state=s.status()
        return {'mode':'SYNTHETIC_ONLY','ai_agents_launched':0,'github_mutations':0,'production_actions':0,
                'synthetic_tasks':len(tasks),'accepted':state['counts'].get('ACCEPTED',0),
                'configured_workers':workers,'observed_peak_parallel_mock_workers':peak,
                'exclusive_lock_scenario_included':True,'all_completed':state['counts'].get('ACCEPTED')==len(tasks)}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--workers',type=int,default=8);p.add_argument('--output');a=p.parse_args()
    if not 1<=a.workers<=64:p.error('workers must be between 1 and 64')
    data=run_demo(a.workers);text=json.dumps(data,indent=2);print(text)
    if a.output:Path(a.output).write_text(text+'\n')
