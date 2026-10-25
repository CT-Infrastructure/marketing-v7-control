#!/usr/bin/env python3
"""Inspect/initialize the local ledger. No live agent dispatch or production actions."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from scheduler import Scheduler
ROOT = Path(__file__).resolve().parents[1]
def load(path):
    return json.loads(Path(path).read_text())
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['init','status','plan','stop'])
    p.add_argument('--graph', default=str(ROOT/'orchestration/task_graph.json'))
    p.add_argument('--policy', default=str(ROOT/'config/orchestration.example.json'))
    p.add_argument('--state', default=str(ROOT/'.control/state.sqlite3'))
    p.add_argument('--reason', default='Operator requested stop')
    a=p.parse_args(); policy=load(a.policy); tasks=load(a.graph)['tasks']
    s=Scheduler(a.state,tasks,policy)
    if a.command=='stop':s.stop(a.reason)
    data=s.status()
    if a.command=='plan':
        data.pop('tasks',None)
        data['note']='Readiness projection only; this command launches no agents and accepts no work.'
    print(json.dumps(data,indent=2))
if __name__=='__main__':main()
