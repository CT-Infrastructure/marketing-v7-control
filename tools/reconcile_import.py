#!/usr/bin/env python3
"""Trusted operator only: release a blocked importer after remote read-back.

This does NOT itself determine whether GitHub committed a write. Preserve a private
read-back evidence file, verify the exact target/pending operation and remote state,
then explicitly authorize resumption. The importer next re-discovers remote objects.
"""
import argparse,hashlib,json,fcntl
from pathlib import Path
from seed_github import atomic_json

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--journal',required=True);p.add_argument('--confirm-target',required=True);p.add_argument('--confirm-pending-key',required=True);p.add_argument('--evidence-file',required=True);p.add_argument('--evidence-sha256',required=True);p.add_argument('--verified-by',required=True);a=p.parse_args()
 path=Path(a.journal);lock=path.with_suffix('.lock')
 with lock.open('w') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  state=json.loads(path.read_text());pending=state.get('pending')
  if state['target']!=a.confirm_target or not pending or pending['key']!=a.confirm_pending_key:raise ValueError('Explicit target/pending operation mismatch')
  evidence=Path(a.evidence_file).read_bytes()
  if not evidence or hashlib.sha256(evidence).hexdigest()!=a.evidence_sha256:raise ValueError('Read-back evidence hash mismatch')
  state.setdefault('operator_reconciliations',[]).append({'operation':pending,'evidence_sha256':a.evidence_sha256,'verified_by':a.verified_by,'meaning':'Operator inspected remote state and authorized importer re-discovery; not proof of full import.'})
  state['pending']=None;atomic_json(path,state)
 print('Pending operation released after operator reconciliation; resume the importer to re-discover remote state.')
if __name__=='__main__':main()
