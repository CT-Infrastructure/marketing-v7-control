"""Read-only portable curation checks; no network, credentials or runtime authority."""
import argparse,hashlib,json,re,stat
from pathlib import Path,PurePosixPath
PACKAGE=Path(__file__).resolve().parent
MAX_BYTES=16*1024*1024

def need(value):
 if not value:raise ValueError('invalid or changed portable curation evidence')
def safe_file(root,relative):
 need(type(relative) is str and bool(relative) and '\\' not in relative and ':' not in relative)
 parts=relative.split('/')
 need(all(p not in ('','.','..') and not any(ord(c)<32 for c in p) for p in parts))
 root=Path(root).absolute()
 need(not root.is_symlink() and all(not p.is_symlink() for p in root.parents))
 target=root.joinpath(*parts)
 need(not target.is_symlink() and all(not p.is_symlink() for p in target.parents))
 need(target.resolve().is_relative_to(root.resolve()))
 info=target.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=MAX_BYTES)
 return target

def raw(root,relative):
 with safe_file(root,relative).open('rb') as stream:data=stream.read(MAX_BYTES+1)
 need(len(data)<=MAX_BYTES);return data
def normalized_sha(root,relative):return hashlib.sha256(raw(root,relative).replace(b'\r\n',b'\n')).hexdigest()
def pairs(items):
 out={}
 for k,v in items:
  need(k not in out);out[k]=v
 return out
def load(root,relative):
 try:return json.loads(raw(root,relative).decode('utf-8-sig'),object_pairs_hook=pairs)
 except (RecursionError,UnicodeError) as exc:raise ValueError('invalid bounded JSON') from exc

def get_pointer(value,pointer):
 need(type(pointer) is str and (pointer=='' or pointer.startswith('/')))
 for token in pointer[1:].split('/') if pointer else []:
  key=token.replace('~1','/').replace('~0','~')
  value=value[int(key)] if isinstance(value,list) else value[key]
 return value

def validate(source_root,package=PACKAGE):
 manifest=load(package,'source-manifest.json');need(type(manifest) is dict)
 sources=manifest['sources'];need(type(sources) is list)
 pins={};source_bytes={};source_json={}
 def source_value(path):
  if path not in source_json:
   try:source_json[path]=json.loads(source_bytes[path].decode('utf-8-sig'),object_pairs_hook=pairs)
   except (RecursionError,UnicodeError) as exc:raise ValueError('invalid bounded source JSON') from exc
  return source_json[path]
 for source in sources:
  need(type(source) is dict and set(source)=={'path','sha256_lf'})
  path=source['path'];pin=source['sha256_lf']
  need(path not in pins and type(pin) is str and re.fullmatch('[a-f0-9]{64}',pin))
  data=raw(source_root,path)
  need(hashlib.sha256(data.replace(b'\r\n',b'\n')).hexdigest()==pin)
  pins[path]=pin;source_bytes[path]=data
 canonical_workflows=set()
 for path in pins:
  if path.startswith('reference/workflows/') and path.endswith('.json'):
   value=source_value(path);wid=value.get('id') if type(value) is dict else None
   need(type(wid) is str and wid==PurePosixPath(path).stem and wid not in canonical_workflows)
   canonical_workflows.add(wid)
 need(len(canonical_workflows)==190)
 def citation(evidence):
  need(type(evidence) is dict and evidence['path'] in pins and evidence['sha256_lf']==pins[evidence['path']])
  value=None
  if evidence.get('pointer'):
   value=get_pointer(source_value(evidence['path']),evidence['pointer'])
  if 'quote'in evidence:need(value==evidence['quote'])
  if 'lines'in evidence:
   lines=source_bytes[evidence['path']].decode('utf-8-sig').splitlines()
   need(all(type(n) is int and 1<=n<=len(lines) for n in evidence['lines']))
  return value
 doc=load(package,'component-curation.json');rows=doc['components']
 need(doc['qualified'] is False and doc['runtime_status']=='NOT_RUN')
 need(type(rows) is list and len(rows)==147)
 need({r['component_id'] for r in rows}=={f'CP{i:03d}' for i in range(1,148)})
 for row in rows:
  source=citation(row['registry_evidence']);need(source['component_id']==row['component_id'] and source['name']==row['canonical_name'])
  need(row['qualified'] is False and row['production_authorized'] is False and row['runtime_status']=='NOT_RUN')
  need(row['source_declared_workflows_unconfirmed']==source['supports_workflows'])
  need(row['source_classification']==source['source_classification'])
  if source['source_classification']=='CONDITIONAL_NOT_INSTALLED':
   need(row['disposition']=='CONDITIONAL_DEFERRED_NO_INSTALL_AUTHORITY')
  relations=row['direct_source_named_consumers'];need(type(relations) is list and len(relations)==len({r['workflow_id'] for r in relations}))
  for relation in relations:
   need(type(relation) is dict and relation['workflow_id'] in canonical_workflows)
   need(type(relation.get('evidence')) is list and bool(relation['evidence']))
   for part in relation['evidence']:
    need(type(part) is dict)
    value=citation(part['evidence']);need(type(value) is str)
    tokens=[s.strip() for s in re.split(r',|;| / | \+ ',value) if s.strip()]
    need(part['canonical_token']==row['canonical_name'] and row['canonical_name'] in tokens)
    need(PurePosixPath(part['evidence']['path']).stem==relation['workflow_id'])
  for edge in row['engineering_prerequisite_edges']:need(citation(edge['evidence'])==row['component_id'])
  for role in row['authoritative_native_roles']:need(citation(role['evidence'])['component']==row['component_id'])
  for placement in row['native_placement_evidence']:need(row['canonical_name'] in citation(placement['evidence'])['components'])
  for parent in row['explicit_native_parent_support']:need(citation(parent['evidence'])==row['canonical_name'])
 shared=load(package,'shared-contract-evidence.json')
 for entry in shared['constraints']:citation(entry['evidence'])
 review=load(package,'review-dispositions.json');need(review['qualified'] is False)
 need(len(review['parents'])==len(review['audits'])==20 and len(review['audit_findings'])==28)
 expected_parents={f'O20-{i:02d}' for i in range(1,21)}
 for collection in (review['parents'],review['audits']):
  need(type(collection) is list and all(type(row) is dict for row in collection))
  names=[row['parent'] for row in collection]
  need(len(names)==len(set(names))==20 and set(names)==expected_parents)
 ids=[wid for parent in review['parents'] for wid in parent['workflow_ids']]
 need(all(type(wid) is str for wid in ids) and len(ids)==len(set(ids))==190 and set(ids)==canonical_workflows)
 for finding in review['audit_findings']:
  need(finding['disposition']=='PENDING_ROOT_REVIEW_NO_SOURCE_OR_GRAPH_CHANGE')
  need(re.fullmatch('[a-f0-9]{64}',finding['original_audit_document_sha256']) is not None)
 for name in ('component-curation.json','review-dispositions.json','source-manifest.json','shared-contract-evidence.json'):
  text=raw(package,name).decode('utf-8-sig')
  need(not re.search(r'[A-Za-z]:[\\/]|\.control|/Users/|/home/',text))
 return {'status':'SOURCE_EVIDENCE_VALID','components':147,'workflows':190,'pending_findings':28,'qualified':False,'runtime_status':'NOT_RUN'}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-root',type=Path,default=PACKAGE.parents[2]);args=parser.parse_args()
 try:print(json.dumps(validate(args.source_root)));return 0
 except (OSError,ValueError,TypeError,KeyError,IndexError,RecursionError):
  print(json.dumps({'status':'INVALID_SOURCE_EVIDENCE','qualified':False}));return 2
if __name__=='__main__':raise SystemExit(main())


