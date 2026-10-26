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

def workflow_mapping(record,canonical):
 need(type(record) is dict)
 mappings=[]
 for key in ('workflow_id','workflow_ids','workflows'):
  if key not in record:continue
  value=record[key]
  if key=='workflow_id':
   need(type(value) is str);value=[value]
  need(type(value) is list and all(type(wid) is str and wid in canonical for wid in value))
  need(len(value)==len(set(value)))
  mappings.append(value)
 if not mappings:return []
 need(all(set(value)==set(mappings[0]) for value in mappings))
 return mappings[0]

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
 # Derive relations only from the bytes already verified against source pins.
 registry=source_value('reference/components/component_registry.json')['components']
 component_names={item['component_id']:item['name'] for item in registry}
 need(len(component_names)==len(registry)==147)
 names=set(component_names.values());need(len(names)==147)
 expected_consumers={cid:{} for cid in component_names}
 by_name={name:cid for cid,name in component_names.items()}
 for path in pins:
  if not (path.startswith('reference/workflows/') and path.endswith('.json')):continue
  workflow=source_value(path);wid=workflow['id'];fields=[]
  if 'source_software' in workflow:fields.append(('/source_software',workflow['source_software']))
  fields.extend((f'/software/{i}',value) for i,value in enumerate(workflow['software']))
  fields.extend((f'/steps/{i}/software',step['software']) for i,step in enumerate(workflow['steps']))
  for pointer,value in fields:
   need(type(value) is str)
   tokens={s.strip() for s in re.split(r',|;| / | \+ ',value) if s.strip()}
   for name in tokens & names:
    expected_consumers[by_name[name]].setdefault(wid,set()).add((path,pointer))
 expected_edges={cid:set() for cid in component_names}
 issues=source_value('backlog/issues.json')['issues'];need(type(issues) is list)
 issue_keys=set()
 for i,issue in enumerate(issues):
  key=issue['key'];need(type(key) is str and key not in issue_keys);issue_keys.add(key)
  wid=issue.get('workflow_id')
  if wid is None:continue
  need(wid in canonical_workflows)
  dependencies=issue['depends_on'];need(type(dependencies) is list)
  need(len(dependencies)==len(set(dependencies)))
  for position,dependency in enumerate(dependencies):
   if dependency in component_names:
    expected_edges[dependency].add((wid,key,'backlog/issues.json',f'/issues/{i}/depends_on/{position}'))
 # Exact registry membership excludes combined provider component strings.
 native_path='contracts/adapters/catalog.v1.json'
 adapters=source_value(native_path)['adapters'];need(type(adapters) is list)
 expected_roles={cid:set() for cid in component_names}
 for index,native in enumerate(adapters):
  need(type(native) is dict and type(native['component']) is str)
  cid=native['component']
  if cid not in component_names:continue
  values=tuple(native[field] for field in ('native_owner','api_boundary','native_dependencies'))
  need(all(type(value) is str for value in values))
  identity=(native_path,f'/adapters/{index}',*values)
  need(identity not in expected_roles[cid]);expected_roles[cid].add(identity)
 for row in rows:
  source=citation(row['registry_evidence']);need(source['component_id']==row['component_id'] and source['name']==row['canonical_name'])
  need(row['qualified'] is False and row['production_authorized'] is False and row['runtime_status']=='NOT_RUN')
  need(row['source_declared_workflows_unconfirmed']==source['supports_workflows'])
  need(row['source_classification']==source['source_classification'])
  if source['source_classification']=='CONDITIONAL_NOT_INSTALLED':
   need(row['disposition']=='CONDITIONAL_DEFERRED_NO_INSTALL_AUTHORITY')
  relations=row['direct_source_named_consumers'];need(type(relations) is list and len(relations)==len({r['workflow_id'] for r in relations}))
  need({r['workflow_id'] for r in relations}==set(expected_consumers[row['component_id']]))
  for relation in relations:
   actual_parts=[]
   need(type(relation) is dict and relation['workflow_id'] in canonical_workflows)
   need(type(relation.get('evidence')) is list and bool(relation['evidence']))
   for part in relation['evidence']:
    need(type(part) is dict)
    value=citation(part['evidence']);need(type(value) is str)
    tokens=[s.strip() for s in re.split(r',|;| / | \+ ',value) if s.strip()]
    need(part['canonical_token']==row['canonical_name'] and row['canonical_name'] in tokens)
    need(PurePosixPath(part['evidence']['path']).stem==relation['workflow_id'])
    actual_parts.append((part['evidence']['path'],part['evidence']['pointer']))
   need(len(actual_parts)==len(set(actual_parts)))
   need(set(actual_parts)==expected_consumers[row['component_id']][relation['workflow_id']])
  edges=row['engineering_prerequisite_edges'];need(type(edges) is list)
  actual_edges=[]
  for edge in edges:
   need(type(edge) is dict and citation(edge['evidence'])==row['component_id'])
   evidence=edge['evidence'];pointer=evidence['pointer']
   need(evidence['path']=='backlog/issues.json' and type(pointer) is str)
   match=re.fullmatch(r'/issues/(0|[1-9][0-9]*)/depends_on/(0|[1-9][0-9]*)',pointer);need(match is not None)
   parent=issues[int(match[1])];position=int(match[2])
   need(parent['key']==edge['package_key'] and parent['workflow_id']==edge['workflow_id'])
   need(parent['depends_on'][position]==row['component_id'])
   actual_edges.append((edge['workflow_id'],edge['package_key'],evidence['path'],pointer))
  need(len(actual_edges)==len(set(actual_edges)))
  need(set(actual_edges)==expected_edges[row['component_id']])
  roles=row['authoritative_native_roles'];need(type(roles) is list)
  actual_roles=[]
  for role in roles:
   need(type(role) is dict)
   native=citation(role['evidence']);need(native['component']==row['component_id'])
   need(role['evidence']['path']=='contracts/adapters/catalog.v1.json')
   need(role['native_owner']==native['native_owner'])
   need(role['api_boundary']==native['api_boundary'])
   need(role['native_dependencies_text']==native['native_dependencies'])
   values=tuple(role[field] for field in ('native_owner','api_boundary','native_dependencies_text'))
   need(all(type(value) is str for value in values))
   actual_roles.append((role['evidence']['path'],role['evidence']['pointer'],*values))
  need(len(actual_roles)==len(set(actual_roles)))
  need(set(actual_roles)==expected_roles[row['component_id']])
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
 finding_keys=set()
 for finding in review['audit_findings']:
  need(type(finding) is dict)
  key=finding['finding_key'];need(type(key) is str and bool(key.strip()) and key not in finding_keys)
  finding_keys.add(key)
  curated=finding['workflow_ids']
  need(type(curated) is list)
  expected=workflow_mapping(finding['raw_finding_with_private_locations_redacted'],canonical_workflows)
  need(set(workflow_mapping({'workflow_ids':curated},canonical_workflows))==set(expected))
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


