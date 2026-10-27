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

ARTIFACT_PATHS=frozenset(('docs/traceability/README.md',)+tuple(
 'docs/traceability/curation-public/'+name for name in (
 'component-curation.json','README.md','review-dispositions.json',
 'shared-contract-evidence.json','source-manifest.json','summary.json',
 'test_portable.py','validate_portable.py','offline-amendments.json')))

def verify_artifacts(root,package=PACKAGE):
 """Separate artifact gate; semantic fixtures do not bypass or mask this gate."""
 entries=load(package,'portable-manifest.json')['artifacts']
 need(type(entries) is list and len(entries)==len(ARTIFACT_PATHS))
 seen=set()
 for entry in entries:
  need(type(entry) is dict and set(entry)=={'path','sha256','bytes'})
  path=entry['path'];need(type(path) is str and path in ARTIFACT_PATHS and path not in seen)
  seen.add(path)
  need(type(entry['bytes']) is int and entry['bytes']>=0)
  need(type(entry['sha256']) is str and re.fullmatch('[a-f0-9]{64}',entry['sha256']))
  data=raw(root,path).replace(b'\r\n',b'\n')
  need(len(data)==entry['bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256'])
 need(seen==ARTIFACT_PATHS)
 return {'status':'ARTIFACT_INTEGRITY_VALID','artifacts':len(seen)}

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

def guard_public_inventory(value):
 """Recursively reject private locations, including embedded historical proposals."""
 if type(value) is dict:
  for key,item in value.items():
   guard_public_inventory(key);guard_public_inventory(item)
  if any(key in value for key in ('source_contract_path','original_parent_path','audit_path')):
   for key in ('source_contract_path','original_parent_path','audit_path'):
    if key not in value:continue
    item=value[key]
    need(item is None or item=='' or (type(item) is str and re.fullmatch(
     r'urn:document:O20-[0-9]{2}:(?:source-contract|parent|audit):sha256:[a-f0-9]{64}#/technical_amendments/0/prior_proposal/parent_plans/[0-9]+/(?:source_contract_path|original_parent_path|audit_path)',item) is not None))
 elif type(value) is list:
  for item in value:guard_public_inventory(item)
 elif type(value) is str:
  need(not re.search(r'[A-Za-z]:[\\/]|\.control|/(?:Users|home)/|(?:workstream_workflows|repository-orchestrators|repo_control)(?:[/\\]|$)',value,re.I))

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
 # Bind complete placement and parent sets to their containing source records.
 placement_path='policies/container/native-exceptions.json'
 expected_placements={cid:set() for cid in component_names}
 placements=source_value(placement_path)['placements'];need(type(placements) is list)
 for index,placement in enumerate(placements):
  need(type(placement) is dict and type(placement['components']) is list)
  need(all(type(name) is str for name in placement['components']))
  need(len(placement['components'])==len(set(placement['components'])))
  need(type(placement['placement']) is str and type(placement['owner']) is str)
  need(type(placement['deployment_authorized']) is bool)
  for name in placement['components']:
   if name in by_name:
    expected_placements[by_name[name]].add((placement_path,f'/placements/{index}',
     placement['placement'],placement['owner'],placement['deployment_authorized']))
 registry_path='reference/components/component_registry.json'
 expected_native_parents={cid:set() for cid in component_names}
 for index,child in enumerate(registry):
  # Missing or explicit null means no association; every non-null value is strict.
  parent_name=child.get('native_parent')
  if parent_name is None:continue
  need(type(parent_name) is str and parent_name in by_name)
  workflows=sorted(expected_consumers[child['component_id']])
  expected_native_parents[by_name[parent_name]].add((registry_path,
   f'/components/{index}/native_parent',child['component_id'],tuple(sorted(workflows))))
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
   need(relation['basis']=='EXACT_CANONICAL_SOFTWARE_TOKEN' and relation['runtime_state']=='NOT_RUN')
   need(relation['consumer_confirmation']=='SOURCE_NAMED_ONLY_NOT_RUNTIME_CONFIRMED')
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
   need(edge['basis']=='EXACT_EXISTING_PACKAGE_PREREQUISITE' and edge['not_automatically_a_direct_consumer'] is True)
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
   need(type(role) is dict and role['runtime_state']=='NOT_RUN')
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
  placements=row['native_placement_evidence'];need(type(placements) is list)
  actual_placements=[]
  for placement in placements:
   need(type(placement) is dict)
   evidence=placement['evidence'];native=citation(evidence)
   need(type(native) is dict and row['canonical_name'] in native['components'])
   need(type(placement['placement']) is str and type(placement['owner_role']) is str)
   need(type(placement['deployment_authorized']) is bool)
   need(placement['placement']==native['placement'] and placement['owner_role']==native['owner'])
   need(placement['deployment_authorized'] is native['deployment_authorized'])
   actual_placements.append((evidence['path'],evidence['pointer'],placement['placement'],
    placement['owner_role'],placement['deployment_authorized']))
  need(len(actual_placements)==len(set(actual_placements)))
  need(set(actual_placements)==expected_placements[row['component_id']])
  parents=row['explicit_native_parent_support'];need(type(parents) is list)
  actual_parents=[]
  for parent in parents:
   need(type(parent) is dict and parent['basis']=='EXPLICIT_NATIVE_PARENT_NOT_DIRECT_CONSUMER')
   evidence=parent['evidence'];need(citation(evidence)==row['canonical_name'])
   need(evidence['path']==registry_path and type(evidence['pointer']) is str)
   match=re.fullmatch(r'/components/(0|[1-9][0-9]*)/native_parent',evidence['pointer']);need(match is not None)
   child=registry[int(match[1])]
   need(type(parent['child_component_id']) is str and parent['child_component_id']==child['component_id'])
   workflows=workflow_mapping({'workflow_ids':parent['workflow_ids']},canonical_workflows)
   need(set(workflows)==set(expected_consumers[child['component_id']]))
   actual_parents.append((evidence['path'],evidence['pointer'],parent['child_component_id'],tuple(sorted(workflows))))
  need(len(actual_parents)==len(set(actual_parents)))
  need(set(actual_parents)==expected_native_parents[row['component_id']])
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
 for name in ('component-curation.json','review-dispositions.json','source-manifest.json','shared-contract-evidence.json','summary.json','portable-manifest.json'):
  # Semantic fixture packages may omit the two artifact-only documents.
  if name in ('summary.json','portable-manifest.json') and not (Path(package)/name).exists():continue
  guard_public_inventory(load(package,name))
 return {'status':'SOURCE_EVIDENCE_VALID','components':147,'workflows':190,'pending_findings':28,'qualified':False,'runtime_status':'NOT_RUN'}


OFFLINE_AMENDMENT_SHA256 = '95938473a464f9b76b15c551dd71ec79fd99811a776b99298682d0424db76b9b'

def validate_m29_gate(change):
 """Preserve native authority/readiness independently of the proposal digest."""
 expected='Applicable permission, approval and destination readiness valid?'
 required=(
  'Additionally, qualification requires a current E11 control receipt;',
  'this does not replace permission, approval or destination readiness.',
  'Missing, stale or ambiguous authority, readiness or E11 evidence is UNKNOWN and remains HOLD pending reconciliation.',
  'Ordinary isolated fixture tests remain permitted.',
  'No hard build edge is established.')
 if not (type(change) is dict and change.get('path')=='reference/workflows/M29.json'
  and change.get('pointer')=='/gate' and change.get('old_value')==expected
  and type(change.get('proposed_value')) is str
  and change['proposed_value'].startswith(expected+' ')
  and all(fragment in change['proposed_value'] for fragment in required)):
  raise ValueError('M29 gate preservation: native predicate, additive E11 and UNKNOWN/HOLD required')

def validate_amendments(source_root,package=PACKAGE):
 """Check the fixed proposal contract and its exact immutable field bindings."""
 doc=load(package,'offline-amendments.json');guard_public_inventory(doc)
 m29=[row for row in doc['rows'] if row['finding_key']=='O20-17:SA-02'];need(len(m29)==1)
 need(len(m29[0]['changes'])==1);validate_m29_gate(m29[0]['changes'][0])
 need(hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==OFFLINE_AMENDMENT_SHA256)
 need(doc['status']=='PROPOSED_NOT_ADOPTED' and doc['qualified'] is False)
 need(doc['production_authorized'] is False and doc['accepted_decision_receipt'] is None)
 need(doc['runtime_status']=='NOT_RUN' and doc['applied_graph_changes']==[])
 review=load(package,'review-dispositions.json')
 need(len(doc['rows'])==28 and len({r['finding_key'] for r in doc['rows']})==28)
 need({r['finding_key'] for r in doc['rows']}=={r['finding_key'] for r in review['audit_findings']})
 need(sum(r['kind']=='BOUNDED_AMENDMENT' for r in doc['rows'])==13)
 pins={s['path']:s['sha256_lf'] for s in load(package,'source-manifest.json')['sources']}
 public=doc['public_source_pins'];need(len(public)==413 and len({s['path'] for s in public})==413)
 for source in public:
  path=source['path'];pin=source['sha256_lf']
  need(path not in pins or pins[path]==pin)
  need(normalized_sha(source_root,path)==pin);pins[path]=pin
 for row in doc['rows']:
  ref=row['source_disposition']
  need(ref['path']=='review-dispositions.json' and normalized_sha(package,ref['path'])==ref['sha256_lf'])
  finding=get_pointer(review,ref['pointer']);need(finding['finding_key']==row['finding_key'])
  need(hashlib.sha256(json.dumps(finding,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==ref['finding_sha256'])
  need(row['selection'] is None and row['accepted_decision_receipt'] is None)
  if row['kind']=='UNANSWERED_CHOICE':need(len(row['alternatives'])>=2 and not row['changes'])
  else:need(bool(row['changes']))
  for item in row.get('curated_evidence',[]):
   need(normalized_sha(package,item['path'])==item['sha256_lf'])
   need(get_pointer(load(package,item['path']),item['pointer'])==item['old_value'])
  for item in row['source_evidence']+row['changes']:
   path=item['path'];need(path in pins and item['sha256_lf']==pins[path])
   need(normalized_sha(source_root,path)==pins[path])
   if item.get('source_kind')=='TEXT_LINE':
    match=re.fullmatch(r'/lines/([1-9][0-9]*)',item['pointer']);need(match is not None)
    value=raw(source_root,path).decode('utf-8-sig').splitlines()[int(match[1])-1]
   else:value=get_pointer(load(source_root,path),item['pointer'])
   need(type(value) is type(item['old_value']) and value==item['old_value'])
   need(hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()==item['old_value_sha256'])
 return {'status':'PROPOSAL_BINDINGS_VALID','bounded_amendments':13,'unanswered_choices':15,'adopted':False}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-root',type=Path,default=PACKAGE.parents[2]);args=parser.parse_args()
 try:
  verify_artifacts(PACKAGE.parents[2],PACKAGE)
  validate_amendments(args.source_root,PACKAGE)
  print(json.dumps(validate(args.source_root)));return 0
 except (OSError,ValueError,TypeError,KeyError,IndexError,RecursionError):
  print(json.dumps({'status':'INVALID_SOURCE_EVIDENCE','qualified':False}));return 2
if __name__=='__main__':raise SystemExit(main())


