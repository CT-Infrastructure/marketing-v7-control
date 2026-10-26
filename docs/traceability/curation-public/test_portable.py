"""Portable validator tests; CURATION_SOURCE_ROOT selects a read-only public checkout."""
import json,os,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import validate_portable as v
class PortableTests(unittest.TestCase):
 def test_complete_public_source(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  result=v.validate(source);self.assertEqual(result['components'],147);self.assertFalse(result['qualified'])
 def test_relative_containment(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);(root/'ok').write_text('x')
   for path in ('../ok','/ok','C:/ok','a/../ok','a\\ok','','./ok','a//ok'):
    with self.subTest(path=path),self.assertRaises(ValueError):v.safe_file(root,path)
   self.assertEqual(v.safe_file(root,'ok'),root/'ok')
 def test_symlink_escape(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);(root/'target').mkdir();(root/'target/file').write_text('x')
   try:(root/'link').symlink_to(root/'target',target_is_directory=True)
   except OSError:self.skipTest('OS does not grant local symlink creation')
   with self.assertRaises(ValueError):v.safe_file(root,'link/file')
 def test_nonregular_and_size(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);(root/'folder').mkdir();(root/'file').write_text('xx')
   with self.assertRaises(ValueError):v.safe_file(root,'folder')
   with patch.object(v,'MAX_BYTES',1),self.assertRaises(ValueError):v.safe_file(root,'file')
 def test_duplicate_json_rejected(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);(root/'test.json').write_text('{"a":1,"a":2}')
   with self.assertRaises(ValueError):v.load(root,'test.json')
 def test_canonical_identity_tampering_rejected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory)
   for name in ('component-curation.json','source-manifest.json','review-dispositions.json','shared-contract-evidence.json'):shutil.copyfile(v.PACKAGE/name,root/name)
   path=root/'component-curation.json';doc=json.loads(path.read_text());doc['components'][0]['canonical_name']='invented-name';path.write_text(json.dumps(doc))
   with self.assertRaises(ValueError):v.validate(source,root)
 def package_copy(self, root):
  for name in ('component-curation.json','source-manifest.json','review-dispositions.json','shared-contract-evidence.json'):
   shutil.copyfile(v.PACKAGE/name,root/name)
 def test_empty_or_fake_direct_evidence_rejected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  for mutation in ('empty','wrong_type','fake_workflow'):
   with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);self.package_copy(root)
    path=root/'component-curation.json';doc=json.loads(path.read_text())
    relation=next(r for c in doc['components'] for r in c['direct_source_named_consumers'])
    if mutation=='empty':relation['evidence']=[]
    elif mutation=='wrong_type':relation['evidence']={}
    else:relation['workflow_id']='FAKE01'
    path.write_text(json.dumps(doc))
    with self.subTest(mutation=mutation),self.assertRaises(ValueError):v.validate(source,root)
 def test_parent_workflows_and_metadata_identities_are_canonical(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  for mutation in ('fake_workflow','duplicate_parent','duplicate_audit'):
   with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);self.package_copy(root)
    path=root/'review-dispositions.json';doc=json.loads(path.read_text())
    if mutation=='fake_workflow':doc['parents'][0]['workflow_ids'][0]='FAKE01'
    elif mutation=='duplicate_parent':doc['parents'][1]['parent']=doc['parents'][0]['parent']
    else:doc['audits'][1]['parent']=doc['audits'][0]['parent']
    path.write_text(json.dumps(doc))
    with self.subTest(mutation=mutation),self.assertRaises(ValueError):v.validate(source,root)
 def test_source_bytes_read_once_within_validation(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  original=v.raw;counts={}
  def counted(root,relative):
   if Path(root)==source:counts[relative]=counts.get(relative,0)+1
   return original(root,relative)
  with patch.object(v,'raw',side_effect=counted):v.validate(source)
  self.assertEqual(set(counts.values()),{1})
  self.assertEqual(counts['backlog/issues.json'],1)
 def test_actual_file_mutation_between_validations_is_detected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  manifest=json.loads((v.PACKAGE/'source-manifest.json').read_text())
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory)
   for item in manifest['sources']:
    target=root/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/item['path'],target)
   v.validate(root)
   changed=root/'reference/workflows/C01.json';changed.write_bytes(changed.read_bytes()+b' ')
   with self.assertRaises(ValueError):v.validate(root)
 def test_classification_and_conditional_disposition_cannot_promote(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  for field,value in (('source_classification','APPROVED'),('disposition','INSTALLED_APPROVED')):
   with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);self.package_copy(root);path=root/'component-curation.json';doc=json.loads(path.read_text())
    component=next(c for c in doc['components'] if c['source_classification']=='CONDITIONAL_NOT_INSTALLED');component[field]=value
    path.write_text(json.dumps(doc))
    with self.subTest(field=field),self.assertRaises(ValueError):v.validate(source,root)
 def test_finding_routing_mutations_rejected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  mutations={
   'lost_singular':lambda rows:rows[13].update(workflow_ids=[]),
   'lost_plural':lambda rows:rows[0].update(workflow_ids=[]),
   'fake_id':lambda rows:rows[13].update(workflow_ids=['FAKE01']),
   'wrong_canonical':lambda rows:rows[13].update(workflow_ids=['I01']),
   'duplicate_key':lambda rows:rows[1].update(finding_key=rows[0]['finding_key']),
   'blank_key':lambda rows:rows[0].update(finding_key=' '),
   'wrong_key_type':lambda rows:rows[0].update(finding_key=1),
   'duplicate_ids':lambda rows:rows[13].update(workflow_ids=['I07','I07']),
   'wrong_type':lambda rows:rows[13].update(workflow_ids='I07'),
   'raw_duplicate':lambda rows:rows[0]['raw_finding_with_private_locations_redacted'].update(workflow_ids=['C02','C02']),
   'raw_fake':lambda rows:rows[13]['raw_finding_with_private_locations_redacted'].update(workflow_id='FAKE01'),
   'raw_wrong_type':lambda rows:rows[13]['raw_finding_with_private_locations_redacted'].update(workflow_id=['I07']),
   'disagreement':lambda rows:rows[13]['raw_finding_with_private_locations_redacted'].update(workflow_ids=['I01']),
   'lost_legacy_plural':lambda rows:rows[1].update(workflow_ids=[]),
  }
  for name,mutate in mutations.items():
   with self.subTest(mutation=name),tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);self.package_copy(root)
    path=root/'review-dispositions.json';doc=json.loads(path.read_text())
    mutate(doc['audit_findings']);path.write_text(json.dumps(doc))
    with self.assertRaises(ValueError):v.validate(source,root)
 def test_explicit_mapping_only_and_agreeing_aliases(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);self.package_copy(root)
   path=root/'review-dispositions.json';doc=json.loads(path.read_text())
   finding=doc['audit_findings'][13]
   finding['raw_finding_with_private_locations_redacted']['workflow_ids']=['I07']
   path.write_text(json.dumps(doc));v.validate(source,root)
   del finding['raw_finding_with_private_locations_redacted']['workflow_id']
   del finding['raw_finding_with_private_locations_redacted']['workflow_ids']
   finding['workflow_ids']=[]
   finding['raw_finding_with_private_locations_redacted']['description']='I07 mentioned in unrelated prose'
   path.write_text(json.dumps(doc));v.validate(source,root)
   finding['workflow_ids']=['I07'];path.write_text(json.dumps(doc))
   with self.assertRaises(ValueError):v.validate(source,root)
class RelationRepairTests(unittest.TestCase):
 package_copy=PortableTests.package_copy
 def reject_mutation(self,mutate):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);self.package_copy(root)
   path=root/'component-curation.json';doc=json.loads(path.read_text())
   mutate(doc['components']);path.write_text(json.dumps(doc))
   with self.assertRaises(ValueError):v.validate(source,root)
 def test_relation_deletions_and_duplicates(self):
  for field in ('direct_source_named_consumers','engineering_prerequisite_edges'):
   for mutation in ('all','one','duplicate'):
    def mutate(rows,field=field,mutation=mutation):
     if mutation=='all':
      for row in rows:row[field]=[]
     else:
      entries=next(row[field] for row in rows if row[field])
      if mutation=='one':entries.pop()
      else:entries.append(entries[0])
    with self.subTest(field=field,mutation=mutation):self.reject_mutation(mutate)
 def test_consumer_citation_deletion_and_duplicate(self):
  for mutation in ('one','duplicate'):
   def mutate(rows):
    parts=next(r['evidence'] for c in rows for r in c['direct_source_named_consumers'] if len(r['evidence'])>1)
    if mutation=='one':parts.pop()
    else:parts.append(parts[0])
   with self.subTest(mutation=mutation):self.reject_mutation(mutate)
 def test_swapped_workflow_labels(self):
  for field in ('direct_source_named_consumers','engineering_prerequisite_edges'):
   def mutate(rows):
    entries=next(c[field] for c in rows if len(c[field])>1)
    entries[0]['workflow_id'],entries[1]['workflow_id']=entries[1]['workflow_id'],entries[0]['workflow_id']
   with self.subTest(field=field):self.reject_mutation(mutate)
 def test_prerequisite_parent_identity_retaining_citation(self):
  for mutation in ('both','workflow','package','position'):
   def mutate(rows):
    edge=rows[0]['engineering_prerequisite_edges'][0]
    self.assertEqual((edge['workflow_id'],edge['package_key']),('I05','WF-I05-VERIFY'))
    self.assertEqual(edge['evidence']['pointer'],'/issues/207/depends_on/3')
    if mutation in ('both','workflow'):edge['workflow_id']='I01'
    if mutation in ('both','package'):edge['package_key']='WF-I01-VERIFY'
    if mutation=='position':edge['evidence']['pointer']='/issues/207/depends_on/4'
   with self.subTest(mutation=mutation):self.reject_mutation(mutate)
 def test_native_contract_field_substitutions(self):
  for field,value in (('api_boundary','Direct writes to Mautic database tables'),('native_owner','Independent custom campaign owner'),('native_dependencies_text','Operational PostgreSQL only')):
   def mutate(rows):
    row=next(c for c in rows if c['component_id']=='CP058')
    row['authoritative_native_roles'][0][field]=value
   with self.subTest(field=field):self.reject_mutation(mutate)

class NativeRoleCompletenessTests(unittest.TestCase):
 package_copy=PortableTests.package_copy
 reject_mutation=RelationRepairTests.reject_mutation
 def test_native_role_deletion_one_and_all(self):
  for mutation in ('one','all'):
   def mutate(rows):
    if mutation=='all':
     for row in rows:row['authoritative_native_roles']=[]
    else:next(c['authoritative_native_roles'] for c in rows if c['authoritative_native_roles']).pop()
   with self.subTest(mutation=mutation):self.reject_mutation(mutate)
 def test_native_role_duplicates(self):
  def mutate(rows):
   entries=next(c['authoritative_native_roles'] for c in rows if c['authoritative_native_roles'])
   entries.append(entries[0].copy())
  self.reject_mutation(mutate)
 def test_native_role_extra_on_unrelated_component(self):
  def mutate(rows):
   role=next(r for c in rows for r in c['authoritative_native_roles'])
   next(c for c in rows if not c['authoritative_native_roles'])['authoritative_native_roles'].append(role.copy())
  self.reject_mutation(mutate)
 def test_native_role_wrong_fields_and_identity(self):
  for field in ('native_owner','api_boundary','native_dependencies_text','pointer','path'):
   def mutate(rows):
    role=next(r for c in rows for r in c['authoritative_native_roles'])
    if field=='pointer':role['evidence']['pointer']='/adapters/06'
    elif field=='path':role['evidence']['path']='reference/components/component_registry.json'
    else:role[field]='invented native contract value'
   with self.subTest(field=field):self.reject_mutation(mutate)
 def test_combined_provider_exclusion_control(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  catalog=json.loads((source/'contracts/adapters/catalog.v1.json').read_text())
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);self.package_copy(root)
   doc=json.loads((root/'component-curation.json').read_text())
   by_id={row['component_id']:row for row in doc['components']}
   combined=next(a for a in catalog['adapters'] if a['adapter']=='providers')
   self.assertEqual(combined['component'],'CP141/CP144/CP147')
   self.assertNotIn(combined['component'],by_id)
   for cid in ('CP141','CP144','CP147'):self.assertEqual(by_id[cid]['authoritative_native_roles'],[])
   self.assertEqual(sum(len(row['authoritative_native_roles']) for row in by_id.values()),8)
   self.assertEqual(v.validate(source,root)['runtime_status'],'NOT_RUN')
 def test_combined_provider_role_injection_rejected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  catalog=json.loads((source/'contracts/adapters/catalog.v1.json').read_text())
  index,native=next((i,a) for i,a in enumerate(catalog['adapters']) if a['adapter']=='providers')
  pin=json.loads((v.PACKAGE/'source-manifest.json').read_text())
  digest=next(s['sha256_lf'] for s in pin['sources'] if s['path']=='contracts/adapters/catalog.v1.json')
  for cid in ('CP141','CP144','CP147'):
   def mutate(rows):
    row=next(c for c in rows if c['component_id']==cid)
    row['authoritative_native_roles'].append({'native_owner':native['native_owner'],'api_boundary':native['api_boundary'],'native_dependencies_text':native['native_dependencies'],'evidence':{'path':'contracts/adapters/catalog.v1.json','pointer':f'/adapters/{index}','sha256_lf':digest},'runtime_state':'NOT_RUN'})
   with self.subTest(component=cid):self.reject_mutation(mutate)


class PlacementParentRepairTests(unittest.TestCase):
 package_copy=PortableTests.package_copy
 reject_mutation=RelationRepairTests.reject_mutation
 def test_cp001_policy_claims(self):
  for mutation in ('reported','placement','owner','authorized','bool_type'):
   def mutate(rows):
    entry=rows[0]['native_placement_evidence'][0]
    if mutation in ('reported','placement'):entry['placement']='privileged omnibus container'
    if mutation in ('reported','owner'):entry['owner_role']='unrelated owner'
    if mutation in ('reported','authorized'):entry['deployment_authorized']=True
    if mutation=='bool_type':entry['deployment_authorized']=0
   with self.subTest(mutation=mutation):self.reject_mutation(mutate)
 def test_cp027_child_and_workflow_identity(self):
  for mutation in ('reported','child','workflow','duplicate_workflow','basis'):
   def mutate(rows):
    entry=rows[26]['explicit_native_parent_support'][0]
    self.assertEqual(entry['evidence']['pointer'],'/components/28/native_parent')
    if mutation in ('reported','child'):entry['child_component_id']='CP058'
    if mutation in ('reported','workflow'):entry['workflow_ids']=['I01']
    if mutation=='duplicate_workflow':entry['workflow_ids'].append(entry['workflow_ids'][0])
    if mutation=='basis':entry['basis']='DIRECT_CONSUMER'
   with self.subTest(mutation=mutation):self.reject_mutation(mutate)
 def test_placement_and_parent_completeness(self):
  for field in ('native_placement_evidence','explicit_native_parent_support'):
   for mutation in ('all','one','duplicate','context','pointer','path','type'):
    def mutate(rows,field=field,mutation=mutation):
     owner=next(row for row in rows if row[field]);entries=owner[field]
     if mutation=='all':
      for row in rows:row[field]=[]
     elif mutation=='one':entries.pop()
     elif mutation=='duplicate':entries.append(entries[0])
     elif mutation=='context':
      target=next(row for row in rows if not row[field]);target[field].append(entries.pop())
     elif mutation=='pointer':
      entries[0]['evidence']['pointer']=('/placements/00' if field=='native_placement_evidence' else '/components/028/native_parent')
     elif mutation=='path':entries[0]['evidence']['path']='backlog/issues.json'
     else:owner[field]={}
    with self.subTest(field=field,mutation=mutation):self.reject_mutation(mutate)
 def test_all_five_relation_context_and_pointer_consistency(self):
  for field in ('direct_source_named_consumers','engineering_prerequisite_edges','authoritative_native_roles','native_placement_evidence','explicit_native_parent_support'):
   for mutation in ('context','pointer'):
    def mutate(rows,field=field,mutation=mutation):
     owner=next(row for row in rows if row[field]);entry=owner[field][0]
     if mutation=='context':
      next(row for row in rows if row is not owner)[field].append(owner[field].pop(0))
     else:
      evidence=entry['evidence'][0]['evidence'] if field=='direct_source_named_consumers' else entry['evidence']
      evidence['pointer']=evidence['pointer']+'/invalid'
    with self.subTest(field=field,mutation=mutation):
     # Malformed pointers may raise a typed lookup error at the API boundary.
     with self.assertRaises((ValueError,KeyError,TypeError,IndexError)):
      # reject_mutation itself expects ValueError, so use the same fixture directly.
      source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
      with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
       root=Path(directory);self.package_copy(root);path=root/'component-curation.json'
       doc=json.loads(path.read_text());mutate(doc['components']);path.write_text(json.dumps(doc));v.validate(source,root)
 def test_relation_labels_cannot_promote_claims(self):
  for field,key,value in (
   ('direct_source_named_consumers','basis','NATIVE_OWNER'),
   ('direct_source_named_consumers','runtime_state','PASS'),
   ('direct_source_named_consumers','consumer_confirmation','CONFIRMED'),
   ('engineering_prerequisite_edges','basis','DIRECT_CONSUMER'),
   ('engineering_prerequisite_edges','not_automatically_a_direct_consumer',False),
   ('authoritative_native_roles','runtime_state','PASS')):
   def mutate(rows,field=field,key=key,value=value):
    next(entry for row in rows for entry in row[field])[key]=value
   with self.subTest(field=field,key=key):self.reject_mutation(mutate)
 def test_pinned_native_positive_controls(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  doc=json.loads((v.PACKAGE/'component-curation.json').read_text());rows=doc['components']
  placement=rows[0]['native_placement_evidence'][0]
  self.assertEqual(placement['placement'],'supported firmware-native services')
  self.assertEqual(placement['owner_role'],'I05/I07 component owners')
  self.assertIs(placement['deployment_authorized'],False)
  parent=rows[26]['explicit_native_parent_support'][0]
  self.assertEqual(parent['child_component_id'],'CP029')
  self.assertEqual(set(parent['workflow_ids']),{'C06','C12','C47','I15','V03','V06'})
  self.assertEqual(v.validate(source)['status'],'SOURCE_EVIDENCE_VALID')

class ArtifactIntegrityTests(unittest.TestCase):
 def artifact_fixture(self,root):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  manifest=json.loads((v.PACKAGE/'portable-manifest.json').read_text())
  for entry in manifest['artifacts']:
   relative=entry['path'];target=root/relative;target.parent.mkdir(parents=True,exist_ok=True)
   origin=v.PACKAGE/Path(relative).name if relative.startswith('docs/traceability/curation-public/') else source/relative
   shutil.copyfile(origin,target)
  (root/'portable-manifest.json').write_text(json.dumps(manifest))
  return manifest
 def test_final_artifacts_positive_and_crlf(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   root=Path(directory);manifest=self.artifact_fixture(root)
   self.assertEqual(v.verify_artifacts(root,root)['artifacts'],9)
   for entry in manifest['artifacts']:
    path=root/entry['path'];path.write_bytes(path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
   self.assertEqual(v.verify_artifacts(root,root)['status'],'ARTIFACT_INTEGRITY_VALID')
 def test_stale_hash_size_duplicate_omission_and_self_listing(self):
  for mutation in ('hash','size','duplicate','omitted','self','data','bool_size'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);manifest=self.artifact_fixture(root);entries=manifest['artifacts']
    if mutation=='hash':entries[0]['sha256']='0'*64
    elif mutation=='size':entries[0]['bytes']+=1
    elif mutation=='duplicate':entries[-1]=entries[0].copy()
    elif mutation=='omitted':entries.pop()
    elif mutation=='self':entries[0]['path']='docs/traceability/curation-public/portable-manifest.json'
    elif mutation=='bool_size':entries[0]['bytes']=True
    else:
     path=root/entries[0]['path'];path.write_bytes(path.read_bytes()+b' ')
    (root/'portable-manifest.json').write_text(json.dumps(manifest))
    with self.assertRaises(ValueError):v.verify_artifacts(root,root)

class NativeParentNullTests(unittest.TestCase):
 def source_root(self):
  return Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
 def test_pinned_null_no_association_positive(self):
  source=self.source_root()
  registry=json.loads((source/'reference/components/component_registry.json').read_text())['components']
  nulls=[child for child in registry if 'native_parent' in child and child['native_parent'] is None]
  self.assertEqual(len(nulls),138)
  rows=json.loads((v.PACKAGE/'component-curation.json').read_text())['components']
  supported={entry['child_component_id'] for row in rows for entry in row['explicit_native_parent_support']}
  self.assertTrue(supported.isdisjoint(child['component_id'] for child in nulls))
  self.assertEqual(v.validate(source)['status'],'SOURCE_EVIDENCE_VALID')
 def test_all_nine_pinned_nonnull_bindings_positive(self):
  source=self.source_root();registry_path='reference/components/component_registry.json'
  registry=json.loads((source/registry_path).read_text())['components']
  expected={'CP029':'PostgreSQL','CP064':'Asterisk','CP065':'Asterisk','CP067':'Asterisk','CP068':'Pipecat','CP069':'Pipecat','CP070':'Pipecat','CP071':'Pipecat','CP078':'FFmpeg'}
  self.assertEqual({child['component_id']:child['native_parent'] for child in registry if child.get('native_parent') is not None},expected)
  rows=json.loads((v.PACKAGE/'component-curation.json').read_text())['components'];by_id={row['component_id']:row for row in rows}
  entries=[(row,entry) for row in rows for entry in row['explicit_native_parent_support']]
  self.assertEqual(len(entries),9)
  self.assertEqual({entry['child_component_id'] for row,entry in entries},set(expected))
  for row,entry in entries:
   cid=entry['child_component_id'];index=next(i for i,child in enumerate(registry) if child['component_id']==cid)
   with self.subTest(child=cid):
    self.assertEqual(row['canonical_name'],expected[cid])
    self.assertEqual(entry['evidence']['path'],registry_path)
    self.assertEqual(entry['evidence']['pointer'],f'/components/{index}/native_parent')
    self.assertEqual(entry['evidence']['quote'],expected[cid])
    self.assertEqual(set(entry['workflow_ids']),{relation['workflow_id'] for relation in by_id[cid]['direct_source_named_consumers']})
  self.assertEqual(v.validate(source)['status'],'SOURCE_EVIDENCE_VALID')
 def synthetic_registry(self,mutate):
  # In-memory source mutation with matching pins and citation hashes; no disk source edits.
  import hashlib
  source=self.source_root();registry_path='reference/components/component_registry.json'
  original_raw=v.raw
  registry=json.loads(original_raw(source,registry_path));mutate(registry['components'])
  data=json.dumps(registry).encode();digest=hashlib.sha256(data).hexdigest()
  manifest=json.loads(original_raw(v.PACKAGE,'source-manifest.json'))
  pin=next(item for item in manifest['sources'] if item['path']==registry_path)
  old_digest=pin['sha256_lf'];pin['sha256_lf']=digest
  curation=original_raw(v.PACKAGE,'component-curation.json').replace(old_digest.encode(),digest.encode())
  def fixture_raw(root,relative):
   if Path(root)==source and relative==registry_path:return data
   if Path(root)==v.PACKAGE and relative=='source-manifest.json':return json.dumps(manifest).encode()
   if Path(root)==v.PACKAGE and relative=='component-curation.json':return curation
   return original_raw(root,relative)
  return patch.object(v,'raw',side_effect=fixture_raw)
 def test_synthetic_absent_no_association_positive(self):
  def mutate(children):
   for child in children:
    if child.get('native_parent') is None:child.pop('native_parent',None)
  with self.synthetic_registry(mutate):
   self.assertEqual(v.validate(self.source_root())['status'],'SOURCE_EVIDENCE_VALID')
 def test_synthetic_malformed_nonnull_rejected(self):
  # Replace both a null record and a meaningful binding to catch silent skipping.
  for cid in ('CP001','CP029'):
   for value in (False,True,0,1,1.5,[],['PostgreSQL'],{},'','Unknown','PostgreSQL/Asterisk','postgresql'):
    def mutate(children,cid=cid,value=value):
     next(child for child in children if child['component_id']==cid)['native_parent']=value
    with self.subTest(child=cid,value=value),self.synthetic_registry(mutate):
     with self.assertRaises(ValueError):v.validate(self.source_root())

class Review03RegressionTests(unittest.TestCase):
 def cli_fixture(self,root):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  manifest=json.loads((v.PACKAGE/'portable-manifest.json').read_text())
  for entry in manifest['artifacts']:
   relative=entry['path'];target=root/relative;target.parent.mkdir(parents=True,exist_ok=True)
   origin=v.PACKAGE/Path(relative).name if relative.startswith('docs/traceability/curation-public/') else source/relative
   shutil.copyfile(origin,target)
  package=root/'docs/traceability/curation-public'
  shutil.copyfile(v.PACKAGE/'portable-manifest.json',package/'portable-manifest.json')
  return source,package
 def run_cli(self,source,package):
  import subprocess,sys
  command=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])
  return subprocess.run(command+[str(package/'validate_portable.py'),'--source-root',str(source)],capture_output=True,text=True,timeout=30)
 def test_cli_staged_package_positive(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   source,package=self.cli_fixture(Path(directory));result=self.run_cli(source,package)
   self.assertEqual(result.returncode,0,result.stdout+result.stderr)
   self.assertEqual(json.loads(result.stdout)['status'],'SOURCE_EVIDENCE_VALID')
 def test_cli_stale_staged_artifact_rejected(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   source,package=self.cli_fixture(Path(directory));path=package/'summary.json'
   path.write_bytes(path.read_bytes()+b' ');result=self.run_cli(source,package)
   self.assertEqual(result.returncode,2,result.stdout+result.stderr)
   self.assertEqual(json.loads(result.stdout)['status'],'INVALID_SOURCE_EVIDENCE')
 def test_cli_missing_manifest_rejected(self):
  with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
   source,package=self.cli_fixture(Path(directory));(package/'portable-manifest.json').unlink()
   result=self.run_cli(source,package);self.assertEqual(result.returncode,2,result.stdout+result.stderr)
 def test_historical_private_inventory_reinjection_rejected(self):
  source=Path(os.environ.get('CURATION_SOURCE_ROOT',str(v.PACKAGE.parents[2])))
  for field in ('source_contract_path','original_parent_path','audit_path'):
   with tempfile.TemporaryDirectory(dir=v.PACKAGE) as directory:
    root=Path(directory);PortableTests().package_copy(root)
    path=root/'review-dispositions.json';doc=json.loads(path.read_text())
    doc['technical_amendments'][0]['prior_proposal']['parent_plans'][0][field]='private-workspace/review-jobs/private-document.json'
    path.write_text(json.dumps(doc))
    with self.subTest(field=field),self.assertRaises(ValueError):v.validate(source,root)
 def test_recursive_inventory_guard_and_public_citations(self):
  for value in ('C:/private/document.json','/home/private/document.json','workstream_workflows/private/document.json'):
   with self.subTest(value=value),self.assertRaises(ValueError):v.guard_public_inventory({'history':[{'nested':value}]})
  v.guard_public_inventory({'path':'reference/workflows/C01.json','pointer':'/software','absent':[None,'']})

if __name__=='__main__':unittest.main(verbosity=2)

