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

if __name__=='__main__':unittest.main(verbosity=2)

