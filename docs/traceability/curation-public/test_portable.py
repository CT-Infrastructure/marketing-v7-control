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
if __name__=='__main__':unittest.main(verbosity=2)

