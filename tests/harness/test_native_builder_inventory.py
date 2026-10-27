"""Synthetic private-filesystem inventory regressions; no host tools run."""
import copy
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import native_builder_inventory as n


class PublicBuilderInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.checkout=self.base/'checkout';self.public=self.base/'public'
        self.checkout.mkdir();self.public.mkdir()
        self.values=dict(GITHUB_REPOSITORY=n.REPOSITORY,GITHUB_SHA='a'*40,F07_CANDIDATE_SHA='b'*40,F07_TASK='F07',
            GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB=n.JOB,RUNNER_OS='Linux',RUNNER_ARCH='X64',ImageOS='ubuntu22',ImageVersion='20261027.1.0')
        self.put(self.checkout/'.git/HEAD',b'a'*40+b'\n')
        self.put(self.checkout/n.SOURCES[0],b'synthetic workflow\n');self.put(self.checkout/n.SOURCES[1],b'synthetic reviewed inventory\n')
        # Public locked repository data, copied into the synthetic checkout.
        for name in n.LOCK_HASHES:self.put(self.checkout/name,(Path(__file__).parent/Path(name).name).read_bytes())
        self.put(self.public/'etc/os-release',b'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="public fixture"\n')
        self.put(self.public/'usr/bin/gcc-11',b'bytes only, never executable')

    def put(self,path,raw):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)

    def files(self):return n.FixedFiles(self.public)

    def document(self):return n.inventory(self.values,self.checkout,self.files())

    def root(self):return self.base/'f07-builder-inventory-123-1'

    def test_fixed_public_inventory_is_closed_and_not_build_or_metadata_authority(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('no tool')),patch.object(os,'system',side_effect=AssertionError('no command')):
            doc=self.document()
        self.assertEqual(doc['context']['tested_git_sha'],'a'*40);self.assertEqual(doc['context']['pr_candidate_sha'],'b'*40)
        self.assertEqual(doc['disposition'],'HOLD_INVENTORY_ONLY_NOT_AUTHORITY')
        self.assertEqual(doc['metadata_get'],'NOT_RUN_ROOT_READBACK_REQUIRED')
        self.assertEqual(doc['full_toolchain_and_elf_runtime_closure'],'NOT_QUALIFIED')
        observed=next(x for x in doc['files'] if x['path']=='/usr/bin/gcc-11')
        self.assertEqual(observed['sha256'],n.sha(b'bytes only, never executable'))
        self.assertNotIn(str(self.base),n.canonical(doc).decode());self.assertNotIn('PRETTY_NAME',n.canonical(doc).decode())

    def test_direct_missing_candidates_are_explicit_not_found_and_not_guessed(self):
        doc=self.document();missing=next(x for x in doc['files'] if x['path']=='/usr/bin/gcc-12')
        self.assertEqual(missing,dict(path='/usr/bin/gcc-12',status='NOT_FOUND',resolved=None,bytes=None,sha256=None,mode=None,links=[]))
        self.assertEqual([x['path'] for x in doc['files']],list(n.FILES))

    def test_known_relative_and_absolute_symlink_closure_is_typed(self):
        (self.public/'usr/bin/gcc').symlink_to('gcc-11')
        (self.public/'usr/bin/cc').symlink_to('/usr/bin/gcc')
        files=self.files();fact=files.file('/usr/bin/cc');files.verify()
        self.assertEqual(fact['resolved'],'/usr/bin/gcc-11')
        self.assertEqual([x['path'] for x in fact['links']],['/usr/bin/cc','/usr/bin/gcc'])
        self.assertEqual(files.public['/usr/bin/cc']['target'],'/usr/bin/gcc')

    def test_allowlisted_directory_alias_keeps_optional_missing_leaf_not_found(self):
        (self.public/'usr/lib').mkdir();(self.public/'lib').symlink_to('usr/lib')
        fact=self.files().file('/lib/x86_64-linux-gnu/libc-2.35.so')
        self.assertEqual(fact['status'],'NOT_FOUND');self.assertEqual(fact['links'][0]['target'],'/usr/lib')

    def test_symlink_unknown_private_escape_and_dangling_targets_reject(self):
        link=self.public/'usr/bin/gcc'
        for target in ('/home/private/secret','/etc/shadow','../../../usr/bin/gcc-11','unknown','/usr/bin/gcc-12','./gcc-11','gcc-11\nTOKEN'):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc')
                link.unlink()

    def test_symlink_cycle_and_file_as_intermediate_directory_reject(self):
        (self.public/'usr/bin/gcc').symlink_to('cc');(self.public/'usr/bin/cc').symlink_to('gcc')
        with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc')
        (self.public/'usr/bin/gcc').unlink();(self.public/'usr/bin/cc').unlink()
        (self.public/'usr/bin/gcc').symlink_to('gcc-11/../gcc-11')
        with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc')

    def test_normalized_variants_and_unrelated_paths_never_read(self):
        for name in ('/usr/bin/../bin/gcc-11','/usr/bin//gcc-11','usr/bin/gcc-11','/etc/passwd','/proc/self/environ','/usr/bin/gcc-11/','/home/runner/.ssh/id_rsa'):
            with self.subTest(name=name),self.assertRaises(n.InventoryHold):self.files().file(name)

    def test_hardlink_special_fifo_directory_and_per_file_size_reject_without_blocking(self):
        target=self.public/'usr/bin/gcc-11';os.link(target,self.public/'usr/bin/other')
        with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')
        (self.public/'usr/bin/other').unlink();target.unlink();os.mkfifo(target)
        with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')
        target.unlink();target.mkdir()
        with self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')
        target.rmdir();target.write_bytes(b'1234')
        with patch.object(n,'MAX_FILE',4):self.assertEqual(self.files().file('/usr/bin/gcc-11')['bytes'],4)
        with patch.object(n,'MAX_FILE',3),self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')

    def test_aggregate_size_boundary_and_symlink_cache_do_not_rehash_arbitrarily(self):
        target=self.public/'usr/bin/gcc-11';target.write_bytes(b'1234')
        (self.public/'usr/bin/gcc').symlink_to('gcc-11')
        with patch.object(n,'MAX_BYTES',4):
            files=self.files();files.file('/usr/bin/gcc-11');files.file('/usr/bin/gcc');self.assertEqual(files.total,4)
        with patch.object(n,'MAX_BYTES',3),self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')

    def test_read_mutation_symlink_mutation_and_missing_to_present_all_fail_closed(self):
        files=self.files();files.file('/usr/bin/gcc-11');(self.public/'usr/bin/gcc-11').write_bytes(b'changed')
        with self.assertRaises(n.InventoryHold):files.verify()
        link=self.public/'usr/bin/gcc';link.symlink_to('gcc-11');files=self.files();files.file('/usr/bin/gcc');link.unlink();link.symlink_to('gcc-12')
        with self.assertRaises(n.InventoryHold):files.verify()
        files=self.files();self.assertEqual(files.file('/usr/bin/gcc-12')['status'],'NOT_FOUND');self.put(self.public/'usr/bin/gcc-12',b'new')
        with self.assertRaises(n.InventoryHold):files.verify()

    def test_changed_during_stream_read_rejects_before_a_fact_is_returned(self):
        target=self.public/'usr/bin/gcc-11';original=n.os.fstat;calls=0
        def changed(descriptor):
            nonlocal calls
            calls+=1
            if calls==2:target.write_bytes(b'changed while open')
            return original(descriptor)
        with patch.object(n.os,'fstat',side_effect=changed),self.assertRaises(n.InventoryHold):self.files().file('/usr/bin/gcc-11')

    def test_closed_context_rejects_unknown_task_platform_revision_and_boolean_ids(self):
        for name,value in (('GITHUB_REPOSITORY','other/repo'),('F07_TASK','F20'),('GITHUB_JOB','other'),('RUNNER_OS','Windows'),('RUNNER_ARCH','ARM64'),('ImageOS','ubuntu24'),('ImageVersion','private/TOKEN'),('GITHUB_SHA','A'*40),('F07_CANDIDATE_SHA','x'),('GITHUB_RUN_ID',True),('GITHUB_RUN_ATTEMPT','01')):
            values=dict(self.values);values[name]=value
            with self.subTest(name=name),self.assertRaises(n.InventoryHold):n.context(values)
        values=dict(self.values,private='TOKEN')
        with self.assertRaises(n.InventoryHold):n.context(values)

    def test_checkout_head_lock_hash_link_and_reference_identity_are_bound(self):
        self.put(self.checkout/'.git/HEAD',b'c'*40+b'\n')
        with self.assertRaises(n.InventoryHold):self.document()
        self.put(self.checkout/'.git/HEAD',b'ref: refs/heads/main\n');self.put(self.checkout/'.git/refs/heads/main',b'a'*40+b'\n')
        self.document()
        self.put(self.checkout/n.SOURCES[3],b'fake authorization')
        with self.assertRaises(n.InventoryHold):self.document()

    def test_malicious_os_fields_are_never_exported_and_unsupported_release_holds(self):
        path=self.public/'etc/os-release';self.put(path,b'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="PRIVATE_TOKEN_NOT_FOR_EXPORT"\n')
        self.assertNotIn('PRIVATE_TOKEN_NOT_FOR_EXPORT',n.canonical(self.document()).decode())
        for raw in (b'ID=ubuntu\nVERSION_ID=24.04\n',b'ID=ubuntu\nID=ubuntu\nVERSION_ID=22.04\n',b'ID="$(secret)"\nVERSION_ID=22.04\n',b'not a key\n',b'ID=ubuntu\nVERSION_ID=22.04\n\xff'):
            self.put(path,raw)
            with self.assertRaises((n.InventoryHold,UnicodeError)):self.document()

    def test_checkout_source_links_size_and_mutation_are_bound_before_publication(self):
        workflow=self.checkout/n.SOURCES[0];workflow.unlink();workflow.symlink_to(self.public/'usr/bin/gcc-11')
        with self.assertRaises(n.InventoryHold):self.document()
        workflow.unlink();workflow.write_bytes(b'synthetic workflow\n')
        with self.assertRaises(n.InventoryHold):n.private_read(workflow,1)
        files=self.files();verify=files.verify
        def changed():
            verify();workflow.write_bytes(b'changed source during inventory')
        with patch.object(files,'verify',side_effect=changed),self.assertRaises(n.InventoryHold):n.inventory(self.values,self.checkout,files)

    def test_closed_document_rejects_unknown_fields_boolean_types_private_paths_and_authority(self):
        doc=self.document()
        for change in ('extra','authority','context','source','file','bool','node'):
            bad=copy.deepcopy(doc)
            if change=='extra':bad['environment']='PRIVATE'
            elif change=='authority':bad['disposition']='QUALIFIED'
            elif change=='context':bad['context']['run_id']=True
            elif change=='source':bad['source_sha256']['/private']='a'*64
            elif change=='file':bad['files'][0]['path']='/etc/shadow'
            elif change=='bool':next(row for row in bad['files'] if row['status']=='OBSERVED')['bytes']=True
            else:bad['closure_nodes'][0]['private']='TOKEN'
            with self.subTest(change=change),self.assertRaises(n.InventoryHold):n.validate_inventory(bad)

    def test_atomic_publication_exact_two_files_size_hash_and_double_publish(self):
        doc=self.document();root=self.root();n.publish(root,self.base,doc)
        self.assertEqual({p.name for p in root.iterdir()},set(n.OUTPUTS))
        inventory=(root/'inventory.json').read_bytes();manifest=json.loads((root/'manifest.json').read_bytes())
        self.assertEqual(manifest['files'],{'inventory.json':dict(bytes=len(inventory),sha256=n.sha(inventory))})
        self.assertLessEqual(sum(p.stat().st_size for p in root.iterdir()),65536)
        self.assertEqual(manifest['artifact_service_metadata'],'NOT_RUN_ROOT_SAME_RUN_READBACK_REQUIRED')
        with self.assertRaises(FileExistsError):n.publish(root,self.base,doc)
        self.assertEqual((root/'inventory.json').read_bytes(),inventory)

    def test_output_root_parent_symlink_wrong_owner_and_replaced_identity_reject(self):
        doc=self.document()
        with self.assertRaises(n.InventoryHold):n.publish(self.base/'wrong-name',self.base,doc)
        alias=self.base/'alias';alias.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(n.InventoryHold):n.publish(alias/self.root().name,alias,doc)
        self.root().mkdir()
        with patch.object(n.os,'getuid',return_value=os.getuid()+1),self.assertRaises(n.InventoryHold):n.root_identity(self.root())
        self.root().rmdir();original=n.root_identity;calls=0
        def replaced(root):
            nonlocal calls
            calls+=1;value=original(root)
            return value if calls==1 else (value[0],value[1]+1,value[2],value[3])
        with patch.object(n,'root_identity',side_effect=replaced),self.assertRaises(n.InventoryHold):n.publish(self.root(),self.base,doc)

    def test_cleanup_validates_all_members_preserves_siblings_and_rejects_unknown_or_link(self):
        root=self.root();doc=self.document();n.publish(root,self.base,doc)
        sibling=self.base/'unrelated';sibling.mkdir();(sibling/'sentinel').write_bytes(b'preserve')
        (root/'unknown').write_bytes(b'unknown')
        with self.assertRaises(n.InventoryHold):n.cleanup(root,self.base,doc['context'])
        self.assertTrue((root/'inventory.json').exists());(root/'unknown').unlink()
        (root/'manifest.json').unlink();(root/'manifest.json').symlink_to(sibling/'sentinel')
        with self.assertRaises(n.InventoryHold):n.cleanup(root,self.base,doc['context'])
        (root/'manifest.json').unlink();n.cleanup(root,self.base,doc['context'])
        self.assertFalse(root.exists());self.assertEqual((sibling/'sentinel').read_bytes(),b'preserve')

    def test_cleanup_owned_atomic_link_pair_and_stream_failure_remain_bounded(self):
        root=self.root();doc=self.document();root.mkdir();temporary=root/n.TEMP_NAMES[0];temporary.write_bytes(b'partial');os.link(temporary,root/n.OUTPUTS[0])
        n.cleanup(root,self.base,doc['context']);self.assertFalse(root.exists())
        with patch.object(n.os,'fsync',side_effect=OSError('SENSITIVE_NOT_FOR_OUTPUT')),self.assertRaises(OSError):n.publish(root,self.base,doc)
        n.cleanup(root,self.base,doc['context']);self.assertFalse(root.exists())

    def test_cli_exception_output_is_fixed_and_never_echoes_sensitive_context(self):
        values=dict(self.values,GITHUB_REPOSITORY='PRIVATE_TOKEN_NOT_FOR_OUTPUT');output=io.StringIO()
        with patch.dict(os.environ,values,clear=True),patch.object(__import__('sys'),'argv',['inventory','inventory','/private/NEVER_ECHO']),patch('sys.stdout',output),self.assertRaises(SystemExit) as exit_status:
            runpy.run_path(n.__file__,run_name='__main__')
        self.assertEqual(exit_status.exception.code,1)
        self.assertNotIn('PRIVATE',output.getvalue());self.assertNotIn('NEVER_ECHO',output.getvalue())
        self.assertEqual(json.loads(output.getvalue()),dict(schema='f07-public-builder-status-v1',status='HOLD',reason='INVENTORY_BOUNDARY_HOLD'))


    def test_diagnostic_exact_exception_classes_never_export_messages_or_errno(self):
        cases=((n.InventoryHold,'GUARD_REJECTED'),(FileNotFoundError,'MISSING'),(PermissionError,'PERMISSION'),(OSError,'OS_ERROR'),(ValueError,'UNKNOWN'))
        for kind,reason in cases:
            def fail():raise kind('PRIVATE_TOKEN\n\x1b[31m/home/private')
            with self.subTest(kind=kind),self.assertRaises(n.DiagnosticHold) as caught:
                n.boundary('public_file',fail,path_id='/usr/bin/gcc-11')
            doc=json.loads(n.diagnostic(caught.exception))
            self.assertEqual(doc,dict(schema='f07-public-builder-diagnostic-v1',status='HOLD',phase='public_file',reason=reason,path_id='/usr/bin/gcc-11'))
            self.assertLessEqual(len(n.diagnostic(caught.exception)),512)
            self.assertNotIn('PRIVATE',n.diagnostic(caught.exception));self.assertNotIn('errno',doc)

    def test_diagnostic_untrusted_attributes_subclasses_and_unknown_values_are_closed(self):
        class Forged(n.DiagnosticHold):pass
        for error in (ValueError('SECRET'*100000),Forged('public_file','MISSING','/usr/bin/gcc-11')):
            self.assertEqual(json.loads(n.diagnostic(error)),dict(schema='f07-public-builder-diagnostic-v1',status='HOLD',phase='unknown',reason='UNKNOWN',path_id=None))
        for phase,reason,path_id in ((True,True,True),('/private','TOKEN','/home/private'),('context\nSECRET','MISSING\x1b','/usr/bin/../private')):
            doc=json.loads(n.diagnostic(n.DiagnosticHold(phase,reason,path_id)))
            self.assertEqual((doc['phase'],doc['reason'],doc['path_id']),('unknown','UNKNOWN',None))
        for phase,path_id in (('private',None),('public_file','/etc/shadow'),(True,None)):
            with self.assertRaises(n.InventoryHold):n.boundary(phase,lambda:None,path_id=path_id)

    def test_nested_diagnostic_preserves_first_phase_and_does_not_run_later_effect(self):
        effects=[]
        def inner():
            n.boundary('release',lambda:n.need(False),path_id='/etc/os-release')
            effects.append('not reached')
        with self.assertRaises(n.DiagnosticHold) as caught:n.boundary('publish',inner)
        self.assertEqual(json.loads(n.diagnostic(caught.exception))['phase'],'release')
        self.assertEqual(effects,[])
        self.assertEqual(n.boundary('document',lambda:'ordinary return'),'ordinary return')

    def test_inventory_diagnostic_reports_actual_synthetic_file_guard_without_accepting_it(self):
        (self.public/'usr/bin/gcc').symlink_to('/home/private/SECRET')
        with self.assertRaises(n.DiagnosticHold) as caught:self.document()
        doc=json.loads(n.diagnostic(caught.exception))
        self.assertEqual((doc['phase'],doc['reason'],doc['path_id']),('public_file','GUARD_REJECTED','/usr/bin/gcc'))
        self.assertNotIn('SECRET',n.diagnostic(caught.exception));self.assertFalse(self.root().exists())
        self.put(self.checkout/'.git/HEAD',b'c'*40+b'\n')
        with self.assertRaises(n.DiagnosticHold) as caught:self.document()
        self.assertEqual(json.loads(n.diagnostic(caught.exception))['phase'],'checkout_before')

    def test_cli_diagnostic_is_separate_closed_stderr_preserving_legacy_stdout(self):
        output=io.StringIO();errors=io.StringIO()
        with patch.dict(os.environ,dict(self.values,GITHUB_REPOSITORY='PRIVATE'),clear=True),patch.object(__import__('sys'),'argv',['inventory','inventory','/private']),patch('sys.stdout',output),patch('sys.stderr',errors),self.assertRaises(SystemExit) as caught:
            runpy.run_path(n.__file__,run_name='__main__')
        self.assertEqual(caught.exception.code,1)
        self.assertEqual(json.loads(output.getvalue()),dict(schema='f07-public-builder-status-v1',status='HOLD',reason='INVENTORY_BOUNDARY_HOLD'))
        self.assertEqual(json.loads(errors.getvalue()),dict(schema='f07-public-builder-diagnostic-v1',status='HOLD',phase='context',reason='GUARD_REJECTED',path_id=None))
        self.assertNotIn('PRIVATE',errors.getvalue());self.assertEqual(len(errors.getvalue().splitlines()),1)


    def test_requested_pkg_config_predicate_diagnostic_keeps_unknown_target_closed(self):
        name='/usr/bin/x86_64-linux-gnu-pkg-config';link=self.public/name.lstrip('/')
        link.symlink_to('/home/private/DO_NOT_EXPORT')
        with patch.object(n.os,'open',side_effect=AssertionError('must not read rejected target')),self.assertRaises(n.DiagnosticHold) as caught:
            n.boundary('public_file',self.files().file,name,path_id=name)
        doc=json.loads(n.diagnostic(caught.exception))
        self.assertEqual(doc,dict(schema='f07-public-builder-diagnostic-v1',status='HOLD',phase='public_file',reason='GUARD_REJECTED',path_id=name,predicate='SYMLINK_TARGET_ALLOWLIST'))
        self.assertNotIn('DO_NOT_EXPORT',n.diagnostic(caught.exception));self.assertNotIn('/home',n.diagnostic(caught.exception))
        self.assertFalse(self.root().exists())

    def test_predicate_codes_distinguish_link_grammar_missing_hops_and_file_type(self):
        name='/usr/bin/x86_64-linux-gnu-pkg-config';link=self.public/name.lstrip('/')
        for target,code in (('./pkg-config','SYMLINK_COMPONENT_GRAMMAR'),('pkgconf','OPTIONAL_MISSING_STABLE'),('x86_64-linux-gnu-pkg-config','SYMLINK_HOP_LIMIT'),('TOKEN\nPRIVATE','SYMLINK_TARGET_TYPE_SIZE_CHARACTERS')):
            link.symlink_to(target)
            with self.subTest(code=code),self.assertRaises(n.DiagnosticHold) as caught:n.boundary('public_file',self.files().file,name,path_id=name)
            self.assertEqual(json.loads(n.diagnostic(caught.exception))['predicate'],code);link.unlink()
        link.mkdir()
        with self.assertRaises(n.DiagnosticHold) as caught:n.boundary('public_file',self.files().file,name,path_id=name)
        self.assertEqual(json.loads(n.diagnostic(caught.exception))['predicate'],'FINAL_REGULAR_SINGLE_LINK')

    def test_predicate_diagnostics_preserve_positive_missing_and_known_alias_facts(self):
        name='/usr/bin/x86_64-linux-gnu-pkg-config';link=self.public/name.lstrip('/')
        self.assertEqual(n.boundary('public_file',self.files().file,name,path_id=name)['status'],'NOT_FOUND')
        self.put(self.public/'usr/bin/pkg-config',b'public fixture only');link.symlink_to('pkg-config')
        files=self.files();fact=n.boundary('public_file',files.file,name,path_id=name);files.verify()
        self.assertEqual(fact['resolved'],'/usr/bin/pkg-config');self.assertEqual(fact['sha256'],n.sha(b'public fixture only'))
        self.assertEqual(n.predicate(True,'REQUEST_ALLOWLIST'),None)

    def test_untrusted_predicate_fields_subclasses_and_nonpublic_phase_never_expand_export(self):
        class Forged(n.PredicateHold):pass
        for error in (n.PredicateHold('PRIVATE'*100000),n.PredicateHold(True),Forged('REQUEST_ALLOWLIST')):
            def fail():raise error
            with self.assertRaises(n.DiagnosticHold) as caught:n.boundary('public_file',fail,path_id='/usr/bin/pkg-config')
            doc=json.loads(n.diagnostic(caught.exception));self.assertNotIn('predicate',doc)
            self.assertEqual(doc['reason'],'UNKNOWN');self.assertLessEqual(len(n.diagnostic(caught.exception)),512)
        for phase in ('context','publish','unknown'):
            error=n.DiagnosticHold(phase,'GUARD_REJECTED','/usr/bin/pkg-config');error.predicate='REQUEST_ALLOWLIST'
            self.assertNotIn('predicate',json.loads(n.diagnostic(error)))
        for bad in (True,'PRIVATE','REQUEST_ALLOWLIST\nTOKEN'):
            with self.assertRaises(n.InventoryHold):n.predicate(False,bad)

    def test_every_closed_predicate_is_bounded_and_nested_failure_keeps_first_code(self):
        for code in n.PREDICATES:
            with self.assertRaises(n.DiagnosticHold) as caught:n.boundary('public_file',lambda:n.predicate(False,code),path_id='/usr/bin/x86_64-linux-gnu-pkg-config')
            raw=n.diagnostic(caught.exception);self.assertEqual(json.loads(raw)['predicate'],code)
            self.assertLessEqual(len(raw.encode('ascii')),512);self.assertEqual(len(raw.splitlines()),1)
        def fail():n.boundary('public_file',lambda:n.predicate(False,'REQUEST_ALLOWLIST'),path_id='/usr/bin/pkg-config')
        with self.assertRaises(n.DiagnosticHold) as caught:n.boundary('publish',fail)
        doc=json.loads(n.diagnostic(caught.exception));self.assertEqual(doc['predicate'],'REQUEST_ALLOWLIST');self.assertEqual(doc['phase'],'public_file')


if __name__=='__main__':unittest.main()
