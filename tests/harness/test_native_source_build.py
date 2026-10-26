"""Synthetic source-contract regressions; no downloaded build/native code runs."""
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import ci_evidence as c
import native_source_build as s


class SourceContractTests(unittest.TestCase):
    def test_selected_lock_and_hold_authorization_are_exact(self):
        lock=s.source_lock();auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        self.assertEqual(lock['distribution_version'],'0.9.0-1ubuntu0.3')
        self.assertEqual(len(lock['patches']),2);self.assertEqual(len(lock['artifacts']),16)
        self.assertEqual(auth['status'],'HOLD_UNAPPROVED');self.assertIsNone(auth['binary'])
        self.assertIsNone(auth['toolchain']);self.assertIsNone(auth['build_adapter'])
        self.assertEqual(lock['patches'][0]['sha256'],'ba0f6263ea685a7d4f28ddb4638f80e4408e72e9e4be1dbbcee36c9edc45bc20')
        self.assertEqual(lock['patches'][1]['sha256'],'6c7e503d19445cc7583da2de020fd84648acfad4feefb69a219af88259e0199d')

    def test_hold_never_reaches_fetch_build_or_native_execution(self):
        lock=s.source_lock();auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        with patch.object(s,'fetch_inputs',side_effect=AssertionError('no download')) as fetch, \
             patch.object(s,'validate_fingerprints',side_effect=AssertionError('no build preparation')) as prepare, \
             patch.object(c,'capture_namespace_process',side_effect=AssertionError('no process')) as process:
            with self.assertRaisesRegex(s.QualificationHold,'^BUILD_INVENTORY_REQUIRED$'):
                s.build_gate(lock,auth)
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve()
                self.assertEqual(s.own_root(root),root)
                with self.assertRaisesRegex(s.QualificationHold,'^BUILD_INVENTORY_REQUIRED$'):
                    s.build_unapproved(root,lock,auth)
                self.assertEqual(list(root.iterdir()),[])
            fetch.assert_not_called();prepare.assert_not_called();process.assert_not_called()
        with self.assertRaises(s.QualificationHold):s.authorized_runtime({},auth,b'',[])

    def test_explicit_jammy_mode_keeps_legacy_platform_contract(self):
        s.validate_platform('ubuntu','22.04','x86_64','Linux')
        with self.assertRaises(ValueError):s.validate_platform('ubuntu','24.04','x86_64','Linux')
        with self.assertRaises(ValueError):s.validate_platform('ubuntu','22.04','aarch64','Linux')
        c.validate_native_platform('ubuntu','24.04','x86_64','Linux')
        with self.assertRaises(ValueError):c.validate_native_platform('ubuntu','22.04','x86_64','Linux')

    def test_source_or_authorization_byte_mutation_rejected(self):
        auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'auth.json';auth['status']='ROOT_AUTHORIZED_EXACT_BUILD'
            path.write_bytes(s.canonical(auth))
            with self.assertRaises(ValueError):s.read_json(path,c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        with self.assertRaises(ValueError):s.hex64('a'*64+'\n')
        with self.assertRaises(ValueError):s.integer(True,8192)

    def test_no_generated_result_can_self_authorize(self):
        auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        fake={'schema':'f07-unapproved-native-build-v1','variant':s.VARIANT,'binary':{'sha256':'a'*64,'bytes':1}}
        with self.assertRaises(s.QualificationHold):s.authorized_runtime(fake,auth,b's',[])
        auth['status']='ROOT_AUTHORIZED_EXACT_BUILD';auth['root_authorization_receipt']='synthetic-root-ref'
        auth['result_sha256']='b'*64
        with self.assertRaises(ValueError):s.authorized_runtime(fake,auth,b's',[])

    def test_next_inventory_facts_gate_before_adapter_use(self):
        lock=s.source_lock();auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        auth['build_admitted']=True
        with self.assertRaises(s.QualificationHold):s.build_gate(lock,auth)
        auth.update(toolchain=[{}],build_adapter={})
        with self.assertRaises(s.QualificationHold):s.build_gate(lock,auth)

    def patch_spec(self,name,old,new):
        raw=('--- a/'+name+'\n+++ b/'+name+'\n@@ -1 +1 @@\n-'+old+'\n+'+new+'\n').encode()
        return raw,dict(bytes=len(raw),sha256=s.digest(raw),modified_files=[name])

    def test_exact_two_patch_order_and_no_reapplication(self):
        p1,a=self.patch_spec('bubblewrap.c','old','new')
        p2,b=self.patch_spec('tests/test-run.sh','base','patched')
        files={'bubblewrap.c':b'old\n','tests/test-run.sh':b'base\n'}
        out=s.patched_files(files,[p1,p2],[a,b])
        self.assertEqual(out['bubblewrap.c'],b'new\n');self.assertEqual(out['tests/test-run.sh'],b'patched\n')
        self.assertEqual(files['bubblewrap.c'],b'old\n')
        with self.assertRaises(ValueError):s.exact_patch(out,p1,a)
        with self.assertRaises(ValueError):s.patched_files(files,[p1],[a])
        with self.assertRaises(ValueError):s.patched_files(files,[p2,p1],[a,b])

    def test_patch_fuzz_offset_reverse_hash_and_target_reject(self):
        raw,spec=self.patch_spec('bubblewrap.c','old','new')
        for files in ({'bubblewrap.c':b'prefix\nold\n'},{'bubblewrap.c':b'new\n'},{'bubblewrap.c':b'OLD\n'}):
            with self.assertRaises(ValueError):s.exact_patch(files,raw,spec)
        with self.assertRaises(ValueError):s.exact_patch({'bubblewrap.c':b'old\n'},raw+b'extra',spec)
        bad=dict(spec,modified_files=['tests/test-run.sh'])
        with self.assertRaises(ValueError):s.exact_patch({'bubblewrap.c':b'old\n'},raw,bad)
        for name in ('../escape','/escape','a/../../escape','a\\escape','a//escape'):
            with self.assertRaises(ValueError):s.relative(name)

    def tar_bytes(self,name='file.txt',kind=tarfile.REGTYPE,link=''):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            info=tarfile.TarInfo(name);info.type=kind;info.linkname=link;info.size=1 if kind==tarfile.REGTYPE else 0
            archive.addfile(info,io.BytesIO(b's') if info.size else None)
        return stream.getvalue()

    def test_archive_hashlisted_members_and_safe_regular_extraction(self):
        rows,data=s.archive_rows(self.tar_bytes(),'tar')
        s.validate_rows(rows,copy.deepcopy(rows))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();s.extract_checked(rows,data,root,rows)
            self.assertEqual((root/'file.txt').read_bytes(),b's')
        changed=copy.deepcopy(rows);changed[0]['sha256']='a'*64
        with self.assertRaises(ValueError):s.validate_rows(rows,changed)
        changed=copy.deepcopy(rows);changed[0]['bytes']=True
        with self.assertRaises(ValueError):s.validate_rows(changed,changed)

    def test_archive_traversal_hardlinks_special_and_escape_links_reject(self):
        for name,kind,link in (('../escape',tarfile.REGTYPE,''),('file',tarfile.LNKTYPE,'target'),
                               ('file',tarfile.FIFOTYPE,''),('file',tarfile.CHRTYPE,'')):
            with self.subTest(name=name,kind=kind),self.assertRaises(ValueError):s.archive_rows(self.tar_bytes(name,kind,link),'tar')
        rows,data=s.archive_rows(self.tar_bytes('link',tarfile.SYMTYPE,'../escape'),'tar')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with self.assertRaises(ValueError):s.extract_checked(rows,data,root,rows)
            self.assertEqual(list(root.iterdir()),[])
        with self.assertRaises(ValueError):s.normalized_member('./'*500+'file')

    def test_only_reviewed_relative_development_link_rewrite(self):
        rows=[dict(name='lib/real.so',type='file',bytes=1,sha256=s.digest(b's'),link=''),
              dict(name='usr/lib/link.so',type='symlink',bytes=0,sha256=None,link='/lib/real.so')]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with self.assertRaises(ValueError):s.extract_checked(rows,{'lib/real.so':b's'},root,rows)
            s.extract_checked(rows,{'lib/real.so':b's'},root,rows,rewrites={'usr/lib/link.so':'../../lib/real.so'})
            self.assertEqual((root/'usr/lib/link.so').read_bytes(),b's')

    def test_partial_private_cleanup_model_rejects_unknown_links_and_oversize(self):
        model={'data':dict(type='file',bytes=7,sha256=s.digest(b's'*7))}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();path=root/'data';path.write_bytes(b'')
            s.validate_private_tree(root,model,complete=False)
            with self.assertRaises(ValueError):s.validate_private_tree(root,model,complete=True)
            path.write_bytes(b's'*8)
            with self.assertRaises(ValueError):s.validate_private_tree(root,model,complete=False)
            path.unlink();(root/'unknown').write_bytes(b'')
            with self.assertRaises(ValueError):s.validate_private_tree(root,model,complete=False)

    def elf(self,glibc='GLIBC_2.35',now=True,stack=True):
        raw=bytearray(2048);ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
        struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,ident,3,62,1,0,64,0,0,64,56,5,0,0,0)
        interp=b'/lib64/ld-linux-x86-64.so.2\0';raw[512:512+len(interp)]=interp
        strings=b'\0libcap.so.2\0libselinux.so.1\0'+glibc.encode()+b'\0';raw[1100:1100+len(strings)]=strings
        ph=[(1,4,0,0x400000,0,2048,2048,4096),(3,4,512,0x400200,0,len(interp),len(interp),1),
            (2,4,768,0x400300,0,144,144,8),(0x6474e551,6 if stack else 7,0,0,0,0,0,16),(0x6474e552,4,0,0,0,0,0,1)]
        for i,p in enumerate(ph):struct.pack_into('<IIQQQQQQ',raw,64+i*56,*p)
        tags=[(1,strings.index(b'libcap')),(1,strings.index(b'libselinux')),(5,0x400000+1100),(10,len(strings)),
              (0x6ffffffb,0x8000000|(1 if now else 0)),(0x6ffffffe,0x400000+1400),(0x6fffffff,1),(0,0)]
        for i,p in enumerate(tags):struct.pack_into('<qQ',raw,768+i*16,*p)
        struct.pack_into('<HHIII',raw,1400,1,1,0,16,0)
        struct.pack_into('<IHHII',raw,1416,0,0,0,strings.index(glibc.encode()),0)
        return bytes(raw)

    def test_static_elf_pie_bindnow_selinux_and_jammy_versions(self):
        report=s.elf_report(self.elf());self.assertTrue(report['pie']);self.assertTrue(report['bind_now'])
        self.assertTrue(report['nonexec_stack']);self.assertIn('libselinux.so.1',report['needed'])
        for raw in (self.elf('GLIBC_2.38'),self.elf(now=False),self.elf(stack=False),b'not ELF'):
            with self.assertRaises(ValueError):s.elf_report(raw)

    def test_readonly_inventory_has_fixed_paths_and_never_calls_tools(self):
        with patch.object(s,'read_file',return_value=b's'), \
             patch('platform.freedesktop_os_release',return_value={'ID':'ubuntu','VERSION_ID':'22.04'}), \
             patch('platform.machine',return_value='x86_64'), \
             patch.object(c,'capture_namespace_process',side_effect=AssertionError('no subprocess')):
            doc=s.inventory()
        self.assertEqual(doc['native_execution'],'NOT_RUN')
        self.assertEqual([x['candidate'] for x in doc['tools']],list(s.TOOL_CANDIDATES))
        self.assertNotIn('environment',doc)


    def test_source_bootstrap_hold_writes_no_build_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with patch('platform.freedesktop_os_release',return_value={'ID':'ubuntu','VERSION_ID':'22.04'}), \
                 patch('platform.machine',return_value='x86_64'),patch('platform.system',return_value='Linux'), \
                 patch.object(s,'fetch_inputs',side_effect=AssertionError('no network')), \
                 patch.object(c,'capture_namespace_process',side_effect=AssertionError('no downloaded-code execution')):
                with self.assertRaises(s.QualificationHold):s.source_bootstrap(root,c.SOURCE_BUILD_AUTHORIZATION_SHA256)
            self.assertEqual(list(root.iterdir()),[])

    def test_debian_ar_inventory_is_data_only_and_bounded(self):
        def member(name,data):
            header=(name+'/').ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'100644'.ljust(8)+str(len(data)).ljust(10)+'`\n'
            return header.encode()+data+(b'\n' if len(data)%2 else b'')
        raw=b'!<arch>\n'+member('debian-binary',b'2.0\n')+member('control.tar.xz',b'synthetic-control')+member('data.tar.zst',b'synthetic-data')
        report=s.deb_data_inventory(raw)
        self.assertEqual(report['data_member'],'data.tar.zst');self.assertIsNone(report['decoded_members'])
        self.assertEqual(report['disposition'],'ROOT_PINNED_DATA_DECODER_REQUIRED')
        for bad in (b'',raw+b'x',raw.replace(b'data.tar.zst',b'evil.tar.zst')):
            with self.assertRaises(ValueError):s.deb_data_inventory(bad)

    def test_zip_special_members_and_private_tree_links_reject(self):
        import zipfile
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            info=zipfile.ZipInfo('fifo');info.create_system=3;info.external_attr=(stat.S_IFIFO|0o600)<<16
            archive.writestr(info,b'')
        with self.assertRaises(ValueError):s.archive_rows(stream.getvalue(),'wheel')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'link').symlink_to('../escape')
            model={'link':dict(type='symlink',link='../escape',bytes=0,sha256=None)}
            with self.assertRaises(ValueError):s.validate_private_tree(root,model)

    def test_separately_reviewed_fixture_requires_exact_binary_result_and_closure(self):
        # Pure synthetic authorization logic; no real lock is activated and the
        # ELF fixture is never executed or treated as a real root build receipt.
        binary=self.elf();report=s.elf_report(binary)
        auth=s.authorization(c.SOURCE_BUILD_AUTHORIZATION_SHA256)
        auth.update(status='ROOT_AUTHORIZED_EXACT_BUILD',build_admitted=True,root_authorization_receipt='synthetic-reviewed-fixture',
                    builder_sha256=s.digest(s.read_file(Path(s.__file__))),toolchain=[],
                    binary=dict(bytes=len(binary),sha256=s.digest(binary)),elf=report,
                    runtime_closure=[dict(path='runtime/lib/synthetic.so',bytes=1,sha256=s.digest(b's'))],
                    loader=dict(path='/lib64/ld-linux-x86-64.so.2',bytes=1,sha256=s.digest(b's')))
        result=dict(schema='f07-unapproved-native-build-v1',variant=s.VARIANT,source_lock_sha256=s.SOURCE_LOCK_SHA256,
                    builder_sha256=auth['builder_sha256'],toolchain_sha256=s.digest(s.canonical([])),
                    binary=auth['binary'],elf=report,runtime_closure=auth['runtime_closure'])
        auth['result_sha256']=s.digest(s.canonical(result))
        with patch.object(s,'validate_fingerprints',return_value=None):
            self.assertEqual(s.authorized_runtime(result,auth,binary,auth['runtime_closure']),auth['binary'])
            with self.assertRaises(ValueError):s.authorized_runtime(result,auth,binary[:-1]+b'x',auth['runtime_closure'])
            with self.assertRaises(ValueError):s.authorized_runtime(result,auth,binary,[])
            changed=dict(result,source_lock_sha256='a'*64)
            with self.assertRaises(ValueError):s.authorized_runtime(changed,auth,binary,auth['runtime_closure'])

class SourceInterfaceRegressionTests(unittest.TestCase):
    def _tar(self,files):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            for name,raw in files.items():
                info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
        return out.getvalue()

    def _fixture(self,series=None,preimage=b'old\n',patch_mutation=False,missing=False,reverse=False):
        specs=[];patches=[]
        for name,old,new in (('first.patch','old','middle'),('second.patch','middle','final')):
            raw=('--- a/bubblewrap.c\n+++ b/bubblewrap.c\n@@ -1 +1 @@\n-'+old+'\n+'+new+'\n').encode()
            specs.append(dict(series_entry=name,member='debian/patches/'+name,bytes=len(raw),sha256=s.digest(raw),modified_files=['bubblewrap.c']))
            patches.append(raw)
        original={'bubblewrap-0.9.0/bubblewrap.c':preimage,'bubblewrap-0.9.0/tests/retained.sh':b'not executed\n'}
        debian={'debian/patches/series':b'first.patch\nsecond.patch\n' if series is None else series,
                specs[0]['member']:patches[0],specs[1]['member']:patches[1]}
        if patch_mutation:debian[specs[0]['member']]=patches[0].replace(b'+middle',b'+MIDDLE')
        if missing:del debian[specs[1]['member']]
        if reverse:specs.reverse()
        blobs={'orig.tar':self._tar(original),'debian.tar':self._tar(debian)}
        artifacts=[dict(name=name,kind=kind,bytes=len(blobs[name]),sha256=s.digest(blobs[name]),members=None)
                   for name,kind in (('orig.tar','orig'),('debian.tar','debian'))]
        return dict(artifacts=artifacts,patches=specs,limits=dict(download_total=sum(map(len,blobs.values())))),blobs

    def _inventory(self,lock,blobs):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for name,raw in blobs.items():(root/name).write_bytes(raw)
            before={p.name:p.read_bytes() for p in root.iterdir()}
            # Only the trust anchor is replaced by an explicit synthetic fixture.
            # Real no-follow reads, archive parser, series/hash checks and exact
            # applicator run; no source code from the archive is imported.
            with patch.object(s,'source_lock',return_value=lock), \
                 patch.object(s,'fetch_inputs',side_effect=AssertionError('no network')) as fetch, \
                 patch.object(c,'capture_namespace_process',side_effect=AssertionError('no native process')) as process:
                report=s.inventory_artifacts(root)
                fetch.assert_not_called();process.assert_not_called()
            self.assertEqual({p.name:p.read_bytes() for p in root.iterdir()},before)
            return report

    def test_authenticated_inventory_emits_exact_once_pre_post_facts_without_execution(self):
        lock,blobs=self._fixture();report=self._inventory(lock,blobs);facts=report['source_patch_facts']
        original={'bubblewrap.c':b'old\n','tests/retained.sh':b'not executed\n'}
        patched=dict(original,**{'bubblewrap.c':b'final\n'})
        self.assertEqual(facts['pre_tree_sha256'],s.tree_digest(original))
        self.assertEqual(facts['post_tree_sha256'],s.tree_digest(patched))
        self.assertEqual(facts['modified_files'],{'bubblewrap.c':dict(pre_bytes=4,pre_sha256=s.digest(b'old\n'),post_bytes=6,post_sha256=s.digest(b'final\n'))})
        self.assertEqual([x['sha256'] for x in facts['patches']],[x['sha256'] for x in lock['patches']])
        self.assertEqual(facts['series_sha256'],s.digest(b'first.patch\nsecond.patch\n'))
        self.assertEqual(facts['file_count'],2);self.assertEqual(len(report['source_inputs']),2)
        for key in ('build','native_execution','third_party_code_execution'):self.assertEqual(report[key],'NOT_RUN')
        self.assertEqual(report['authorization'],'NOT_GRANTED');self.assertLessEqual(len(s.canonical(report)),1048576)

    def test_authenticated_inventory_rejects_wrong_series_order_options_and_extra_patch(self):
        for series in (b'second.patch\nfirst.patch\n',b'first.patch -p0\nsecond.patch\n',
                       b'first.patch\nsecond.patch\nthird.patch\n',b'# comment\nfirst.patch\nsecond.patch\n',b'first.patch\r\nsecond.patch\r\n'):
            with self.subTest(series=series),self.assertRaises(ValueError):self._inventory(*self._fixture(series=series))

    def test_authenticated_inventory_rejects_patch_member_mutation_missing_and_wrong_order(self):
        for kwargs in (dict(patch_mutation=True),dict(missing=True),dict(reverse=True)):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self._inventory(*self._fixture(**kwargs))

    def test_authenticated_inventory_rejects_fuzz_offset_reverse_and_reapplication(self):
        for preimage in (b'prefix\nold\n',b'OLD\n',b'middle\n',b'final\n'):
            with self.subTest(preimage=preimage),self.assertRaises(ValueError):self._inventory(*self._fixture(preimage=preimage))

    def test_authenticated_inventory_rejects_wrong_raw_artifact_hash_and_missing_source(self):
        lock,blobs=self._fixture();blobs['orig.tar']=blobs['orig.tar']+b'x'
        with self.assertRaises(ValueError):self._inventory(lock,blobs)
        lock,blobs=self._fixture();lock['artifacts']=lock['artifacts'][1:]
        with self.assertRaises(ValueError):self._inventory(lock,blobs)

    def test_authenticated_inventory_rejects_wrong_pinned_members_and_source_symlink(self):
        lock,blobs=self._fixture();lock['artifacts'][0]['members']=[]
        with self.assertRaises(ValueError):self._inventory(lock,blobs)
        lock,blobs=self._fixture();out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            info=tarfile.TarInfo('bubblewrap-0.9.0/bubblewrap.c');info.type=tarfile.SYMTYPE;info.linkname='elsewhere';archive.addfile(info)
        blobs['orig.tar']=out.getvalue();lock['artifacts'][0].update(bytes=len(blobs['orig.tar']),sha256=s.digest(blobs['orig.tar']))
        with self.assertRaises(ValueError):self._inventory(lock,blobs)

    def _graph(self,links=None):
        model={'a':dict(type='directory'),'z':dict(type='directory'),
               'outside':dict(type='file',bytes=1,sha256=s.digest(b's'))}
        for name,target in (links or {'a/b':'../z','x':'a/b/../../outside'}).items():model[name]=dict(type='symlink',link=target)
        return model

    def _rows(self,model):
        return [dict(name=name,type=spec['type'],bytes=spec.get('bytes',0),sha256=spec.get('sha256'),link=spec.get('link','')) for name,spec in model.items()]

    def test_exact_reviewed_chained_escape_rejects_before_any_extraction_write(self):
        rows=self._rows(self._graph())
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with self.assertRaises(ValueError):s.extract_checked(rows,{'outside':b's'},root,rows)
            self.assertEqual(list(root.iterdir()),[])

    def test_exact_reviewed_chained_escape_private_tree_rejects_without_host_reads(self):
        model=self._graph()
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp).resolve();root=parent/'owned';root.mkdir();(parent/'outside').write_bytes(b'preserve')
            (root/'a').mkdir();(root/'z').mkdir();(root/'outside').write_bytes(b's')
            (root/'a/b').symlink_to('../z');(root/'x').symlink_to('a/b/../../outside')
            for complete in (False,True):
                with self.assertRaises(ValueError):s.validate_private_tree(root,model,complete=complete)
            self.assertEqual((parent/'outside').read_bytes(),b'preserve')

    def test_link_cycles_dangling_absolute_and_non_directory_traversals_reject(self):
        cases=({'x':'x'},{'x':'y','y':'x'},{'x':'missing'},{'x':'/outside'},
               {'x':'../outside'},{'x':'outside/../outside'},{'x':'a/missing/../outside'},
               {'x':'a/'+'x'*241},{'x':'a//z'},{'x':'a/./z'})
        for links in cases:
            with self.subTest(links=links),self.assertRaises(ValueError):s.validate_link_model(self._graph(links))

    def test_symlink_or_regular_member_ancestor_rejects_before_writes(self):
        for kind in ('symlink','file'):
            model=self._graph({'x':'z'})
            model['x']=dict(type='symlink',link='z') if kind=='symlink' else dict(type='file',bytes=1,sha256=s.digest(b's'))
            model['x/child']=dict(type='file',bytes=1,sha256=s.digest(b's'));rows=self._rows(model)
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve()
                with self.assertRaises(ValueError):s.extract_checked(rows,{'outside':b's','x':b's','x/child':b's'},root,rows)
                self.assertEqual(list(root.iterdir()),[])

    def test_valid_internal_chain_resolves_and_complete_tree_is_accepted(self):
        model=self._graph({'a/b':'../z','x':'a/b/../outside','y':'x'})
        self.assertEqual(s.validate_link_model(model),{'a/b':'z','x':'outside','y':'outside'})
        rows=self._rows(model)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();s.extract_checked(rows,{'outside':b's'},root,rows)
            s.validate_private_tree(root,model,complete=True)
            self.assertEqual((root/'y').read_bytes(),b's')

    def test_three_reviewed_development_rewrites_remain_internal(self):
        rewrites=s.source_lock()['symlink_rewrites'];rows=[];data={}
        for name,target in rewrites.items():
            destination='lib/x86_64-linux-gnu/'+target.rsplit('/',1)[1]
            rows.append(dict(name=destination,type='file',bytes=1,sha256=s.digest(b's'),link=''));data[destination]=b's'
            rows.append(dict(name=name,type='symlink',bytes=0,sha256=None,link='/'+destination))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();s.extract_checked(rows,data,root,rows,rewrites=rewrites)
            for name in rewrites:self.assertEqual((root/name).read_bytes(),b's')

    def test_graph_count_size_hop_and_special_type_bounds_reject(self):
        bad=self._graph({'x':'outside'});bad['outside']['bytes']=s.MAX_FILE+1
        with self.assertRaises(ValueError):s.validate_link_model(bad)
        bad=self._graph({'x':'outside'});bad['outside']['type']='fifo'
        with self.assertRaises(ValueError):s.validate_link_model(bad)
        bad={str(i):dict(type='directory') for i in range(s.MAX_ENTRIES+1)}
        with self.assertRaises(ValueError):s.validate_link_model(bad)
        bad=self._graph({**{'l'+str(i):'l'+str(i+1) for i in range(41)},'l41':'outside'})
        with self.assertRaises(ValueError):s.validate_link_model(bad)


if __name__=='__main__':unittest.main()
