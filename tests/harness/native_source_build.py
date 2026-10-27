"""Explicit Jammy source variant. Inventory is not build or runtime authority."""
from __future__ import annotations
import hashlib
import bz2
import gzip
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VARIANT = 'ubuntu-0.9.0-1ubuntu0.3-jammy-source-v1'
SOURCE_LOCK_SHA256 = '6c8be8dc661d54be89d22c72db9b81d187489ea1dde451d6934f7d39746abe83'
MAX_ENTRIES, MAX_FILE, MAX_TOTAL = 8192, 8388608, 134217728
TOOL_CANDIDATES = ('/usr/bin/gcc-11','/usr/bin/as','/usr/bin/ld.bfd','/usr/bin/ninja',
                   '/usr/bin/pkg-config','/usr/bin/python3','/usr/bin/dpkg-deb',
                   '/lib/x86_64-linux-gnu/libc.so.6','/lib64/ld-linux-x86-64.so.2',
                   '/usr/include/stdio.h','/usr/include/linux/version.h',
                   '/usr/lib/x86_64-linux-gnu/crt1.o','/usr/lib/x86_64-linux-gnu/crti.o',
                   '/usr/lib/x86_64-linux-gnu/crtn.o','/usr/lib/x86_64-linux-gnu/libc.so')


class QualificationHold(ValueError):
    pass


def check(value):
    if not value: raise ValueError('invalid source-build contract')


def hold(reason):
    raise QualificationHold(reason)


def canonical(doc):
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def hex64(value):
    check(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None)
    return value


def integer(value, maximum, minimum=0):
    check(type(value) is int and minimum <= value <= maximum)
    return value


def unique(pairs):
    doc={}
    for key,value in pairs:
        check(key not in doc);doc[key]=value
    return doc


def relative(name):
    check(type(name) is str and 0 < len(name) <= 240 and '\\' not in name and ':' not in name)
    check(not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')))
    check(re.fullmatch('[A-Za-z0-9_+.,@%=/ -]+',name) is not None)
    return name


def own_root(root):
    root=Path(root)
    check(root.is_absolute() and root != Path(root.anchor) and root.is_dir() and root.resolve()==root)
    for part in (root,*root.parents): check(not part.is_symlink())
    return root


def read_file(path, maximum=MAX_FILE, deadline=None):
    path=Path(path);info=path.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink() and info.st_size<=maximum)
    descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    chunks=[];size=0
    with os.fdopen(descriptor,'rb') as stream:
        opened=os.fstat(stream.fileno())
        check((opened.st_dev,opened.st_ino,opened.st_size)==(info.st_dev,info.st_ino,info.st_size))
        while True:
            if deadline is not None: check(time.monotonic()<deadline)
            chunk=stream.read(min(65536,maximum-size+1))
            if not chunk: break
            size+=len(chunk);check(size<=maximum);chunks.append(chunk)
    check(size==info.st_size)
    return b''.join(chunks)


def read_json(path, expected, maximum=1048576):
    raw=read_file(path,maximum);check(digest(raw)==hex64(expected))
    doc=json.loads(raw,object_pairs_hook=unique);check(raw==canonical(doc));return doc


def source_lock():
    lock=read_json(ROOT/'tests/harness/native-source-ci.lock.json',SOURCE_LOCK_SHA256)
    check(lock['schema']=='f07-native-source-inputs-v1' and lock['variant']==VARIANT)
    check(lock['distribution_version']=='0.9.0-1ubuntu0.3')
    check(lock['limits']['entries']==MAX_ENTRIES and lock['limits']['file_bytes']==MAX_FILE and lock['limits']['aggregate_bytes']==MAX_TOTAL)
    check(len(lock['patches'])==2 and len(lock['artifacts'])==16)
    names=set();total=0
    for item in lock['artifacts']:
        check('/' not in relative(item['name']) and item['name'] not in names);names.add(item['name'])
        integer(item['bytes'],MAX_FILE,1);hex64(item['sha256']);total+=item['bytes']
        check(item['url'].startswith(('https://archive.ubuntu.com/ubuntu/pool/','https://files.pythonhosted.org/packages/')))
        check(item['url'].split('/')[-1]==item['name'])
    check(total<=lock['limits']['download_total'])
    return lock


def authorization(expected):
    doc=read_json(ROOT/'tests/harness/native-build-authorization.lock.json',expected)
    check(set(doc)=={'schema','variant','status','build_admitted','source_lock_sha256','toolchain','build_adapter',
                     'result_sha256','binary','elf','runtime_closure','loader','builder_sha256','root_authorization_receipt'})
    check(doc['schema']=='f07-native-build-authorization-v1' and doc['variant']==VARIANT)
    check(doc['source_lock_sha256']==SOURCE_LOCK_SHA256 and type(doc['build_admitted']) is bool)
    check(doc['status'] in ('HOLD_UNAPPROVED','ROOT_AUTHORIZED_EXACT_BUILD'))
    if doc['status']=='HOLD_UNAPPROVED': check(doc['binary'] is None and doc['result_sha256'] is None)
    else:
        check(doc['build_admitted'] and all(doc[k] is not None for k in ('toolchain','build_adapter','result_sha256','binary','elf','runtime_closure','loader','builder_sha256','root_authorization_receipt')))
        hex64(doc['result_sha256']);hex64(doc['builder_sha256'])
    return doc


def build_gate(lock, auth):
    if not auth['build_admitted']: hold('BUILD_INVENTORY_REQUIRED')
    if auth['toolchain'] is None or auth['build_adapter'] is None: hold('TOOLCHAIN_ADAPTER_INVENTORY_REQUIRED')
    if any(a['members'] is None for a in lock['artifacts'] if a['kind']!='provenance'):
        hold('ARCHIVE_MEMBER_INVENTORY_REQUIRED')
    if any(a.get('decoded_tar') is None for a in lock['artifacts'] if a['kind']=='deb'):
        hold('DEB_DATA_DECODER_INVENTORY_REQUIRED')
    if auth['runtime_closure'] is None or lock.get('runtime_map') is None: hold('PRIVATE_RUNTIME_CLOSURE_INVENTORY_REQUIRED')
    if lock['patched_tree_sha256'] is None or lock['generated_output_model'] is None:
        hold('PATCHED_TREE_OUTPUT_MODEL_REQUIRED')
    hex64(lock['patched_tree_sha256'])
    expected_source_identity(lock)
    expected_debian_input_identity(lock)


def validate_platform(os_id, version, machine, system):
    check((os_id,version,machine,system)==('ubuntu','22.04','x86_64','Linux'))


def inventory():
    # Fixed public tool candidates only. No PATH lookup, executable invocation,
    # environment dump, source import, configure, network or namespace operation.
    import platform
    release=platform.freedesktop_os_release()
    results=[];deadline=time.monotonic()+30
    for name in TOOL_CANDIDATES:
        try:
            path=Path(name).resolve();check(path.is_relative_to('/usr') or path.is_relative_to('/lib'))
            raw=read_file(path,67108864,deadline)
            results.append(dict(candidate=name,available=True,bytes=len(raw),sha256=digest(raw)))
        except (OSError,ValueError): results.append(dict(candidate=name,available=False,bytes=None,sha256=None))
    return dict(schema='f07-source-readonly-inventory-v1',variant=VARIANT,
        os_id=release.get('ID') if release.get('ID') in ('ubuntu','debian') else 'OTHER',
        os_version=release.get('VERSION_ID') if release.get('VERSION_ID') in ('22.04','24.04') else 'OTHER',
        architecture='x86_64' if platform.machine()=='x86_64' else 'OTHER',tools=results,
        build_adapter='NOT_INVENTORIED',compiler_closure='NOT_INVENTORIED',
        source_member_hashes='NOT_INVENTORIED',native_execution='NOT_RUN')


def normalized_member(name):
    check(type(name) is str and len(name)<=242)
    while name.startswith('./'): name=name[2:]
    return relative(name.rstrip('/'))


def local_pax_mtime(payload):
    # Inspect the raw self-counted record, not tarfile's merged metadata dict.
    check(type(payload) is bytes and 0<len(payload)<=64)
    match=re.fullmatch(rb'([1-9][0-9]{0,2}) mtime=((?:0|[1-9][0-9]{0,11})\.[0-9]{1,9})\n',payload)
    check(match is not None and int(match[1])==len(payload))
    check(int(match[2].split(b'.')[0])<=253402300799)
    return match[2].decode('ascii')


def raw_tar_headers(raw, deadline):
    # A separate bounded raw pass must precede effective TarInfo acceptance.
    # Only one LOCAL x header / one mtime record may bind the next member.
    source=io.BytesIO(raw)
    if raw.startswith(b'\xfd7zXZ\x00'):stream=lzma.LZMAFile(source)
    elif raw.startswith(b'\x1f\x8b'):stream=gzip.GzipFile(fileobj=source)
    elif raw.startswith(b'BZh'):stream=bz2.BZ2File(source)
    else:stream=source
    decoded=0;total=0;headers=[];pending=None;offset=0;pax_count=0
    def read(size):
        nonlocal decoded
        check(time.monotonic()<deadline and 0<size<=65536)
        value=stream.read(size);decoded+=len(value)
        check(decoded<=MAX_TOTAL+MAX_ENTRIES*2048+10240)
        return value
    with stream:
        while True:
            block=read(512);check(len(block)==512)
            if block==bytes(512):
                check(pending is None)
                trailer=read(512);check(trailer==bytes(512));padding=1024
                while True:
                    trailer=read(512)
                    if not trailer:break
                    padding+=len(trailer);check(len(trailer)==512 and not any(trailer) and padding<=10752)
                break
            try:info=tarfile.TarInfo.frombuf(block,'utf-8','strict')
            except (tarfile.HeaderError,UnicodeError) as exc:raise ValueError('invalid raw tar header') from exc
            size=integer(info.size,MAX_FILE)
            check(info.type in (tarfile.REGTYPE,tarfile.DIRTYPE,tarfile.SYMTYPE,tarfile.XHDTYPE))
            if info.type==tarfile.XHDTYPE:
                check(pending is None and 0<size<=64);pax_count+=1;check(pax_count<=MAX_ENTRIES)
                payload=read(size);check(len(payload)==size)
                pending=dict(mtime=local_pax_mtime(payload),header_offset=offset,payload_sha256=digest(payload))
            else:
                check(len(headers)<MAX_ENTRIES)
                check(info.type==tarfile.REGTYPE or size==0)
                total+=size;check(total<=MAX_TOTAL)
                attributes={k:getattr(info,k) for k in ('name','linkname','size','type','mode','uid','gid','uname','gname','devmajor','devminor')}
                headers.append(dict(attributes=attributes,pax={} if pending is None else {'mtime':pending['mtime']},
                                    header_offset=offset,local_pax=pending,mtime=info.mtime))
                pending=None;remaining=size
                while remaining:
                    chunk=read(min(65536,remaining));check(bool(chunk));remaining-=len(chunk)
            pad=(-size)%512
            if pad:padding=read(pad);check(len(padding)==pad and not any(padding))
            offset+=512+size+pad
    return headers


def archive_rows(raw, kind, deadline=None):
    # Data only, bounded in decoded bytes/count. .deb decoded sidecars require
    # separate root-pinned parent linkage; no dpkg/control/maintainer execution.
    check(type(raw) is bytes and len(raw)<=MAX_FILE)
    deadline=time.monotonic()+15 if deadline is None else deadline
    rows=[];data={};total=0
    if kind=='wheel':
        end=raw.rfind(b'PK\x05\x06',max(0,len(raw)-65557))
        check(end>=0 and end+22<=len(raw))
        disk,cdisk,local_count,count,cdsize,cdoff,comment=struct.unpack_from('<HHHHIIH',raw,end+4)
        check(disk==cdisk==0 and local_count==count and count<=MAX_ENTRIES and count!=65535)
        check(end+22+comment==len(raw) and cdoff+cdsize==end)
        cursor=cdoff;seen=0
        while cursor<end:
            check(cursor+46<=end and raw[cursor:cursor+4]==b'PK\x01\x02')
            name_size,extra_size,comment_size=struct.unpack_from('<HHH',raw,cursor+28)
            cursor+=46+name_size+extra_size+comment_size;seen+=1
            check(cursor<=end and seen<=MAX_ENTRIES)
        check(seen==count)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                check(time.monotonic()<deadline)
                name=normalized_member(info.filename)
                mode=stat.S_IFMT(info.external_attr>>16)
                check(not info.flag_bits&1 and mode in (0,stat.S_IFREG,stat.S_IFDIR))
                size=integer(info.file_size,MAX_FILE);total+=size;check(total<=MAX_TOTAL)
                value=b'' if info.is_dir() else archive.read(info)
                rows.append(dict(name=name,type='directory' if info.is_dir() else 'file',bytes=size,sha256=None if info.is_dir() else digest(value),link=''))
                if not info.is_dir(): data[name]=value
                check(len(rows)<=MAX_ENTRIES)
    else:
        headers=raw_tar_headers(raw,deadline);index=0
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*') as archive:
            for info in archive:
                check(time.monotonic()<deadline)
                check(index<len(headers));header=headers[index];index+=1
                check(all(getattr(info,k)==v for k,v in header['attributes'].items()))
                check(info.pax_headers==header['pax'])
                check(info.mtime==(header['mtime'] if not header['pax'] else float(header['pax']['mtime'])))
                if info.name in ('.','./'): continue
                name=normalized_member(info.name);size=integer(info.size,MAX_FILE)
                check(info.type in (tarfile.REGTYPE,tarfile.DIRTYPE,tarfile.SYMTYPE))
                total+=size;check(total<=MAX_TOTAL)
                value=b''
                if info.isfile():
                    stream=archive.extractfile(info);check(stream is not None)
                    with stream: value=stream.read(size+1)
                    check(len(value)==size);data[name]=value
                rows.append(dict(name=name,type='file' if info.isfile() else 'directory' if info.isdir() else 'symlink',
                                 bytes=size,sha256=digest(value) if info.isfile() else None,link=info.linkname))
                check(len(rows)<=MAX_ENTRIES)
        check(index==len(headers))
    check(len({r['name'] for r in rows})==len(rows))
    return rows,data


def validate_rows(rows, expected):
    check(type(rows) is list and type(expected) is list and len(rows)<=MAX_ENTRIES)
    check(canonical(rows)==canonical(expected))
    for row in rows:
        relative(row['name']);integer(row['bytes'],MAX_FILE)
        check(set(row)=={'name','type','bytes','sha256','link'} and row['type'] in ('file','directory','symlink'))
        if row['type']=='file': hex64(row['sha256']);check(row['link']=='')
        if row['type']=='directory': check(row['bytes']==0 and row['sha256'] is None and row['link']=='')
        if row['type']=='symlink': check(row['bytes']==0 and row['sha256'] is None)
    check(sum(r['bytes'] for r in rows)<=MAX_TOTAL)


def safe_link(name,target):
    relative(name);check(type(target) is str and not target.startswith('/') and '\\' not in target and ':' not in target)
    parts=list(PurePosixPath(name).parent.parts)
    for part in target.split('/'):
        if part=='..': check(bool(parts));parts.pop()
        else: check(part not in ('','.'));parts.append(part)
    check(bool(parts));return '/'.join(parts)


def validate_link_model(model):
    # Resolve authenticated model data only, never host paths. Implicit parents
    # are directories; explicit files/links cannot be member ancestors.
    check(type(model) is dict and len(model)<=MAX_ENTRIES)
    nodes={};total=0
    for name,spec in model.items():
        relative(name);check(type(spec) is dict and spec['type'] in ('file','directory','symlink'))
        nodes[name]=spec
        if spec['type']=='file':
            total+=integer(spec['bytes'],MAX_FILE);hex64(spec['sha256'])
        else:
            check(integer(spec.get('bytes',0),MAX_FILE)==0 and spec.get('sha256') is None)
        if spec['type']=='symlink':
            target=spec['link']
            check(type(target) is str and 0<len(target)<=240 and not target.startswith('/'))
            check(re.fullmatch('[A-Za-z0-9_+.,@%=/ -]+',target) is not None)
            check(all(p not in ('','.') for p in target.split('/')))
        check(total<=MAX_TOTAL)
    for name in model:
        parts=name.split('/')
        for i in range(1,len(parts)):
            parent='/'.join(parts[:i])
            if parent in nodes:check(nodes[parent]['type']=='directory')
            else:
                nodes[parent]=dict(type='directory');check(len(nodes)<=MAX_ENTRIES)
    check(len(nodes)<=MAX_ENTRIES)
    resolved={}
    for name,spec in model.items():
        if spec['type']!='symlink':continue
        parts=name.split('/')[:-1];todo=spec['link'].split('/');hops=0;steps=0
        while todo:
            steps+=1;check(steps<=MAX_ENTRIES*4)
            part=todo.pop(0)
            if part=='..':check(bool(parts));parts.pop();continue
            current='/'.join(parts+[part]);check(current in nodes)
            node=nodes[current]
            if node['type']=='symlink':
                hops+=1;check(hops<=40)
                todo=node['link'].split('/')+todo
            else:
                parts.append(part)
                if todo:check(node['type']=='directory')
        destination='/'.join(parts);check(destination in nodes)
        resolved[name]=destination
    return resolved


def extract_checked(rows, data, root, expected, selected=None, rewrites=None):
    validate_rows(rows,expected);root=own_root(root);check(not list(root.iterdir()))
    rewrites={} if rewrites is None else rewrites
    chosen={r['name'] for r in rows} if selected is None else set(selected)
    check(chosen <= {r['name'] for r in rows})
    model={r['name']:dict(r,link=rewrites.get(r['name'],r['link'])) for r in rows if r['name'] in chosen}
    check(set(rewrites)<=chosen and all(model[n]['type']=='symlink' for n in rewrites))
    validate_link_model(model)
    # Validate the whole link graph and all content before any write.
    for row in rows:
        if row['type']=='file': check(digest(data[row['name']])==row['sha256'] and len(data[row['name']])==row['bytes'])
    for row in rows:
        if row['name'] not in chosen or row['type']=='symlink': continue
        path=root/row['name'];path.parent.mkdir(parents=True,exist_ok=True)
        if row['type']=='directory': path.mkdir(exist_ok=True)
        else:
            with path.open('xb') as stream: check(stream.write(data[row['name']])==row['bytes'])
            path.chmod(0o644)
    for row in rows:
        if row['name'] in chosen and row['type']=='symlink':
            path=root/row['name'];path.parent.mkdir(parents=True,exist_ok=True)
            path.symlink_to(rewrites.get(row['name'],row['link']))


def exact_patch(files, raw, spec):
    check(type(raw) is bytes and len(raw)==spec['bytes'] and digest(raw)==spec['sha256'] and b'\r' not in raw)
    lines=raw.decode('utf-8').splitlines(keepends=True);result=dict(files);changed=[];index=0
    while index<len(lines):
        if not lines[index].startswith('--- a/'):
            index+=1;continue
        name=lines[index][6:].rstrip('\n');relative(name)
        check(name in spec['modified_files'] and name not in changed and name in files)
        check(index+1<len(lines) and lines[index+1]=='+++ b/'+name+'\n');index+=2
        old=files[name].decode('utf-8').splitlines(keepends=True);out=[];cursor=0;hunks=0
        while index<len(lines) and lines[index].startswith('@@ '):
            match=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n',lines[index]);check(match is not None)
            start,oldcount,newstart,newcount=int(match[1])-1,int(match[2] or 1),int(match[3])-1,int(match[4] or 1)
            check(cursor<=start<=len(old));out+=old[cursor:start];check(len(out)==newstart)
            cursor=start;removed=added=0;index+=1
            while index<len(lines) and lines[index][:1] in (' ','+','-') and not lines[index].startswith('--- a/'):
                marker,value=lines[index][0],lines[index][1:]
                if marker in (' ','-'):
                    check(cursor<len(old) and old[cursor]==value);cursor+=1;removed+=1
                if marker in (' ','+'): out.append(value);added+=1
                index+=1
            check((removed,added)==(oldcount,newcount));hunks+=1
        check(hunks>0);out+=old[cursor:];result[name]=''.join(out).encode('utf-8');changed.append(name)
    check(set(changed)==set(spec['modified_files']))
    return result


def patched_files(files, patches, specs):
    check(len(patches)==len(specs)==2)
    result=dict(files)
    for raw,spec in zip(patches,specs): result=exact_patch(result,raw,spec)
    return result


def source_patch_facts(original, debian, specs):
    check(type(original) is dict and type(debian) is dict and len(specs)==2)
    check(0<len(original)<=MAX_ENTRIES and len(debian)<=MAX_ENTRIES)
    for files in (original,debian):
        total=0
        for name,raw in files.items():
            relative(name);check(type(raw) is bytes);integer(len(raw),MAX_FILE)
            total+=len(raw);check(total<=MAX_TOTAL)
    check('debian/patches/series' in debian)
    entries=[p['series_entry'] for p in specs]
    check(len(set(entries))==2)
    for entry,spec in zip(entries,specs):
        relative(entry);check(spec['member']=='debian/patches/'+entry)
    # No comments/options/whitespace/order changes or additional patch.
    series=debian['debian/patches/series']
    check(series==('\n'.join(entries)+'\n').encode('utf-8'))
    patches=[];identities=[]
    for spec in specs:
        check(spec['member'] in debian)
        raw=debian[spec['member']]
        check(len(raw)==integer(spec['bytes'],MAX_FILE) and digest(raw)==hex64(spec['sha256']))
        patches.append(raw)
        identities.append(dict(member=spec['member'],series_entry=spec['series_entry'],bytes=len(raw),sha256=digest(raw),
                               modified_files=list(spec['modified_files'])))
    patched=patched_files(original,patches,specs)
    check(len(patched)==len(original) and sum(len(v) for v in patched.values())<=MAX_TOTAL)
    for value in patched.values():integer(len(value),MAX_FILE)
    modified=sorted({name for spec in specs for name in spec['modified_files']})
    facts=dict(schema='f07-source-patch-facts-v1',patches=identities,series_sha256=digest(series),
               pre_tree_sha256=tree_digest(original),post_tree_sha256=tree_digest(patched),file_count=len(patched),
               modified_files={name:dict(pre_bytes=len(original[name]),pre_sha256=digest(original[name]),
                   post_bytes=len(patched[name]),post_sha256=digest(patched[name])) for name in modified},
               application='EXACT_ORDER_ONCE_NO_FUZZ_OFFSET_REVERSE',authorization='NOT_GRANTED',build='NOT_RUN',native_execution='NOT_RUN')
    check(len(canonical(facts))<=65536)
    return patched,facts


def tree_digest(files):
    return digest(canonical({relative(name):digest(value) for name,value in sorted(files.items())}))


def debian_input_model(rows, specs, data=None):
    """Authenticated metadata only; packaging aliases are never staged/run."""
    validate_rows(rows,rows);members={row['name']:dict(row) for row in rows}
    check(len(members)==len(rows) and bool(members))
    check(all(name=='debian' or name.startswith('debian/') for name in members))
    resolved=validate_link_model(members)
    for destination in resolved.values():check(destination in members and members[destination]['type']=='file')
    check(len(specs)==2)
    series='debian/patches/series';entries=[spec['series_entry'] for spec in specs]
    check(len(set(entries))==2)
    expected=('\n'.join(entries)+'\n').encode('utf-8')
    required={series:dict(bytes=len(expected),sha256=digest(expected))}
    for spec in specs:
        check(spec['member']=='debian/patches/'+relative(spec['series_entry']))
        required[relative(spec['member'])]=dict(bytes=integer(spec['bytes'],MAX_FILE),sha256=hex64(spec['sha256']))
    check(len(required)==3)
    for name,identity in required.items():
        check(name in members and members[name]['type']=='file')
        check(members[name]['bytes']==identity['bytes'] and members[name]['sha256']==identity['sha256'])
    if data is not None:
        check(type(data) is dict and set(data)=={name for name,row in members.items() if row['type']=='file'})
        for name,raw in data.items():
            check(type(raw) is bytes and len(raw)==members[name]['bytes'] and digest(raw)==members[name]['sha256'])
    return dict(schema='f07-debian-input-model-v1',source_lock_sha256=SOURCE_LOCK_SHA256,
                members=[members[name] for name in sorted(members)])


def expected_debian_input_identity(lock):
    items=[item for item in lock['artifacts'] if item['kind']=='debian'];check(len(items)==1)
    if items[0]['members'] is None:hold('DEBIAN_INPUT_MODEL_INVENTORY_REQUIRED')
    return digest(canonical(debian_input_model(items[0]['members'],lock['patches'])))


def validate_input_model_result(result, lock):
    check(result['debian_input_model_sha256']==expected_debian_input_identity(lock))


def typed_source_model(rows):
    """All authenticated orig members, stripped once; no file alias expansion."""
    validate_rows(rows,rows);prefix='bubblewrap-0.9.0/';members={};root_member=None
    for row in rows:
        if row['name']==prefix[:-1]:
            check(root_member is None and row['type']=='directory');root_member=dict(row);continue
        check(row['name'].startswith(prefix));name=relative(row['name'][len(prefix):])
        check(name not in members);members[name]=dict(row,name=name)
    check(bool(members))
    resolved=validate_link_model(members)
    # Source aliases are terminal FILE aliases only; no directory compatibility.
    for name,destination in resolved.items():check(destination in members and members[destination]['type']=='file')
    return dict(schema='f07-typed-source-model-v1',source_lock_sha256=SOURCE_LOCK_SHA256,
                root_member=root_member,members=[members[name] for name in sorted(members)])


def post_source_identity(original_model, regular_post_tree_sha256):
    """Additive identity; tree_digest/patched_tree_sha256 stay FILE-ONLY."""
    check(type(original_model) is dict and set(original_model)=={'schema','source_lock_sha256','root_member','members'})
    check(original_model['schema']=='f07-typed-source-model-v1' and original_model['source_lock_sha256']==SOURCE_LOCK_SHA256)
    check(type(original_model['members']) is list and len(original_model['members'])<=MAX_ENTRIES)
    rows=[dict(row,name='bubblewrap-0.9.0/'+relative(row['name'])) for row in original_model['members']]
    if original_model['root_member'] is not None:rows.insert(0,original_model['root_member'])
    check(canonical(typed_source_model(rows))==canonical(original_model))
    return digest(canonical(dict(schema='f07-post-source-identity-v1',source_lock_sha256=SOURCE_LOCK_SHA256,
        original_source_model_sha256=digest(canonical(original_model)),regular_post_tree_sha256=hex64(regular_post_tree_sha256))))


def expected_source_identity(lock):
    # Expected facts come only from the separately hash-pinned ROOT lock model,
    # never a build receipt, observed filesystem or generated inventory output.
    origins=[item for item in lock['artifacts'] if item['kind']=='orig'];check(len(origins)==1)
    if origins[0]['members'] is None or lock['patched_tree_sha256'] is None:hold('TYPED_SOURCE_MODEL_INVENTORY_REQUIRED')
    model=typed_source_model(origins[0]['members'])
    return model,post_source_identity(model,lock['patched_tree_sha256'])


def source_identity_facts(rows, original, patched):
    model=typed_source_model(rows);members={r['name']:r for r in model['members']}
    regular={name for name,row in members.items() if row['type']=='file'}
    check(set(original)==set(patched)==regular)
    post=[]
    for name,row in members.items():
        item=dict(row)
        if row['type']=='file':
            check(len(original[name])==row['bytes'] and digest(original[name])==row['sha256'])
            item.update(bytes=integer(len(patched[name]),MAX_FILE),sha256=digest(patched[name]))
        post.append(item)
    check(sum(row['bytes'] for row in post)<=MAX_TOTAL)
    after=dict(model,members=post)
    facts=dict(original_source_model=model,post_source_model=after,
        original_source_model_sha256=digest(canonical(model)),post_source_model_sha256=digest(canonical(after)),
        post_source_identity=post_source_identity(model,tree_digest(patched)))
    check(len(canonical(facts))<=1048576)
    return facts


def validate_source_tree(root, lock):
    """Complete lstat/readlink/no-follow binding before AND after build."""
    root=own_root(root);original,expected=expected_source_identity(lock)
    members={row['name']:row for row in original['members']};placement=dict(members)
    for name in members:
        parts=name.split('/')
        for i in range(1,len(parts)):
            parent='/'.join(parts[:i]);placement.setdefault(parent,dict(type='directory'))
            check(len(placement)<=MAX_ENTRIES)
    modified={name for patch in lock['patches'] for name in patch['modified_files']}
    check(modified<={name for name,row in members.items() if row['type']=='file'})
    pending=[root];seen=set();hashes={};post={name:dict(row) for name,row in members.items()};total=0
    while pending:
        directory=pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path=Path(entry.path);name=path.relative_to(root).as_posix();check(name in placement and name not in seen)
                spec=placement[name];info=entry.stat(follow_symlinks=False);seen.add(name)
                if spec['type']=='directory':check(stat.S_ISDIR(info.st_mode));pending.append(path)
                elif spec['type']=='symlink':check(stat.S_ISLNK(info.st_mode) and os.readlink(path)==spec['link'])
                else:
                    check(stat.S_ISREG(info.st_mode) and info.st_nlink==1)
                    value=read_file(path);total+=len(value);check(total<=MAX_TOTAL);hashes[name]=digest(value)
                    if name not in modified:check(len(value)==spec['bytes'] and hashes[name]==spec['sha256'])
                    post[name].update(bytes=len(value),sha256=hashes[name])
                check(len(seen)<=MAX_ENTRIES and len(pending)<=MAX_ENTRIES)
    check(seen==set(placement))
    regular=digest(canonical(dict(sorted(hashes.items()))));check(regular==lock['patched_tree_sha256'])
    after=dict(original,members=[post[name] for name in sorted(post)])
    return dict(source_tree_sha256=regular,post_source_identity=expected,
                original_source_model_sha256=digest(canonical(original)),post_source_model_sha256=digest(canonical(after)))


def validate_source_result(result, lock):
    model,expected=expected_source_identity(lock)
    check(result['source_tree_sha256']==lock['patched_tree_sha256'] and result['post_source_identity']==expected)
    check(result['original_source_model_sha256']==digest(canonical(model)))
    hex64(result['post_source_model_sha256'])


# Root-reviewed expected target policy, not a measurement of an executor.
ELF_PAGE_BYTES=4096


def target_loader_policy():
    return dict(system='Linux',elf='ELF64_LSB',architecture='x86_64',glibc='2.35',
        page_bytes=ELF_PAGE_BYTES,load_bias='PAGE_ALIGNED_REQUIRED',relro_rounding='DOWN_BOTH',
        qualification='EXPECTED_ONLY_NOT_MEASURED')


def require_measured_loader_policy():
    # No measured adapter/loader/page/bias receipt exists in the current closed
    # authorization schema. A future root-reviewed interface must bind it before
    # any build or native launch; parser output cannot self-certify that fact.
    hold('TARGET_LOADER_PAGE_POLICY_NOT_QUALIFIED')


def elf_report(raw):
    check(type(raw) is bytes and 64<=len(raw)<=MAX_FILE and raw[:7]==b'\x7fELF\x02\x01\x01')
    e=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);check(e[2]==62 and e[1]==3 and e[9]==56 and e[10]<=128)
    ph=[]
    for index in range(e[10]):
        offset=e[5]+index*56;check(offset+56<=len(raw));p=struct.unpack_from('<IIQQQQQQ',raw,offset)
        check(p[2]+p[5]<=len(raw));ph.append(p)
    loads=[p for p in ph if p[0]==1]
    check(bool(loads))
    for p in loads:
        check(0<p[6] and p[5]<=p[6] and p[3]+p[6]<2**64 and p[1]&~7==0)
        check(p[7] in (0,1) or (p[7]&(p[7]-1)==0 and p[2]%p[7]==p[3]%p[7]))
    ordered=sorted(loads,key=lambda p:p[3])
    check(all(a[3]+a[6]<=b[3] for a,b in zip(ordered,ordered[1:])))
    page=ELF_PAGE_BYTES
    down=lambda value:value-value%page
    up=lambda value:(value+page-1)//page*page
    # Page aliases, even apparently coherent ones, are outside this supported
    # subset. Byte-disjoint segments may still replace one another's pages.
    for p in loads:
        check(p[2]%page==p[3]%page and up(p[3]+p[6])<2**64)
    check(all(up(a[3]+a[6])<=down(b[3]) for a,b in zip(ordered,ordered[1:])))
    relros=[p for p in ph if p[0]==0x6474e552]
    stacks=[p for p in ph if p[0]==0x6474e551]
    check(len(relros)==len(stacks)==1)
    relro=relros[0];stack=stacks[0]
    check(0<relro[5]<=relro[6] and relro[3]+relro[6]<2**64 and relro[1]==4)
    # The file-backed prefix and full protection range must share one writable
    # load mapping; a header alone is not evidence of protected memory.
    owners=[p for p in loads if p[1]&2 and p[3]<=relro[3] and relro[3]+relro[6]<=p[3]+p[6]
        and relro[3]+relro[5]<=p[3]+p[5] and relro[2]==p[2]+relro[3]-p[3]]
    check(len(owners)==1)
    protected_start=down(relro[3]);protected_end=down(relro[3]+relro[6])
    check(protected_start<protected_end)
    owner=owners[0]
    check(down(owner[3])<=protected_start and protected_end<=up(owner[3]+owner[5]))
    check(stack[1]&~7==0 and not stack[1]&1)
    def mapped(address,size):
        check(0<size and address+size<2**64)
        matches=[p for p in loads if p[3]<=address and address+size<=p[3]+p[5]]
        check(len(matches)==1);p=matches[0];return p[2]+address-p[3]
    vectors=[p for p in ph if p[0]==2];check(len(vectors)==1)
    vector=vectors[0]
    # This supported vector is wholly initialized, not a file-prefix followed
    # by implicit memory zeros. Bind the entire range to the unique LOAD image,
    # rather than trusting a decoy vector selected only by p_offset.
    check(0<vector[5]==vector[6]<=65536 and vector[5]%16==0)
    check(vector[3]+vector[6]<2**64 and vector[2]%8==vector[3]%8==0)
    check(vector[7] in (0,1) or (vector[7]&(vector[7]-1)==0 and vector[2]%vector[7]==vector[3]%vector[7]))
    vector_offset=mapped(vector[3],vector[6]);check(vector_offset==vector[2])
    dynamic={};needed=[];interpreter=None;terminated=False
    for offset in range(vector_offset,vector_offset+vector[5],16):
        tag,value=struct.unpack_from('<qQ',raw,offset)
        if terminated:
            check(tag==value==0);continue
        if tag==0:
            check(value==0);terminated=True;continue
        if tag==1:
            check(value not in needed);needed.append(value)
        else:check(tag not in dynamic);dynamic[tag]=value
    check(terminated)
    for p in ph:
        if p[0]==3:
            check(0<p[5]<=256);value=raw[p[2]:p[2]+p[5]];check(value.endswith(b'\0'));interpreter=value[:-1].decode('ascii')
    check(5 in dynamic and 10 in dynamic and dynamic[10]<=1048576)
    strings=mapped(dynamic[5],dynamic[10]);end=strings+dynamic[10]
    def string(index):
        check(0<=index<dynamic[10]);stop=raw.find(b'\0',strings+index,end);check(stop!=-1)
        return raw[strings+index:stop].decode('ascii')
    # The supported output must declare its GLIBC requirements explicitly.
    # glibc2.35 consumes next pointers until zero, not the count fields alone.
    check(0x6ffffffe in dynamic and 0x6fffffff in dynamic)
    versions=[];claimed=set()
    def version_record(address):
        check(address%4==0)
        off=mapped(address,16);check(off%4==0)
        check(off+16<=vector_offset or vector_offset+vector[5]<=off)
        check(off+16<=strings or end<=off)
        words=set(range(off,off+16,4));check(not claimed.intersection(words))
        claimed.update(words);check(len(claimed)<=4*128*129)
        return off
    def version_link(address,offset):
        check(offset>=16 and offset%4==0 and address+offset<2**64)
        return address+offset
    address=dynamic[0x6ffffffe];count=dynamic[0x6fffffff];check(0<count<=128)
    for index in range(count):
        off=version_record(address);version,cnt,file_name,aux,nxt=struct.unpack_from('<HHIII',raw,off)
        check(version==1 and 0<cnt<=128);string(file_name)
        a=version_link(address,aux)
        for inner in range(cnt):
            off=version_record(a);_,_,_,name,n=struct.unpack_from('<IHHII',raw,off);text=string(name)
            check(0<len(text)<=128)
            if text.startswith('GLIBC_'):
                check(re.fullmatch(r'GLIBC_\d+(?:\.\d+){1,2}',text) is not None);versions.append(text)
            if inner==cnt-1:check(n==0)
            else:a=version_link(a,n)
        if index==count-1:check(nxt==0)
        else:address=version_link(address,nxt)
    check(bool(versions))
    report=dict(machine='AMD64',elf_type='ET_DYN',interpreter=interpreter,
        pie=bool(dynamic.get(0x6ffffffb,0)&0x8000000),bind_now=bool(24 in dynamic or dynamic.get(30,0)&8 or dynamic.get(0x6ffffffb,0)&1),
        relro=True,nonexec_stack=True,expected_loader_policy=target_loader_policy(),
        effective_relro=dict(start=protected_start,end=protected_end,bytes=protected_end-protected_start),
        full_got_plt_protection='FULL_GOT_PLT_UNQUALIFIED',
        needed=[string(n) for n in needed],rpath=string(dynamic[15]) if 15 in dynamic else None,
        runpath=string(dynamic[29]) if 29 in dynamic else None,glibc_versions=sorted(set(versions)))
    check(report['interpreter'] in ('/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'))
    # Only the separately qualified explicit private loader path is supported.
    # Embedded tags, including empty/current-directory or expanded forms, deny.
    check(report['rpath'] is None and report['runpath'] is None)
    check(all(re.fullmatch('[A-Za-z0-9_.+-]{1,80}',n) is not None for n in report['needed']))
    check(report['pie'] and report['bind_now'] and report['relro'] and report['nonexec_stack'])
    check('libselinux.so.1' in report['needed'] and 'libcap.so.2' in report['needed'])
    check(all(tuple(map(int,v[6:].split('.'))) <= (2,35) for v in versions))
    return report


def validate_fingerprints(entries, deadline=None):
    deadline=time.monotonic()+30 if deadline is None else min(deadline,time.monotonic()+30)
    check(type(entries) is list and 0<len(entries)<=256)
    check(len({item['path'] for item in entries})==len(entries))
    for item in entries:
        check(set(item)=={'path','bytes','sha256'} and type(item['path']) is str and Path(item['path']).is_absolute())
        raw=read_file(Path(item['path']).resolve(),67108864,deadline)
        check(len(raw)==item['bytes'] and digest(raw)==hex64(item['sha256']))


def authorized_runtime(result, auth, binary, closure):
    # A build-generated result cannot approve itself: caller supplies the separately
    # hash-pinned root authorization document, never an output-derived expectation.
    if auth['status']!='ROOT_AUTHORIZED_EXACT_BUILD': hold('ROOT_EXACT_BUILD_RESULT_REQUIRED')
    check(auth['build_admitted'] is True and auth['root_authorization_receipt'] is not None)
    check(digest(canonical(result))==hex64(auth['result_sha256']))
    check(result['schema']=='f07-unapproved-native-build-v1' and result['variant']==VARIANT)
    check(result['source_lock_sha256']==SOURCE_LOCK_SHA256 and result['builder_sha256']==auth['builder_sha256'])
    check(digest(read_file(Path(__file__)))==auth['builder_sha256'])
    check(result['toolchain_sha256']==digest(canonical(auth['toolchain'])))
    validate_fingerprints(auth['toolchain'])
    check(result['binary']==auth['binary'] and result['elf']==auth['elf'] and result['runtime_closure']==auth['runtime_closure'])
    check(len(binary)==auth['binary']['bytes'] and digest(binary)==hex64(auth['binary']['sha256']))
    check(elf_report(binary)==auth['elf'])
    check(closure==auth['runtime_closure'])
    check(auth['loader'] is not None);validate_fingerprints([auth['loader']])
    return auth['binary']


def validate_private_tree(root, model, complete=False):
    root=own_root(root);validate_link_model(model)
    seen=set();total=0;pending=[root]
    while pending:
        base=pending.pop()
        with os.scandir(base) as entries:
            for entry in entries:
                path=Path(entry.path);name=path.relative_to(root).as_posix();check(name in model)
                spec=model[name];info=entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):check(spec['type']=='directory');pending.append(path)
                elif stat.S_ISLNK(info.st_mode):check(spec['type']=='symlink' and os.readlink(path)==spec['link'])
                else:
                    check(spec['type']=='file' and stat.S_ISREG(info.st_mode) and info.st_nlink==1)
                    maximum=integer(spec['bytes'],MAX_FILE);check(info.st_size==maximum if complete else 0<=info.st_size<=maximum)
                    total+=info.st_size;check(total<=MAX_TOTAL)
                    if complete:check(digest(read_file(path))==hex64(spec['sha256']))
                seen.add(name);check(len(seen)<=MAX_ENTRIES and len(pending)<=MAX_ENTRIES)
    if complete:check(seen==set(model))


def fetch_inputs(root, lock, deadline):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):raise ValueError('redirect rejected')
    root=own_root(root);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    data={};total=0
    for item in lock['artifacts']:
        check(time.monotonic()<deadline)
        with opener.open(urllib.request.Request(item['url']),timeout=min(20,max(0.1,deadline-time.monotonic()))) as response:
            check(response.status==200)
            chunks=[];size=0
            while size<=item['bytes']:
                remaining=deadline-time.monotonic();check(remaining>0)
                if response.fp is None:break
                response.fp.raw._sock.settimeout(min(20,remaining))
                chunk=response.read1(min(4096,item['bytes']-size+1))
                if not chunk:break
                chunks.append(chunk);size+=len(chunk)
            raw=b''.join(chunks)
        check(len(raw)==item['bytes'] and digest(raw)==item['sha256']);total+=len(raw)
        check(total<=lock['limits']['download_total'] and time.monotonic()<deadline)
        with (root/item['name']).open('xb') as stream:check(stream.write(raw)==len(raw))
        data[item['name']]=raw
    return data


def prepare_tree(root, lock, artifacts, deadline):
    root=own_root(root);files=None;debian=None;sysrows={};sysdata={};source_rows=None
    for item in lock['artifacts']:
        check(time.monotonic()<deadline)
        raw=artifacts[item['name']];check(len(raw)==item['bytes'] and digest(raw)==item['sha256'])
        if item['kind']=='provenance':continue
        if item['kind']=='deb':
            # A root-authenticated decoded sidecar is required when stdlib cannot
            # decode the package compression. Its parent digest is part of lock.
            sidecar=item.get('decoded_tar')
            if sidecar is None:hold('DEB_DATA_SIDECAR_INVENTORY_REQUIRED')
            check(sidecar['parent_sha256']==item['sha256'])
            check('/' not in relative(sidecar['name']));integer(sidecar['bytes'],MAX_FILE,1);hex64(sidecar['sha256'])
            decoded=read_file(root/'downloads'/sidecar['name'])
            check(len(decoded)==sidecar['bytes'] and digest(decoded)==sidecar['sha256'])
            rows,data=archive_rows(decoded,'tar',deadline)
        else:rows,data=archive_rows(raw,item['kind'],deadline)
        validate_rows(rows,item['members'])
        if item['kind']=='orig':
            prefix='bubblewrap-0.9.0/'
            check(all(name.startswith(prefix) for name in data))
            typed_source_model(rows);source_rows=rows
            files={name[len(prefix):]:value for name,value in data.items()}
        elif item['kind']=='debian':
            debian_input_model(rows,lock['patches'],data);debian=data
        elif item['kind']=='wheel':
            target=root/'tools';target.mkdir();extract_checked(rows,data,target,item['members'])
        else:
            for row in rows:
                if row['name'] not in item['extract_paths']:continue
                name=row['name']
                if name in sysrows:check(canonical(sysrows[name])==canonical(row))
                sysrows[name]=row
                if row['type']=='file':sysdata[name]=data[name]
    check(files is not None and debian is not None)
    original=files;files,_=source_patch_facts(files,debian,lock['patches']);check(tree_digest(files)==lock['patched_tree_sha256'])
    facts=source_identity_facts(source_rows,original,files);_,expected=expected_source_identity(lock)
    check(facts['post_source_identity']==expected)
    target=root/'source';target.mkdir()
    post_rows=facts['post_source_model']['members']
    extract_checked(post_rows,files,target,post_rows)
    bound=validate_source_tree(target,lock);check(bound['post_source_model_sha256']==facts['post_source_model_sha256'])
    sysroot=root/'sysroot';sysroot.mkdir()
    rows=list(sysrows.values());extract_checked(rows,sysdata,sysroot,rows,rewrites=lock['symlink_rewrites'])
    return tree_digest(files)


def runtime_closure(root, expected):
    check(type(expected) is list and 0<len(expected)<=128)
    result=[]
    for item in expected:
        name=relative(item['path']);raw=read_file(root/name)
        check(len(raw)==item['bytes'] and digest(raw)==hex64(item['sha256']))
        result.append(dict(path=name,bytes=len(raw),sha256=digest(raw)))
    check(len({x['path'] for x in result})==len(result));return result

def build_unapproved(root, lock, auth, deadline=None):
    # No code/configure/process executes while unknown facts remain null.
    build_gate(lock,auth);require_measured_loader_policy();root=own_root(root)
    deadline=time.monotonic()+90 if deadline is None else deadline
    validate_fingerprints(auth['toolchain'],deadline)
    validate_private_tree(root,lock['generated_output_model'],complete=False)
    source_binding=validate_source_tree(root/'source',lock)
    debian_identity=expected_debian_input_identity(lock)
    adapter=auth['build_adapter'];check(set(adapter)=={'path','bytes','sha256','protocol','network','filesystem'})
    check((adapter['protocol'],adapter['network'],adapter['filesystem'])==('f07-private-build-plan-v1','deny','private-build-v1'))
    validate_fingerprints([{k:adapter[k] for k in ('path','bytes','sha256')}])
    # Root-admitted adapter executes this closed plan in its independently qualified
    # filesystem/network boundary. No guessed unshare/bwrap/container fallback.
    plan=dict(schema='f07-private-build-plan-v1',stage='build',variant=VARIANT,source_lock_sha256=SOURCE_LOCK_SHA256,
              source_tree_sha256=lock['patched_tree_sha256'],recipe=lock['recipe'],toolchain=auth['toolchain'],
              sysroot='sysroot',source='source',build='build',runtime='runtime',tests='NOT_RUN',install=False,
              environment=dict(PYTHONPATH='tools',PKG_CONFIG_LIBDIR='sysroot/usr/lib/x86_64-linux-gnu/pkgconfig',
                  PKG_CONFIG_SYSROOT_DIR='sysroot',LDFLAGS='-Lsysroot/usr/lib/x86_64-linux-gnu -Lsysroot/lib/x86_64-linux-gnu -Wl,-z,now'),
              generated_output_model=lock['generated_output_model'],runtime_closure=auth['runtime_closure'])
    plan.update(source_binding);plan['debian_input_model_sha256']=debian_identity
    path=root/'build-plan.json'
    with path.open('xb') as stream:check(stream.write(canonical(plan))==len(canonical(plan)))
    from ci_evidence import capture_namespace_process
    remaining=deadline-time.monotonic();check(remaining>=0.1)
    state=capture_namespace_process([adapter['path'],'--f07-build-plan',str(path)],timeout=min(90,remaining))
    check(state['reason'] is None and state['code']==0)
    validate_private_tree(root,lock['generated_output_model'],complete=False)
    check(validate_source_tree(root/'source',lock)==source_binding)
    validate_fingerprints(auth['toolchain'],deadline)
    validate_private_tree(root,lock['generated_output_model'],complete=False)
    binarypath=root/'runtime/bin/bwrap'
    check(not binarypath.lstat().st_mode&0o6000)
    if hasattr(os,'listxattr'):check('security.capability' not in os.listxattr(binarypath))
    binary=read_file(binarypath);report=elf_report(binary)
    config=read_file(root/'build/config.h');check(b'#define HAVE_SELINUX 1' in config.splitlines())
    result=dict(schema='f07-unapproved-native-build-v1',variant=VARIANT,status='UNAPPROVED',
        source_lock_sha256=SOURCE_LOCK_SHA256,source_tree_sha256=lock['patched_tree_sha256'],
        builder_sha256=digest(read_file(Path(__file__))),toolchain_sha256=digest(canonical(auth['toolchain'])),
        recipe_sha256=digest(canonical(lock['recipe'])),binary=dict(bytes=len(binary),sha256=digest(binary)),
        elf=report,runtime_closure=runtime_closure(root,auth['runtime_closure']),vendor_tests='NOT_RUN',production='NOT_RUN')
    result.update(source_binding);result['debian_input_model_sha256']=debian_identity
    validate_source_result(result,lock);validate_input_model_result(result,lock)
    # Result is never copied into the authorization document or launched here.
    return result


def source_bootstrap(root, expected_authorization):
    import platform
    release=platform.freedesktop_os_release()
    validate_platform(release.get('ID'),release.get('VERSION_ID'),platform.machine(),platform.system())
    lock=source_lock();auth=authorization(expected_authorization);build_gate(lock,auth)
    root=own_root(root)
    with (root/'runtime/source-clock.json').open('xb') as clock:
        stamp=time.monotonic();raw=canonical(dict(schema='f07-source-clock-v1',start=stamp,deadline=stamp+540))
        check(clock.write(raw)==len(raw))
    target=root/'sourcebuild';check(not target.exists());target.mkdir(mode=0o700)
    deadline=time.monotonic()+90
    downloads=target/'downloads';downloads.mkdir()
    inputs=fetch_inputs(downloads,lock,deadline)
    adapter=auth['build_adapter'];validate_fingerprints([{k:adapter[k] for k in ('path','bytes','sha256')}])
    check((adapter['protocol'],adapter['network'],adapter['filesystem'])==('f07-private-build-plan-v1','deny','private-build-v1'))
    decode_plan=dict(schema='f07-private-build-plan-v1',stage='decode-data-only',artifacts=lock['artifacts'],install=False)
    planpath=target/'decode-plan.json'
    with planpath.open('xb') as stream:check(stream.write(canonical(decode_plan))==len(canonical(decode_plan)))
    from ci_evidence import capture_namespace_process
    remaining=deadline-time.monotonic();check(remaining>=0.1)
    decoded=capture_namespace_process([adapter['path'],'--f07-build-plan',str(planpath)],timeout=min(90,remaining))
    check(decoded['reason'] is None and decoded['code']==0)
    prepare_tree(target,lock,inputs,deadline);check(time.monotonic()<deadline)
    for item in auth['runtime_closure']:
        name=relative(item['path']);check(name.startswith('runtime/lib/'))
        source=relative(lock['runtime_map'][name]);check(source.startswith('sysroot/'))
        raw=read_file(target/source);check(len(raw)==item['bytes'] and digest(raw)==item['sha256'])
        path=target/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:check(stream.write(raw)==len(raw))
    # A qualified adapter must supply any root-pinned decoded sidecars before
    # staging; their absence is a repairable inventory gate, never a fallback.
    result=build_unapproved(target,lock,auth,deadline)
    check(time.monotonic()<deadline)
    raw=canonical(result);check(len(raw)<=65536)
    with (target/'build-result.json').open('xb') as stream:check(stream.write(raw)==len(raw))
    if auth['status']!='ROOT_AUTHORIZED_EXACT_BUILD':
        print(raw.decode(),end='');hold('ROOT_EXACT_BUILD_RESULT_REQUIRED')
    binary=read_file(target/'runtime/bin/bwrap');closure=runtime_closure(target,auth['runtime_closure'])
    validate_source_result(result,lock);validate_input_model_result(result,lock)
    authorized_runtime(result,auth,binary,closure)
    return result


def runtime_budget(root):
    raw=read_file(own_root(root)/'runtime/source-clock.json',1024)
    doc=json.loads(raw,object_pairs_hook=unique);check(raw==canonical(doc) and set(doc)=={'schema','start','deadline'})
    check(doc['schema']=='f07-source-clock-v1' and type(doc['start']) is float and type(doc['deadline']) is float)
    limits=source_lock()['limits'];cap=integer(limits['harness_seconds'],600,1);check(cap==450)
    for name,value in (('execution_seconds',540),('operation_seconds',90),('job_seconds',720),('reserve_seconds',180)):
        check(integer(limits[name],720,1)==value)
    now=time.monotonic()
    check(abs(doc['deadline']-doc['start']-540)<0.000001 and doc['start']<=now<doc['deadline'])
    remaining=doc['deadline']-now;check(remaining>=0.1)
    return min(600,cap,remaining)


def runtime_prefix(root, expected_authorization):
    target=own_root(root)/'sourcebuild';lock=source_lock();auth=authorization(expected_authorization)
    build_gate(lock,auth);require_measured_loader_policy();validate_private_tree(target,lock['generated_output_model'],complete=False)
    result_raw=read_file(target/'build-result.json',65536)
    result=json.loads(result_raw,object_pairs_hook=unique);check(result_raw==canonical(result))
    binary=read_file(target/'runtime/bin/bwrap');closure=runtime_closure(target,auth['runtime_closure'])
    validate_source_result(result,lock);validate_input_model_result(result,lock)
    authorized_runtime(result,auth,binary,closure)
    check(auth['loader']['path'].startswith(('/lib/','/lib64/','/usr/lib/')))
    return [auth['loader']['path'],'--inhibit-cache','--library-path',str(target/'runtime/lib'),str(target/'runtime/bin/bwrap')]

def deb_data_inventory(raw):
    check(type(raw) is bytes and len(raw)<=MAX_FILE and raw[:8]==b'!<arch>\n')
    offset=8;entries=[];data=[]
    while offset<len(raw):
        check(offset+60<=len(raw));header=raw[offset:offset+60];check(header[58:]==b'`\n')
        name=header[:16].decode('ascii').strip().rstrip('/');relative(name)
        text=header[48:58].decode('ascii').strip();check(re.fullmatch('[0-9]{1,10}',text) is not None)
        size=integer(int(text),MAX_FILE);start=offset+60;check(start+size<=len(raw))
        entries.append(dict(name=name,bytes=size,sha256=digest(raw[start:start+size])))
        if name.startswith('data.tar.'):data.append(name)
        offset=start+size+(size%2);check(len(entries)<=8)
    check(offset==len(raw) and len(data)==1 and any(x['name']=='debian-binary' for x in entries))
    return dict(ar_members=entries,data_member=data[0],decoded_members=None,disposition='ROOT_PINNED_DATA_DECODER_REQUIRED')


def inventory_artifacts(root):
    root=own_root(root);lock=source_lock();deadline=time.monotonic()+30;result=[];original=None;debian=None;source_identities=[];download_total=0;source_rows=None
    for item in lock['artifacts']:
        raw=read_file(root/item['name'],MAX_FILE,deadline)
        check(len(raw)==item['bytes'] and digest(raw)==item['sha256'])
        download_total+=len(raw);check(download_total<=lock['limits']['download_total'])
        row=dict(name=item['name'],bytes=len(raw),sha256=digest(raw),kind=item['kind'])
        if item['kind']=='deb':row['inventory']=deb_data_inventory(raw)
        elif item['kind']!='provenance':
            members,data=archive_rows(raw,item['kind'],deadline);row['members']=members
            if item['kind'] in ('orig','debian'):
                validate_rows(members,members)
                if item['kind']=='orig':typed_source_model(members);source_rows=members
                else:
                    row['input_model']=debian_input_model(members,lock['patches'],data)
                    row['input_model_sha256']=digest(canonical(row['input_model']))
                validate_link_model({m['name']:m for m in members})
                if item['members'] is not None:validate_rows(members,item['members'])
                source_identities.append({k:row[k] for k in ('name','bytes','sha256','kind')})
            if item['kind']=='orig':
                check(original is None)
                prefix='bubblewrap-0.9.0/';check(all(name.startswith(prefix) for name in data))
                original={name[len(prefix):]:value for name,value in data.items()}
            if item['kind']=='debian':
                check(debian is None);debian=data
        result.append(row)
    check(original is not None and debian is not None and time.monotonic()<deadline)
    patched,facts=source_patch_facts(original,debian,lock['patches'])
    facts.update(source_identity_facts(source_rows,original,patched))
    check(time.monotonic()<deadline)
    report=dict(schema='f07-source-artifact-inventory-v1',variant=VARIANT,artifacts=result,
                source_inputs=source_identities,source_patch_facts=facts,
                third_party_code_execution='NOT_RUN',build='NOT_RUN',native_execution='NOT_RUN',authorization='NOT_GRANTED')
    check(len(canonical(report))<=1048576)
    return report

def main():
    if sys.argv[1:]==['inventory']:
        raw=canonical(inventory());check(len(raw)<=65536)
    elif len(sys.argv)==3 and sys.argv[1]=='inventory-artifacts':
        raw=canonical(inventory_artifacts(sys.argv[2]));check(len(raw)<=1048576)
    else:raise ValueError('unsupported readonly command')
    print(raw.decode(),end='')


if __name__=='__main__':
    try: main()
    except QualificationHold as exc:
        print(canonical(dict(schema='f07-source-status-v1',status='HOLD',reason=str(exc))).decode(),end='');sys.exit(2)
    except Exception:
        print('{"schema":"f07-source-status-v1","status":"FAIL","reason":"CONTRACT_INVALID"}');sys.exit(1)
