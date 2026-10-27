"""Public fixed-path inventory only. No tool invocation or build authority."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

REPOSITORY='CT-Infrastructure/marketing-v7-control'
JOB='f07-builder-public-inventory'
MAX_FILE=67108864
MAX_BYTES=268435456
MAX_NODES=256
FILES=tuple(sorted({
    '/etc/os-release','/usr/lib/os-release',
    *('/usr/bin/'+p for p in ('cc','gcc','gcc-11','gcc-12','cpp-11','x86_64-linux-gnu-gcc-11','x86_64-linux-gnu-gcc-12','x86_64-linux-gnu-cpp-11',
        'as','x86_64-linux-gnu-as','ld','ld.bfd','x86_64-linux-gnu-ld','x86_64-linux-gnu-ld.bfd','ninja','pkg-config','pkgconf','x86_64-linux-gnu-pkg-config','python3','python3.10')),
    '/etc/alternatives/cc',
    *('/usr/lib/gcc/x86_64-linux-gnu/11/'+p for p in ('cc1','collect2','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','include/stddef.h','include/stdarg.h','include/limits.h')),
    *('/usr/include/'+p for p in ('stdio.h','features.h','stdc-predef.h','linux/version.h','x86_64-linux-gnu/bits/libc-header-start.h','x86_64-linux-gnu/gnu/stubs.h')),
    *('/usr/lib/x86_64-linux-gnu/'+p for p in ('crt1.o','Scrt1.o','crti.o','crtn.o','libc.so','libc_nonshared.a','libgcc_s.so.1','libc.so.6','libc-2.35.so','ld-linux-x86-64.so.2','ld-2.35.so')),
    *('/lib/x86_64-linux-gnu/'+p for p in ('libgcc_s.so.1','libc.so.6','libc-2.35.so','ld-linux-x86-64.so.2','ld-2.35.so')),
    '/lib64/ld-linux-x86-64.so.2','/usr/lib64/ld-linux-x86-64.so.2',
    '/usr/share/pkg-config-crosswrapper',
}))
NODES=frozenset({p for name in FILES for p in (name,*map(str,Path(name).parents))})
CONTEXT_KEYS=('GITHUB_REPOSITORY','GITHUB_SHA','F07_CANDIDATE_SHA','F07_TASK','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT',
              'GITHUB_JOB','RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion')
SOURCES=('.github/workflows/package-validation.yml','tests/harness/native_builder_inventory.py',
         'tests/harness/native-source-ci.lock.json','tests/harness/native-build-authorization.lock.json')
LOCK_HASHES={SOURCES[2]:'6c8be8dc661d54be89d22c72db9b81d187489ea1dde451d6934f7d39746abe83',
             SOURCES[3]:'85de32f8eba0691dc66168e4bcb49af9125c691ea9fc545a780fba74c845dba9'}
OUTPUTS=('inventory.json','manifest.json')
TEMP_NAMES=('.inventory.json.tmp','.manifest.json.tmp')


class InventoryHold(ValueError):
    pass


def need(value):
    if not value:raise InventoryHold('INVENTORY_BOUNDARY_HOLD')


# Diagnostics identify the failed boundary, never the contents of an exception.
PHASES=frozenset(('arguments','context','checkout_path','output_parent','self_binding','output_path',
    'platform','checkout_before','release','public_file','public_verify','checkout_after','document','publish','cleanup','unknown'))
REASONS=frozenset(('GUARD_REJECTED','MISSING','PERMISSION','OS_ERROR','DECODE_ERROR','UNKNOWN'))


# Fixed predicate identifiers describe source conditions, never observed data.
PREDICATES=frozenset(('COMPONENT_ALLOWLIST', 'FILE_AND_AGGREGATE_SIZE', 'FINAL_REGULAR_SINGLE_LINK', 'INTERMEDIATE_DIRECTORY', 'MISSING_REMAINS_MISSING', 'OBSERVED_IDENTITY_STABLE', 'OBSERVED_NODE_LIMIT', 'OBSERVE_ALLOWLIST_AND_DEADLINE', 'OPEN_FILE_IDENTITY_STABLE', 'OPTIONAL_MISSING_STABLE', 'PARENT_WITHIN_ROOT', 'READ_DEADLINE', 'READ_SIZE_AND_PATH_IDENTITY', 'READ_SIZE_LIMIT', 'REQUEST_ALLOWLIST', 'RESOLVED_FILE_ALLOWLIST', 'SYMLINK_COMPONENT_GRAMMAR', 'SYMLINK_HOP_LIMIT', 'SYMLINK_TARGET_ALLOWLIST', 'SYMLINK_TARGET_TYPE_SIZE_CHARACTERS', 'VERIFY_IDENTITY_STABLE'))


class PredicateHold(InventoryHold):
    def __init__(self,code):
        super().__init__('INVENTORY_BOUNDARY_HOLD');self.code=code


def predicate(value,code):
    need(type(code) is str and code in PREDICATES)
    if not value:raise PredicateHold(code)


# Authenticated Jammy pkg-config0.29.2-1ubuntu3 payload69da4190... supplies
# wrapper2235 bytes SHA2564d37004a6a285b0676073345752c42f8af20cc8ea7537772b8ea4249b9fc1001.
# Its hook conditionally creates this target; this is not hosted-file proof.
WRAPPER_REQUEST='/usr/bin/x86_64-linux-gnu-pkg-config'
PUBLIC_WRAPPER='/usr/share/pkg-config-crosswrapper'
WRAPPER_BYTES=2235
WRAPPER_SHA256='4d37004a6a285b0676073345752c42f8af20cc8ea7537772b8ea4249b9fc1001'
WRAPPER_CLASSES=frozenset(('KNOWN_PUBLIC_WRAPPER','UNKNOWN'))


class WrapperTargetHold(PredicateHold):
    def __init__(self,classification):
        super().__init__('SYMLINK_TARGET_ALLOWLIST');self.classification=classification


def wrapper_target_diagnostic(error):
    # Separate record preserves the existing exact legacy diagnostic contract.
    if type(error) is not DiagnosticHold:return ''
    if (error.phase,error.reason,error.path_id)!=('public_file','GUARD_REJECTED',WRAPPER_REQUEST):return ''
    classification=getattr(error,'wrapper_classification',None)
    if type(classification) is not str or classification not in WRAPPER_CLASSES:return ''
    raw=canonical(dict(schema='f07-public-wrapper-classification-v1',status='HOLD',path_id=WRAPPER_REQUEST,target_class=classification))
    need(len(raw)<=512);return raw.decode('ascii')


class DiagnosticHold(InventoryHold):
    def __init__(self,phase,reason,path_id):
        super().__init__('INVENTORY_BOUNDARY_HOLD')
        self.phase=phase;self.reason=reason;self.path_id=path_id


def boundary(phase,operation,*args,path_id=None):
    need(type(phase) is str and phase in PHASES)
    need(path_id is None or (type(path_id) is str and path_id in FILES))
    try:return operation(*args)
    except DiagnosticHold:raise
    except Exception as error:
        # Exact classes only: no errno, message, filename, repr or traceback export.
        reason={InventoryHold:'GUARD_REJECTED',FileNotFoundError:'MISSING',PermissionError:'PERMISSION',
            OSError:'OS_ERROR',UnicodeDecodeError:'DECODE_ERROR'}.get(type(error),'UNKNOWN')
        converted=DiagnosticHold(phase,reason,path_id)
        if type(error) in (PredicateHold,WrapperTargetHold) and type(error.code) is str and error.code in PREDICATES:
            converted.reason='GUARD_REJECTED';converted.predicate=error.code
            if type(error) is WrapperTargetHold and type(error.classification) is str and error.classification in WRAPPER_CLASSES:
                converted.wrapper_classification=error.classification
        raise converted from None


def diagnostic(error):
    phase='unknown';reason='UNKNOWN';path_id=None
    if type(error) is DiagnosticHold:
        if type(error.phase) is str and error.phase in PHASES:phase=error.phase
        if type(error.reason) is str and error.reason in REASONS:reason=error.reason
        if type(error.path_id) is str and error.path_id in FILES:path_id=error.path_id
    doc=dict(schema='f07-public-builder-diagnostic-v1',status='HOLD',phase=phase,reason=reason,path_id=path_id)
    if type(error) is DiagnosticHold:
        code=getattr(error,'predicate',None)
        if type(code) is str and code in PREDICATES and reason=='GUARD_REJECTED' and phase in ('public_file','public_verify','release'):
            doc['predicate']=code
    raw=canonical(doc)
    need(len(raw)<=512);return raw.decode('ascii')


def canonical(doc):
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def hex40(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{40}',value) is not None);return value


def hex64(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None);return value


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def safe_directory(path):
    path=Path(path);need(path.is_absolute() and path!=Path(path.anchor) and str(path)==str(Path(os.path.normpath(path))))
    for parent in (path,*path.parents):need(stat.S_ISDIR(parent.lstat().st_mode))
    return path


def private_read(path,maximum):
    """Fixed checkout metadata only, with no linked ancestors or leaf."""
    path=Path(path);safe_directory(path.parent);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=maximum)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as stream:
        need(identity(os.fstat(stream.fileno()))==identity(info));raw=stream.read(maximum+1)
        need(identity(os.fstat(stream.fileno()))==identity(info))
    need(len(raw)==info.st_size and identity(path.lstat())==identity(info));return raw


def checkout_binding(root,expected):
    root=safe_directory(root);git=root/'.git';safe_directory(git)
    head=private_read(git/'HEAD',256)
    if head.startswith(b'ref: '):
        ref=head[5:].decode('ascii').rstrip('\n')
        need(re.fullmatch(r'refs/(?:heads|remotes)/[A-Za-z0-9_./-]{1,120}',ref) is not None)
        need(all(part not in ('','.','..') for part in ref.split('/')))
        head=private_read(git/ref,64)
    need(head==expected.encode()+b'\n')
    hashes={name:sha(private_read(root/name,1048576)) for name in SOURCES}
    for name,value in LOCK_HASHES.items():need(hashes[name]==value)
    return hashes


def context(values):
    need(type(values) is dict and set(values)==set(CONTEXT_KEYS) and all(type(v) is str for v in values.values()))
    need(values['GITHUB_REPOSITORY']==REPOSITORY and values['F07_TASK']=='F07' and values['GITHUB_JOB']==JOB)
    hex40(values['GITHUB_SHA']);hex40(values['F07_CANDIDATE_SHA'])
    for name in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):need(re.fullmatch('[1-9][0-9]{0,18}',values[name]) is not None)
    need(values['RUNNER_OS']=='Linux' and values['RUNNER_ARCH']=='X64' and values['ImageOS']=='ubuntu22')
    need(re.fullmatch(r'[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}',values['ImageVersion']) is not None)
    return dict(repository=REPOSITORY,task='F07',job=JOB,tested_git_sha=values['GITHUB_SHA'],pr_candidate_sha=values['F07_CANDIDATE_SHA'],
        run_id=int(values['GITHUB_RUN_ID']),run_attempt=int(values['GITHUB_RUN_ATTEMPT']),runner_os='Linux',runner_arch='X64',image_os='ubuntu22',image_version=values['ImageVersion'])


class FixedFiles:
    """Bounded component resolution; injected roots support synthetic tests only."""
    def __init__(self,root=Path('/')):
        self.root=Path(root);self.observed={};self.public={};self.cache={};self.total=0;self.deadline=time.monotonic()+60

    def physical(self,name):return self.root/name.lstrip('/')

    def observe(self,name):
        predicate(name in NODES and time.monotonic()<self.deadline,'OBSERVE_ALLOWLIST_AND_DEADLINE')
        info=self.physical(name).lstat();key=identity(info)
        if name in self.observed:predicate(self.observed[name]==key,'OBSERVED_IDENTITY_STABLE')
        self.observed[name]=key;predicate(len(self.observed)<=MAX_NODES,'OBSERVED_NODE_LIMIT');return info

    def resolve(self,name):
        predicate(name in FILES,'REQUEST_ALLOWLIST');parts=[];todo=[(p,False) for p in name.split('/')[1:]];hops=0;links=[]
        while todo:
            part,required=todo.pop(0)
            if part=='..':predicate(bool(parts),'PARENT_WITHIN_ROOT');parts.pop();continue
            current='/'+('/'.join(parts+[part]));predicate(current in NODES,'COMPONENT_ALLOWLIST')
            try:info=self.observe(current)
            except FileNotFoundError:
                predicate(not required and (current not in self.observed or self.observed[current] is None),'OPTIONAL_MISSING_STABLE')
                self.observed[current]=None;predicate(len(self.observed)<=MAX_NODES,'OBSERVED_NODE_LIMIT');return None,links
            if stat.S_ISLNK(info.st_mode):
                hops+=1;predicate(hops<=16,'SYMLINK_HOP_LIMIT');target=os.readlink(self.physical(current))
                predicate(identity(self.observe(current))==identity(info),'OBSERVED_IDENTITY_STABLE')
                predicate(type(target) is str and 0<len(target)<=240 and re.fullmatch('[A-Za-z0-9_+./-]+',target) is not None,'SYMLINK_TARGET_TYPE_SIZE_CHARACTERS')
                rawparts=target.split('/');absolute=target.startswith('/')
                if absolute:rawparts=rawparts[1:]
                predicate(all(p not in ('','.') for p in rawparts),'SYMLINK_COMPONENT_GRAMMAR')
                lexical=os.path.normpath(target if absolute else os.path.join('/'+('/'.join(parts)),target))
                if lexical not in NODES and name==WRAPPER_REQUEST and current==WRAPPER_REQUEST:
                    # Re-observe only the link itself before classifying; never
                    # stat/open/follow the rejected target, even the known one.
                    predicate(identity(self.observe(current))==identity(info),'OBSERVED_IDENTITY_STABLE')
                    raise WrapperTargetHold('KNOWN_PUBLIC_WRAPPER' if lexical==PUBLIC_WRAPPER else 'UNKNOWN')
                predicate(lexical in NODES,'SYMLINK_TARGET_ALLOWLIST')
                links.append(dict(path=current,target=lexical,raw_target_sha256=sha(os.fsencode(target))))
                self.public[current]=dict(path=current,type='symlink',mode=stat.S_IMODE(info.st_mode),target=lexical,raw_target_sha256=sha(os.fsencode(target)))
                if absolute:parts=[]
                todo=[(p,True) for p in rawparts]+todo
            else:
                parts.append(part)
                if todo:
                    predicate(stat.S_ISDIR(info.st_mode),'INTERMEDIATE_DIRECTORY');self.public[current]=dict(path=current,type='directory',mode=stat.S_IMODE(info.st_mode))
                else:predicate(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'FINAL_REGULAR_SINGLE_LINK')
        result='/'+('/'.join(parts));predicate(result in FILES,'RESOLVED_FILE_ALLOWLIST');return result,links

    def file(self,name):
        resolved,links=self.resolve(name)
        if name==PUBLIC_WRAPPER and resolved is not None:need(resolved==PUBLIC_WRAPPER and not links)
        if resolved is None:return dict(path=name,status='NOT_FOUND',resolved=None,bytes=None,sha256=None,mode=None,links=links)
        if resolved not in self.cache:
            info=self.observe(resolved)
            if resolved==PUBLIC_WRAPPER:need(info.st_size==WRAPPER_BYTES)
            predicate(info.st_size<=MAX_FILE and self.total+info.st_size<=MAX_BYTES,'FILE_AND_AGGREGATE_SIZE')
            descriptor=os.open(self.physical(resolved),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            digest=hashlib.sha256();size=0
            with os.fdopen(descriptor,'rb') as stream:
                predicate(identity(os.fstat(stream.fileno()))==identity(info),'OPEN_FILE_IDENTITY_STABLE')
                while True:
                    predicate(time.monotonic()<self.deadline,'READ_DEADLINE')
                    block=stream.read(min(65536,MAX_FILE-size+1))
                    if not block:break
                    size+=len(block);predicate(size<=MAX_FILE,'READ_SIZE_LIMIT');digest.update(block)
                predicate(identity(os.fstat(stream.fileno()))==identity(info),'OPEN_FILE_IDENTITY_STABLE')
            predicate(size==info.st_size and identity(self.observe(resolved))==identity(info),'READ_SIZE_AND_PATH_IDENTITY');self.total+=size
            self.cache[resolved]=dict(path=resolved,type='file',mode=stat.S_IMODE(info.st_mode),bytes=size,sha256=digest.hexdigest())
            self.public[resolved]=self.cache[resolved]
        fact=self.cache[resolved]
        if resolved==PUBLIC_WRAPPER:need(fact['bytes']==WRAPPER_BYTES and fact['sha256']==WRAPPER_SHA256)
        return dict(path=name,status='OBSERVED',resolved=resolved,bytes=fact['bytes'],sha256=fact['sha256'],mode=fact['mode'],links=links)

    def verify(self):
        for name,expected in self.observed.items():
            if expected is None:
                try:self.physical(name).lstat()
                except FileNotFoundError:continue
                predicate(False,'MISSING_REMAINS_MISSING')
            predicate(identity(self.physical(name).lstat())==expected,'VERIFY_IDENTITY_STABLE')

    def release(self):
        fact=self.file('/etc/os-release');need(fact['status']=='OBSERVED' and fact['bytes']<=8192)
        raw=private_read(self.physical(fact['resolved']),8192);fields={}
        for line in raw.decode('ascii').splitlines():
            if not line or line.startswith('#'):continue
            key,sep,value=line.partition('=');need(sep and re.fullmatch('[A-Z_]+',key) is not None)
            if key in ('ID','VERSION_ID'):
                need(key not in fields);fields[key]=value
        need(fields.get('ID') in ('ubuntu','"ubuntu"') and fields.get('VERSION_ID') in ('22.04','"22.04"'))
        need(sha(raw)==fact['sha256']);return dict(id='ubuntu',version_id='22.04')


def inventory(values,checkout,files=None):
    ctx=boundary('context',context,values);before=boundary('checkout_before',checkout_binding,checkout,ctx['tested_git_sha'])
    files=FixedFiles() if files is None else files
    release=boundary('release',files.release,path_id='/etc/os-release')
    facts=[boundary('public_file',files.file,name,path_id=name) for name in FILES]
    boundary('public_verify',files.verify)
    boundary('checkout_after',need,boundary('checkout_after',checkout_binding,checkout,ctx['tested_git_sha'])==before)
    doc=dict(schema='f07-public-builder-inventory-v1',context=ctx,source_sha256=before,os_release=release,
        files=facts,closure_nodes=[files.public[name] for name in sorted(files.public)],
        disposition='HOLD_INVENTORY_ONLY_NOT_AUTHORITY',compiler_execution='NOT_RUN',build_adapter='NOT_QUALIFIED',
        full_toolchain_and_elf_runtime_closure='NOT_QUALIFIED',build='NOT_RUN',native_runtime='NOT_RUN',
        metadata_get='NOT_RUN_ROOT_READBACK_REQUIRED',service_job_metadata='NOT_RUN_ROOT_READBACK_REQUIRED',elapsed_seven_day_deletion='NOT_RUN')
    boundary('document',validate_inventory,doc);return doc


def validate_inventory(doc):
    need(type(doc) is dict and set(doc)=={'schema','context','source_sha256','os_release','files','closure_nodes','disposition','compiler_execution','build_adapter','full_toolchain_and_elf_runtime_closure','build','native_runtime','metadata_get','service_job_metadata','elapsed_seven_day_deletion'})
    need(doc['schema']=='f07-public-builder-inventory-v1' and doc['disposition']=='HOLD_INVENTORY_ONLY_NOT_AUTHORITY')
    need(doc['compiler_execution']==doc['build']==doc['native_runtime']==doc['elapsed_seven_day_deletion']=='NOT_RUN')
    need(doc['build_adapter']==doc['full_toolchain_and_elf_runtime_closure']=='NOT_QUALIFIED' and doc['metadata_get']=='NOT_RUN_ROOT_READBACK_REQUIRED')
    need(doc['service_job_metadata']=='NOT_RUN_ROOT_READBACK_REQUIRED')
    need(doc['os_release']==dict(id='ubuntu',version_id='22.04'))
    ctx=doc['context'];need(type(ctx) is dict and set(ctx)=={'repository','task','job','tested_git_sha','pr_candidate_sha','run_id','run_attempt','runner_os','runner_arch','image_os','image_version'})
    for name in ('run_id','run_attempt'):need(type(ctx[name]) is int and 0<ctx[name]<10**19)
    mapped=dict(GITHUB_REPOSITORY=ctx['repository'],F07_TASK=ctx['task'],GITHUB_JOB=ctx['job'],GITHUB_SHA=ctx['tested_git_sha'],F07_CANDIDATE_SHA=ctx['pr_candidate_sha'],
        GITHUB_RUN_ID=str(ctx['run_id']),GITHUB_RUN_ATTEMPT=str(ctx['run_attempt']),RUNNER_OS=ctx['runner_os'],RUNNER_ARCH=ctx['runner_arch'],ImageOS=ctx['image_os'],ImageVersion=ctx['image_version'])
    need(context(mapped)==ctx)
    need(type(doc['source_sha256']) is dict and set(doc['source_sha256'])==set(SOURCES))
    for value in doc['source_sha256'].values():hex64(value)
    for name,value in LOCK_HASHES.items():need(doc['source_sha256'][name]==value)
    need(type(doc['files']) is list and [row['path'] for row in doc['files']]==list(FILES))
    for row in doc['files']:
        need(set(row)=={'path','status','resolved','bytes','sha256','mode','links'} and row['status'] in ('OBSERVED','NOT_FOUND'))
        need(type(row['links']) is list and len(row['links'])<=16)
        if row['status']=='OBSERVED':
            need(row['resolved'] in FILES and type(row['bytes']) is int and 0<=row['bytes']<=MAX_FILE)
            need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None)
            need(type(row['mode']) is int and 0<=row['mode']<=0o7777)
        else:need(all(row[k] is None for k in ('resolved','bytes','sha256','mode')))
        for link in row['links']:need(set(link)=={'path','target','raw_target_sha256'} and link['path'] in NODES and link['target'] in NODES and re.fullmatch('[0-9a-f]{64}',link['raw_target_sha256']) is not None)
    need(type(doc['closure_nodes']) is list and len(doc['closure_nodes'])<=MAX_NODES)
    need([row['path'] for row in doc['closure_nodes']]==sorted({row['path'] for row in doc['closure_nodes']}))
    for row in doc['closure_nodes']:
        need(row['path'] in NODES and type(row['mode']) is int and 0<=row['mode']<=0o7777)
        keys={'path','type','mode'}
        if row['type']=='file':keys|={'bytes','sha256'};need(row['path'] in FILES and type(row['bytes']) is int and 0<=row['bytes']<=MAX_FILE and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None)
        elif row['type']=='symlink':keys|={'target','raw_target_sha256'};need(row['target'] in NODES and re.fullmatch('[0-9a-f]{64}',row['raw_target_sha256']) is not None)
        else:need(row['type']=='directory')
        need(set(row)==keys)
    nodes={row['path']:row for row in doc['closure_nodes']}
    wrapper=next(row for row in doc['files'] if row['path']==PUBLIC_WRAPPER)
    if wrapper['status']=='OBSERVED':
        need(wrapper['resolved']==PUBLIC_WRAPPER and wrapper['links']==[])
        need(wrapper['bytes']==WRAPPER_BYTES and wrapper['sha256']==WRAPPER_SHA256)
        need(PUBLIC_WRAPPER in nodes and nodes[PUBLIC_WRAPPER]['type']=='file')
    need(sum(row['bytes'] for row in nodes.values() if row['type']=='file')<=MAX_BYTES)
    for fact in doc['files']:
        if fact['status']=='OBSERVED':
            need(fact['resolved'] in nodes);node=nodes[fact['resolved']]
            need(node['type']=='file' and all(node[k]==fact[k] for k in ('bytes','sha256','mode')))
        for link in fact['links']:
            need(link['path'] in nodes and nodes[link['path']]['type']=='symlink')
            need(all(nodes[link['path']][k]==link[k] for k in ('target','raw_target_sha256')))
    need(len(canonical(doc))<=61440)


def output_path(root,parent,ctx):
    parent=safe_directory(parent);root=Path(root)
    need(root.parent==parent and root.name=='f07-builder-inventory-'+str(ctx['run_id'])+'-'+str(ctx['run_attempt']))
    return root


def root_identity(root):
    safe_directory(root);info=root.lstat();need(info.st_uid==os.getuid());return (info.st_dev,info.st_ino,info.st_uid,info.st_mode)


def publish(root,parent,doc):
    validate_inventory(doc);root=output_path(root,parent,doc['context'])
    raw=canonical(doc);manifest=dict(schema='f07-public-builder-inventory-manifest-v1',context=doc['context'],source_sha256=doc['source_sha256'],
        files={'inventory.json':dict(bytes=len(raw),sha256=sha(raw))},retention_days=7,
        artifact_service_metadata='NOT_RUN_ROOT_SAME_RUN_READBACK_REQUIRED',elapsed_deletion='NOT_RUN',authority='NONE')
    meta=canonical(manifest);need(len(meta)<=4096 and len(raw)+len(meta)<=65536)
    root.mkdir(mode=0o700);expected=root_identity(root)
    for name,data in zip(OUTPUTS,(raw,meta)):
        need(root_identity(root)==expected)
        temporary=root/('.'+name+'.tmp')
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(descriptor,'wb') as stream:need(stream.write(data)==len(data));stream.flush();os.fsync(stream.fileno())
        need(root_identity(root)==expected);os.link(temporary,root/name,follow_symlinks=False)
        need(root_identity(root)==expected);temporary.unlink()
    need(root_identity(root)==expected and {p.name for p in root.iterdir()}==set(OUTPUTS))
    for name,data in zip(OUTPUTS,(raw,meta)):need(private_read(root/name,65536)==data)


def cleanup(root,parent,ctx):
    root=output_path(root,parent,ctx)
    try:root.lstat()
    except FileNotFoundError:return
    expected=root_identity(root);entries=list(root.iterdir());need(len(entries)<=4 and {p.name for p in entries}<=set(OUTPUTS+TEMP_NAMES))
    identities={};owned={}
    for path in entries:
        info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_size<=65536)
        key=(info.st_dev,info.st_ino);identities.setdefault(key,[]).append((path,info.st_nlink))
        owned[path]=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size)
    for group in identities.values():need(all(links==len(group) for _,links in group))
    need(root_identity(root)==expected)
    for path in entries:
        need(root_identity(root)==expected);info=path.lstat()
        need((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size)==owned[path]);path.unlink()
    need(root_identity(root)==expected);root.rmdir()


def main():
    boundary('arguments',need,len(sys.argv)==3 and sys.argv[1] in ('inventory','cleanup'))
    values={name:os.environ.get(name) for name in CONTEXT_KEYS};ctx=boundary('context',context,values)
    checkout=boundary('checkout_path',safe_directory,os.environ.get('GITHUB_WORKSPACE',''))
    parent=boundary('output_parent',safe_directory,os.environ.get('RUNNER_TEMP',''))
    boundary('self_binding',need,Path(__file__).absolute()==checkout/'tests/harness/native_builder_inventory.py')
    target=boundary('output_path',output_path,sys.argv[2],parent,ctx)
    if sys.argv[1]=='cleanup':boundary('cleanup',cleanup,target,parent,ctx)
    else:
        boundary('platform',need,os.uname().sysname=='Linux' and os.uname().machine=='x86_64')
        boundary('publish',publish,target,parent,inventory(values,checkout))
    print('{"schema":"f07-public-builder-status-v1","status":"INVENTORY_ONLY_NOT_AUTHORITY"}')


if __name__=='__main__':
    try:main()
    except Exception as error:
        sys.stderr.write(diagnostic(error))
        sys.stderr.write(wrapper_target_diagnostic(error))
        print('{"schema":"f07-public-builder-status-v1","status":"HOLD","reason":"INVENTORY_BOUNDARY_HOLD"}')
        sys.exit(1)
