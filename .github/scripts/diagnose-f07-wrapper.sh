#!/usr/bin/env bash
set -euo pipefail
python3 -I -S -B - "$@" <<'PY'
import hashlib,json,os,re,stat,sys,time,subprocess,selectors
from pathlib import Path
EXPECTED_SIZE=2235
EXPECTED_SHA='4d37004a6a285b0676073345752c42f8af20cc8ea7537772b8ea4249b9fc1001'
WRAPPER=Path('/usr/share/pkg-config-crosswrapper')
SOURCES=('.github/workflows/f07-hosted-wrapper-diagnostic.yml','.github/scripts/diagnose-f07-wrapper.sh')
def need(value):
    if not value:raise ValueError('CLOSED_BOUNDARY')
def ident(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory(p):
    need(p.is_absolute() and str(p)==os.path.normpath(str(p)))
    for x in (p,*p.parents):need(stat.S_ISDIR(x.lstat().st_mode))
    return p
def read_fixed(p,cap):
    directory(p.parent);before=p.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap)
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        need(ident(os.fstat(stream.fileno()))==ident(before));raw=stream.read(cap+1)
        need(ident(os.fstat(stream.fileno()))==ident(before))
    need(len(raw)==before.st_size and ident(p.lstat())==ident(before));return raw,before

def parse_release(raw):
    # Parse data only: no shell expansion, evaluation, comments or extra keys.
    need(type(raw) is bytes and len(raw)<=8192)
    allowed=('ID','VERSION_ID','VERSION_CODENAME','BUILD_ID','PRETTY_NAME');fields={}
    for line in raw.decode('ascii').splitlines():
        if not line or line.startswith('#'):continue
        key,sep,value=line.partition('=');need(sep and re.fullmatch('[A-Z_][A-Z0-9_]*',key))
        if key not in allowed:continue
        need(key not in fields and len(value)<=258)
        if value.startswith(('"',"'")):
            need(len(value)>=2 and value[-1]==value[0]);value=value[1:-1]
        need(len(value)<=256 and all(32<=ord(char)<=126 for char in value))
        need('\\' not in value and '"' not in value and "'" not in value)
        fields[key]=value
    need(fields.get('ID')=='ubuntu' and fields.get('VERSION_ID')=='22.04')
    return {'status':'OBSERVED_PUBLIC_OS_FIELDS','fields':fields}

def package_query(arguments,kind):
    # Fixed executable/argv, no PATH search or shell. Kill/reap only this child.
    child=None;selection=selectors.DefaultSelector();data=[bytearray(),bytearray()];deadline=time.monotonic()+5
    try:
        child=subprocess.Popen(['/usr/bin/dpkg-query',*arguments],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'LC_ALL':'C','PATH':'/usr/bin:/bin'},close_fds=True)
        for index,stream in enumerate((child.stdout,child.stderr)):
            os.set_blocking(stream.fileno(),False);selection.register(stream,selectors.EVENT_READ,index)
        while selection.get_map():
            if time.monotonic()>=deadline:raise TimeoutError()
            for key,_ in selection.select(min(.05,max(0,deadline-time.monotonic()))):
                block=os.read(key.fileobj.fileno(),min(1024,8193-sum(map(len,data))))
                if not block:selection.unregister(key.fileobj);continue
                data[key.data].extend(block)
                if sum(map(len,data))>8192:raise ValueError()
        code=child.wait(timeout=max(.001,deadline-time.monotonic()))
        if code!=0:return {'status':'UNAVAILABLE','facts':[]}
        lines=bytes(data[0]).decode('ascii').splitlines();facts=[]
        for line in lines:
            if kind=='version':
                match=re.fullmatch(r'(pkg-config|pkgconf)(?::amd64)?\t([A-Za-z0-9.+:~_-]{1,80})',line)
                need(match is not None);facts.append({'package':match[1],'version':match[2]})
            else:
                match=re.fullmatch(r'(pkg-config|pkgconf)(?::amd64)?: /usr/share/pkg-config-crosswrapper',line)
                need(match is not None);facts.append({'package':match[1]})
        need(len(facts)<=2 and len({x['package'] for x in facts})==len(facts))
        return {'status':'OBSERVED_PACKAGE_METADATA_ONLY','facts':facts}
    except Exception:return {'status':'UNAVAILABLE','facts':[]}
    finally:
        selection.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=1)
            for stream in (child.stdout,child.stderr):stream.close()

def main():
    need(len(sys.argv)==2 and sys.argv[1] in ('collect','cleanup'))
    run=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
    need(re.fullmatch('[1-9][0-9]{0,18}',run) and re.fullmatch('[1-9][0-9]{0,18}',attempt))
    need(os.environ.get('GITHUB_REPOSITORY')=='CT-Infrastructure/marketing-v7-control' and os.environ.get('GITHUB_JOB')=='f07-wrapper-diagnostic')
    parent=directory(Path(os.environ.get('RUNNER_TEMP','')));root=parent/('f07-wrapper-diagnostic-'+run+'-'+attempt);target=root/'diagnostic.json'
    if sys.argv[1]=='cleanup':
        try:root.lstat()
        except FileNotFoundError:return
        directory(root);before=ident(root.lstat());need(root.lstat().st_uid==os.getuid())
        entries=list(root.iterdir());need(len(entries)<=1 and all(p.name=='diagnostic.json' for p in entries))
        for p in entries:
            info=p.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.getuid() and info.st_size<=65536)
        need(ident(root.lstat())==before)
        for p in entries:p.unlink()
        root.rmdir();return
    root.mkdir(mode=0o700);directory(root);root_id=(root.stat().st_dev,root.stat().st_ino)
    tested=os.environ.get('GITHUB_SHA','');candidate=os.environ.get('F07_CANDIDATE_SHA','')
    need(re.fullmatch('[0-9a-f]{40}',tested) and re.fullmatch('[0-9a-f]{40}',candidate))
    image=os.environ.get('ImageVersion','');need(re.fullmatch(r'[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}',image))
    need(os.environ.get('ImageOS')=='ubuntu22' and os.environ.get('RUNNER_OS')=='Linux' and os.environ.get('RUNNER_ARCH')=='X64')
    checkout=directory(Path(os.environ.get('GITHUB_WORKSPACE','')))
    sources={name:hashlib.sha256(read_fixed(checkout/name,65536)[0]).hexdigest() for name in SOURCES}
    wrapper={'status':'BOUNDARY_REJECTED','type':None,'uid':None,'gid':None,'mode':None,'bytes':None,'sha256':None,'matches_expected':False}
    try:
        directory(WRAPPER.parent);info=WRAPPER.lstat()
        kind='regular' if stat.S_ISREG(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else 'other'
        wrapper.update(type=kind,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
        raw,info=read_fixed(WRAPPER,65536);digest=hashlib.sha256(raw).hexdigest()
        wrapper.update(status='OBSERVED_PUBLIC_FILE_ONLY',bytes=len(raw),sha256=digest,matches_expected=(len(raw)==EXPECTED_SIZE and digest==EXPECTED_SHA))
    except FileNotFoundError:wrapper['status']='MISSING'
    except Exception:pass
    release={'status':'UNAVAILABLE','fields':{}}
    try:
        path=Path('/etc/os-release');directory(path.parent);before=path.lstat()
        if stat.S_ISLNK(before.st_mode):
            link=os.readlink(path);need(link in ('../usr/lib/os-release','/usr/lib/os-release'));need(ident(path.lstat())==ident(before));path=Path('/usr/lib/os-release')
        raw,_=read_fixed(path,8192);release=parse_release(raw)
    except Exception:pass
    doc={'schema':'f07-fixed-public-wrapper-diagnostic-v1','disposition':'DIAGNOSTIC_ONLY_NOT_ACCEPTANCE','repository':'CT-Infrastructure/marketing-v7-control','job':'f07-wrapper-diagnostic','tested_git_sha':tested,'pr_candidate_sha':candidate,'run_id':run,'run_attempt':attempt,'source_sha256':sources,'runner':{'os':'Linux','arch':'X64','image_os':'ubuntu22','image_version':image},'wrapper_path':str(WRAPPER),'expected':{'bytes':EXPECTED_SIZE,'sha256':EXPECTED_SHA},'observed':wrapper,'os_release':release,'package_versions':package_query(['-W','-f=${binary:Package}\t${Version}\n','pkg-config','pkgconf'],'version'),'package_owner':package_query(['-S',str(WRAPPER)],'owner'),'native_execution':'NOT_RUN','adoption':'NOT_AUTHORIZED','retention_days_configured':7,'elapsed_seven_day_deletion':'NOT_RUN','service_artifact_metadata':'ROOT_SAME_RUN_READBACK_REQUIRED'}
    need(sources=={name:hashlib.sha256(read_fixed(checkout/name,65536)[0]).hexdigest() for name in SOURCES})
    raw=(json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii');need(len(raw)<=65536)
    need((root.stat().st_dev,root.stat().st_ino)==root_id)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:need(stream.write(raw)==len(raw));stream.flush();os.fsync(stream.fileno())
    need(read_fixed(target,65536)[0]==raw);print(raw.decode('ascii'),end='')
try:main()
except Exception:
    print('{"schema":"f07-wrapper-diagnostic-status-v1","status":"CLOSED_BOUNDARY_FAILURE"}');sys.exit(1)
PY
