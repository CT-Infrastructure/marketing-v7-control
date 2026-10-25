"""Host-side snapshot and output validation; do not execute agent Git configuration."""
from __future__ import annotations
import hashlib, io, json, os, re, subprocess, tarfile
from pathlib import Path
from scheduler import safe_relative, path_owned

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def extract_archive(data: bytes, destination: Path, max_bytes: int=100*1024*1024):
    destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        members=archive.getmembers();total=0;seen=set()
        for member in members:
            rel=safe_relative(member.name)
            if rel in seen:raise ValueError('Duplicate archive member')
            seen.add(rel)
            if not (member.isdir() or member.isfile()):raise ValueError('Only regular files/directories allowed in source export')
            if member.size<0:raise ValueError('Invalid archive size')
            total+=member.size
            if total>max_bytes:raise ValueError('Source export exceeds budget')
        for member in members:
            target=destination/safe_relative(member.name)
            if member.isdir():target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            stream=archive.extractfile(member)
            if stream is None:raise ValueError('Missing member bytes')
            with target.open('xb') as out:
                while True:
                    block=stream.read(1024*1024)
                    if not block:break
                    out.write(block)
            # Do not copy setuid/setgid bits or untrusted ownership.
            target.chmod(0o755 if member.mode&0o111 else 0o644)

def export_git(source: Path, revision: str, destination: Path, max_bytes: int=100*1024*1024):
    if not re.fullmatch(r'[a-fA-F0-9]{40,64}',revision):raise ValueError('An immutable full Git revision is required')
    r=subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',str(source),'archive','--format=tar',revision],capture_output=True,check=True,timeout=60)
    if len(r.stdout)>max_bytes+1024*1024:raise ValueError('Archive exceeds context budget')
    extract_archive(r.stdout,destination,max_bytes)

def inventory(root: Path, max_bytes: int=200*1024*1024) -> dict[str,str]:
    total=0;result={}
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            if p.is_symlink():raise ValueError('Symlink outputs are forbidden')
            if not (p.is_dir() or p.is_file()):raise ValueError('Special-file output forbidden')
        for name in files:
            p=Path(directory)/name;relative=safe_relative(p.relative_to(root).as_posix())
            total+=p.stat().st_size
            if total>max_bytes:raise ValueError('Workspace exceeds output budget')
            result[relative]=digest(p)
    return result

def verify_result(packet: dict, workspace: Path, output: Path, before: dict, max_bytes: int) -> dict:
    after=inventory(workspace,max_bytes)
    changed=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k))
    if any(not path_owned(p,packet['task']['write_paths']) for p in changed):raise ValueError('Actual diff exceeds owned write paths')
    path=output/'result.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:raise ValueError('Invalid result file')
    result=json.loads(path.read_text())
    for k in ['task_key','lease_token','fence','input_sha256','base_revision']:
        if result.get(k)!=packet[k]:raise ValueError('Result/input binding mismatch: '+k)
    if sorted(result.get('changed_paths',[]))!=changed:raise ValueError('Declared diff differs from actual filesystem diff')
    inventory(output,max_bytes)
    for artifact in result.get('artifacts',[]):
        target=output/safe_relative(artifact['path'])
        if not target.is_file() or digest(target)!=artifact['sha256']:raise ValueError('Invalid artifact digest')
    return result
