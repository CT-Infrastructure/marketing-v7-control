"""F06 offline policy validation. No launch, host inspection or qualification."""
import argparse
import json
import re
from pathlib import Path

class PolicyError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise PolicyError(message)

def shape(value, keys, label):
    require(type(value) is dict and set(value) == set(keys.split()), label + ': missing or unknown field')

def integer(value, low, high, label):
    require(type(value) is int and low <= value <= high, label + ': bounded integer required')

def text(value, label):
    require(type(value) is str and bool(value) and len(value) <= 256 and not any(ord(c) < 32 for c in value), label + ': text required')

def name(value, label):
    require(type(value) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', value) is not None, label + ': safe identifier required')

def resolved(value):
    if isinstance(value, str):
        require(not any(marker in value for marker in ('UNRESOLVED', '{{', '${')), 'unresolved value')
    elif isinstance(value, dict):
        for item in value.values(): resolved(item)
    elif isinstance(value, list):
        for item in value: resolved(item)

# Supported subset: lowercase DNS-style registry (optional decimal port),
# slash-separated distribution repository components, and a lowercase SHA256.
# Tags, IPv6 literals and implicit registries are intentionally unsupported.
IDENTITY_MIN = 1
IDENTITY_MAX = 2147483647


def image_reference(value):
    require(type(value) is str, 'immutable image digest required')
    match = re.fullmatch(
        r'(?P<host>[a-z0-9.-]+)(?::(?P<port>[0-9]{1,5}))?/'
        r'(?P<repo>[a-z0-9._/-]+)@sha256:[a-f0-9]{64}', value)
    require(match is not None, 'immutable image digest required')
    host = match['host']
    require(len(host) <= 253 and all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in host.split('.')), 'invalid registry hostname')
    port = match['port']
    require('.' in host or port is not None or host == 'localhost', 'explicit registry required')
    require(port is None or 1 <= int(port) <= 65535, 'invalid registry port')
    require(len(match['repo']) <= 255 and all(
        re.fullmatch(r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*', part)
        for part in match['repo'].split('/')), 'invalid repository component')

def validate_manifest(m):
    resolved(m)
    shape(m, 'schema_version component_id image rootless process filesystem isolation resources lifecycle dependencies secret_refs environment external_effects', 'manifest')
    require(m['schema_version'] == '1.0', 'unsupported schema')
    name(m['component_id'], 'component_id')
    image_reference(m['image'])
    require(m['rootless'] is True, 'rootless required')
    shape(m['process'], 'uid gid', 'process')
    for key in ('uid', 'gid'):
        integer(m['process'][key], IDENTITY_MIN, IDENTITY_MAX, key)
    fs = m['filesystem']
    shape(fs, 'read_only read_only_tmpfs mounts tmpfs', 'filesystem')
    require(fs['read_only_tmpfs'] is False, 'implicit writable tmpfs forbidden')
    require(fs['read_only'] is True, 'read-only root required; exceptions need separate review')
    require(type(fs['mounts']) is list and type(fs['tmpfs']) is list, 'mount lists required')
    targets = set()
    for mount in fs['mounts']:
        shape(mount, 'type name target uid gid mode backup_ref restore_ref', 'mount')
        require(mount['type'] == 'named_volume', 'host bind mounts forbidden')
        name(mount['name'], 'volume name')
        target = mount['target']
        require(type(target) is str and re.fullmatch(r'/(?:var/lib|data|srv)/[a-z][a-z0-9/-]*', target) is not None and '//' not in target and not target.endswith('/'), 'private state target required')
        require(target not in targets and not any(target.startswith(t + '/') or t.startswith(target + '/') for t in targets), 'overlapping mounts forbidden')
        targets.add(target)
        require(mount['uid'] == m['process']['uid'] and type(mount['uid']) is int and mount['gid'] == m['process']['gid'] and type(mount['gid']) is int, 'volume ownership mismatch')
        require(mount['mode'] == '0700', 'private volume mode required')
        text(mount['backup_ref'], 'backup_ref'); text(mount['restore_ref'], 'restore_ref')
    for tmp in fs['tmpfs']:
        shape(tmp, 'target size_mib noexec nosuid nodev', 'tmpfs')
        require(tmp['target'] in ('/tmp', '/run/app') and tmp['target'] not in targets, 'unsafe or duplicate tmpfs')
        targets.add(tmp['target'])
        integer(tmp['size_mib'], 1, 256, 'tmpfs size')
        require(all(tmp[k] is True for k in ('noexec', 'nosuid', 'nodev')), 'tmpfs hardening required')
    isolation=m['isolation']
    shape(isolation, 'privileged network pid ipc capabilities no_new_privileges seccomp lsm devices sockets', 'isolation')
    require(isolation['privileged'] is False and isolation['no_new_privileges'] is True, 'privilege escalation forbidden')
    require(isolation['network'] == 'none' and isolation['pid'] == 'private' and isolation['ipc'] == 'private', 'private namespaces and no network required')
    require(isolation['capabilities'] == [] and isolation['devices'] == [] and isolation['sockets'] == [], 'capabilities/devices/sockets forbidden')
    require(isolation['seccomp'] == 'runtime-default' and isolation['lsm'] == 'host-enforcing-default', 'default seccomp and enforcing LSM required')
    r=m['resources']; shape(r, 'memory_mib cpu_percent pids disk_mib runtime_seconds', 'resources')
    for key, bounds in {'memory_mib':(16,1536),'cpu_percent':(1,100),'pids':(1,256),'disk_mib':(16,2048),'runtime_seconds':(1,86400)}.items():
        integer(r[key], *bounds, key)
    require(sum(t['size_mib'] for t in fs['tmpfs']) <= r['memory_mib'], 'tmpfs exceeds memory limit')
    lc=m['lifecycle']; shape(lc, 'restart restart_seconds start_seconds stop_seconds start_limit_interval_seconds start_limit_burst health readiness_ref drain_ref rollback_ref', 'lifecycle')
    require(lc['restart'] == 'no', 'bounded one-shot must not automatically restart')
    for key, bounds in {'restart_seconds':(1,60),'start_seconds':(1,300),'stop_seconds':(1,120),'start_limit_interval_seconds':(60,3600),'start_limit_burst':(1,5)}.items():
        integer(lc[key], *bounds, key)
    h=lc['health']; shape(h, 'argv interval_seconds timeout_seconds retries start_seconds', 'health')
    require(type(h['argv']) is list and len(h['argv']) == 1 and type(h['argv'][0]) is str and re.fullmatch(r'/app/[a-z][a-z0-9-]*', h['argv'][0]), 'direct fixed health executable required')
    for key,bounds in {'interval_seconds':(5,300),'timeout_seconds':(1,30),'retries':(1,5),'start_seconds':(1,180)}.items():
        integer(h[key],*bounds,key)
    require(h['timeout_seconds'] < h['interval_seconds'], 'health timeout must be below interval')
    for key in ('readiness_ref','drain_ref','rollback_ref'):
        text(lc[key],key)
    require(type(m['dependencies']) is list and len(set(m['dependencies'])) == len(m['dependencies']), 'unique dependency IDs required')
    for dep in m['dependencies']:
        name(dep,'dependency')
    require(m['component_id'] not in m['dependencies'], 'self dependency forbidden')
    require(type(m['secret_refs']) is list, 'secret reference list required')
    for secret in m['secret_refs']:
        name(secret,'secret reference')
    require(m['environment'] == {'OUTBOUND_EFFECTS':'HOLD'}, 'only fixed nonsecret HOLD environment allowed')
    require(m['external_effects'] == 'disabled', 'external effects must remain disabled')
    return {'valid':True,'evidence_level':'offline_policy_only','launch_authorized':False,'qualification':'NOT_RUN'}

# Deliberately restricted offline syntax; not a replacement for the installed generator.
KEYS = {
 'Unit':set('Description StartLimitIntervalSec StartLimitBurst'.split()),
 'Container':set('Image ContainerName User ReadOnly ReadOnlyTmpfs NoNewPrivileges DropCapability Network Tmpfs Environment HealthCmd HealthInterval HealthTimeout HealthRetries HealthStartPeriod'.split()),
 'Service':set('Restart RestartSec TimeoutStartSec TimeoutStopSec MemoryMax CPUQuota TasksMax RuntimeMaxSec'.split())}

def validate_quadlet(source):
    require(type(source) is str and len(source) <= 32768, 'bounded source required')
    require('UNRESOLVED' not in source and '{{' not in source and '${' not in source, 'unresolved template is not installable')
    require(not any((ord(c) < 32 and c not in '\t\r\n') or 127 <= ord(c) <= 159 or c in '\u2028\u2029' for c in source), 'unsupported control or line separator')
    require(re.search(r'\r(?!\n)', source) is None, 'bare carriage return unsupported')
    parsed={}; section=None
    for line in source.replace('\r\n', '\n').split('\n'):
        line=line.strip(' \t')
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section=line[1:-1]
            require(section in KEYS and section not in parsed, 'unknown or duplicate section')
            parsed[section]={}; continue
        require(section is not None and '=' in line and not line.endswith('\\'), 'invalid syntax')
        key,value=line.split('=',1)
        require(key in KEYS[section] and key not in parsed[section] and bool(value) and '%' not in value.replace('100%',''), 'unknown/duplicate/unsafe key or value')
        parsed[section][key]=value
    require(set(parsed)==set(KEYS) and all(set(parsed[k])==KEYS[k] for k in KEYS), 'all baseline keys required')
    c=parsed['Container']; u=parsed['Unit']; s=parsed['Service']
    image_reference(c['Image'])
    name(c['ContainerName'],'container name')
    require(re.fullmatch(r'[1-9][0-9]{0,9}:[1-9][0-9]{0,9}',c['User']), 'nonroot UID:GID required')
    for key, value in zip(('uid', 'gid'), c['User'].split(':')):
        integer(int(value), IDENTITY_MIN, IDENTITY_MAX, key)
    require(all(c[k]==v for k,v in {'ReadOnly':'true','ReadOnlyTmpfs':'false','NoNewPrivileges':'true','DropCapability':'all','Network':'none'}.items()), 'hardening required')
    require(c['Environment']=='OUTBOUND_EFFECTS=HOLD', 'fixed held environment required')
    require(c['Tmpfs']=='/tmp:rw,nosuid,nodev,noexec,size=64m', 'bounded hardened tmpfs required')
    try:
        health_argv=json.loads(c['HealthCmd'])
    except (ValueError,TypeError) as exc:
        raise PolicyError('JSON exec-form health command required') from exc
    require(type(health_argv) is list and len(health_argv)==1 and type(health_argv[0]) is str and re.fullmatch(r'/app/[a-z][a-z0-9-]*',health_argv[0]), 'fixed JSON exec-form health executable required')
    require(c['HealthInterval']=='30s' and c['HealthTimeout']=='5s' and c['HealthRetries']=='3' and c['HealthStartPeriod']=='30s','bounded health checks required')
    require(u['StartLimitIntervalSec']=='300' and u['StartLimitBurst']=='3','restart rate limit required')
    require(s=={'Restart':'no','RestartSec':'10','TimeoutStartSec':'180','TimeoutStopSec':'60','MemoryMax':'512M','CPUQuota':'100%','TasksMax':'128','RuntimeMaxSec':'3600'},'bounded service policy required')
    return {'valid':True,'evidence_level':'offline_syntax_subset_only','installed_generator':'NOT_RUN','launch_authorized':False}

def load_quadlet(path):
    # Preserve physical line endings so CR/VT/Unicode separator checks cannot be bypassed.
    with Path(path).open('r', encoding='utf-8-sig', newline='') as stream:
        return stream.read()


def load_json(path):
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=unique)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path'); parser.add_argument('--quadlet',action='store_true'); args=parser.parse_args()
    try:
        result=validate_quadlet(load_quadlet(args.path)) if args.quadlet else validate_manifest(load_json(args.path))
        print(json.dumps(result)); raise SystemExit(0)
    except (PolicyError,ValueError,TypeError,KeyError,OSError) as exc:
        print(json.dumps({'valid':False,'launch_authorized':False,'reason':str(exc)})); raise SystemExit(2)
