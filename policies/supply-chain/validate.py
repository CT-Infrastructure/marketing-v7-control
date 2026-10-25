"""Offline lock diagnostics. No downloads, execution, scanning or adoption authority."""
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
REGISTRY=ROOT/'reference/components/component_registry.json'
FORMATS=FormatChecker()
@FORMATS.checks('date-time', raises=(ValueError,TypeError))
def valid_time(value):
    if not isinstance(value,str):return True
    return datetime.fromisoformat(value.replace('Z','+00:00')).tzinfo is not None

def instant(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value):
        raise ValueError('canonical UTC timestamp required')
    return datetime.fromisoformat(value.replace('Z','+00:00'))

def schema_validate(name,value):
    schema=json.loads((HERE/(name+'.schema.json')).read_text())
    Draft202012Validator(schema,format_checker=FORMATS).validate(value)

def known(value):return value!='UNSET'

def check_digest(digest):
    alg,value=digest['algorithm'],digest['value']
    lengths={'sha256':64,'git-sha1':40}
    if alg=='UNSET':
        if value!='UNSET':raise ValueError('digest algorithm/value mismatch')
    elif not isinstance(value,str) or not re.fullmatch('[a-f0-9]{'+str(lengths[alg])+'}',value):
        raise ValueError('noncanonical digest')

def registry_source_bytes():
    """Recover the declared LF source bytes from LF or uniform CRLF checkout.

    No general text normalization: mixed endings and lone CR are rejected.
    The caller hashes these exact recovered bytes against the unchanged lock.
    """
    raw=REGISTRY.read_bytes()
    if b'\r' not in raw:return raw
    source=raw.replace(b'\r\n',b'\n')
    if b'\r' in source or source.replace(b'\n',b'\r\n')!=raw:
        raise ValueError('registry has unsupported line-ending transformation')
    return source

def require_nonblank(value):
    """UNSET remains explicit; whitespace is never an evidence/identity value."""
    if isinstance(value,str) and not value.strip():
        raise ValueError('blank evidence or identity')
    if isinstance(value,dict):
        for item in value.values():require_nonblank(item)
    elif isinstance(value,list):
        for item in value:require_nonblank(item)

def exact_release(value):
    """Check a concrete version/tag or source hash, including qualified refs.

    Prerelease names and full SHA pins are allowed. Wildcard/range syntax and
    moving terminal tags are not concrete releases, even with a registry prefix.
    """
    if not isinstance(value,str) or not value or value=='UNSET':return False
    if re.search(r'[\s*^~<>=|]',value):return False
    # Explicit branch namespaces stay mutable regardless of terminal spelling.
    if re.search(r'(?:^|/)refs/(?:heads|remotes)/',value,re.I):return False
    if '@' in value:
        # Digest qualification cannot fall back to the generic tag grammar.
        return re.fullmatch(r'[^@]+@sha256:[a-f0-9]{64}',value) is not None
    terminal=re.split(r'[/@:]',value)[-1]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+\-]*',terminal):return False
    if terminal.lower() in ('latest','main','master','head','stable','nightly','x'):
        return False
    if re.search(r'(?:^|\.)[xX](?:$|[.\-+])',terminal):return False
    return True

def validate_entry(e):
    """Shared local invariants; registry/dependency checks remain manifest-wide."""
    schema=json.loads((HERE/'lock-manifest.schema.json').read_text())['properties']['entries']['items']
    Draft202012Validator(schema,format_checker=FORMATS).validate(e)
    require_nonblank(e)
    check_digest(e['digest'])
    if e['purpose']=='engineering-observation' and e['state']!='OBSERVED':
        raise ValueError('engineering observations cannot be adoption candidates')
    # Repository names are not selectors: latest-version may be a valid name.
    origin=e['origin']
    terminal=origin.rsplit('/',1)[-1]
    selector=terminal.rsplit('@',1)[-1] if '@' in terminal else (
        terminal.rsplit(':',1)[-1] if ':' in terminal else None)
    if selector is not None:
        exact_selector=(exact_release('origin@'+selector) if '@' in terminal and selector.startswith('sha256:')
                        else exact_release(selector))
        if not exact_selector:
            raise ValueError('floating origin selector forbidden')
    if known(e['release']):
        # Native package revisions (including Debian pre-release '~') are exact
        # versions, not dependency range expressions. Keep other types strict.
        if e['artifact_type']=='OS_PACKAGE':
            exact=bool(re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*',e['release']))
        else:
            exact=exact_release(e['release'])
        if not exact or e['release'].lower() in ('main','master','head','stable','nightly'):
            raise ValueError('floating release forbidden')
    if '@sha256:' in e['release']:
        release_digest=e['release'].rsplit('@sha256:',1)[1]
        if e['digest']!={'algorithm':'sha256','value':release_digest}:
            raise ValueError('release digest must match locked subject')
    if e['artifact_type'] in ('ACTION','COMFY_NODE') and known(e['release']):
        if not re.fullmatch('[a-f0-9]{40}',e['release']) or e['digest']!={'algorithm':'git-sha1','value':e['release']}:
            raise ValueError('source action/node requires matching full commit')
    if e['artifact_type'] in ('OCI','OS_PACKAGE','APPLICATION','MODEL','TOOL') and known(e['digest']['value']) and e['digest']['algorithm']!='sha256':
        raise ValueError('artifact requires sha256')
    check_digest(e['sbom']['subject_digest'])
    kinds=set()
    for scan in e['scans']:
        if scan['kind'] in kinds:raise ValueError('duplicate scan kind')
        kinds.add(scan['kind']);check_digest(scan['subject_digest'])
        if scan['status']=='PASS' and scan['findings']:raise ValueError('PASS cannot contain findings')
        if scan['status']=='FAIL' and not scan['findings']:raise ValueError('FAIL must identify findings')
        if scan['status']=='NOT_RUN' and scan['findings']:raise ValueError('NOT_RUN cannot invent findings')
        if scan['scanned_at']!='UNSET':instant(scan['scanned_at'])
    if kinds!={'vulnerability','secret'}:raise ValueError('both scan kinds required')

def validate_manifest(manifest):
    schema_validate('lock-manifest',manifest)
    source=registry_source_bytes()
    if manifest['source_registry_sha256']!=hashlib.sha256(source).hexdigest():
        raise ValueError('registry hash mismatch')
    components={c['component_id']:c for c in json.loads(source)['components']}
    ids=set();covered=set()
    for e in manifest['entries']:
        if e['id'] in ids:raise ValueError('duplicate lock id')
        ids.add(e['id']);check_digest(e['digest'])
        cid=e['component_id']
        if cid!='UNSET':
            if cid not in components:raise ValueError('unknown component')
            c=components[cid];covered.add(cid)
            for field in ('name','source_classification','deployment_mode'):
                if e[field]!=c[field]:raise ValueError('source registry drift: '+field)
            if c['source_classification']=='CONDITIONAL_NOT_INSTALLED' and e['state']!='DEFERRED':
                raise ValueError('conditional component promotion requires separate selection')
        elif e['purpose']!='engineering-observation':raise ValueError('unbound component')
        validate_entry(e)
        for scan in e['scans']:
            if known(scan['tool_release']) and not exact_release(scan['tool_release']):
                raise ValueError('floating scanner release forbidden')
    if covered!=set(components):raise ValueError('incomplete component inventory')
    graph={e['id']:e['dependencies'] for e in manifest['entries']}
    visiting=set();visited=set()
    def visit(key):
        if key not in graph:raise ValueError('unknown dependency')
        if key in visiting:raise ValueError('dependency cycle')
        if key in visited:return
        visiting.add(key)
        for dep in graph[key]:visit(dep)
        visiting.remove(key);visited.add(key)
    for key in graph:visit(key)
    return manifest

def validate_exceptions(document,manifest,now):
    schema_validate('exceptions',document);now=instant(now)
    entries={e['id']:e for e in manifest['entries']};ids=set()
    for e in document['exceptions']:
        if e['id'] in ids:raise ValueError('duplicate exception id')
        ids.add(e['id']);check_digest(e['subject_digest'])
        if e['entry_id'] not in entries or e['subject_digest']!=entries[e['entry_id']]['digest'] or e['subject_digest']['algorithm']=='UNSET':
            raise ValueError('exception must bind exact known artifact')
        if e['owner_ref']==e['independent_reviewer_ref']:raise ValueError('exception requires independent reviewer')
        for field in ('owner_ref','independent_reviewer_ref','finding_id','reason','evidence_ref','approval_ref'):
            if e[field]=='UNSET' or not e[field].strip():raise ValueError('exception missing '+field)
        if any(control=='UNSET' or not control.strip() for control in e['compensating_controls']):
            raise ValueError('exception requires concrete compensating controls')
        issued,expires=instant(e['issued_at']),instant(e['expires_at'])
        if not issued<=now<expires or expires-issued>timedelta(days=30):raise ValueError('exception stale, future or exceeds 30 days')
        subject=entries[e['entry_id']]
        validate_entry(subject)
        scan=next(s for s in subject['scans'] if s['kind']=='vulnerability')
        if scan['subject_digest']!=e['subject_digest'] or scan['status']!='FAIL' or e['finding_id'] not in scan['findings']:
            raise ValueError('exception finding not observed on exact failed subject')
    return document

def adoption_blockers(entry,now,exceptions=()):
    """Candidate diagnostics only; empty list is NOT authority to adopt/deploy."""
    validate_entry(entry)
    # Full-manifest binding validation belongs at the integration boundary.
    # Here preserve structural rejection and revalidate every current-entry
    # exception without treating valid exceptions for other entries as ours.
    document={'schema_version':'1.0','exceptions':list(exceptions)}
    schema_validate('exceptions',document)
    exceptions=[e for e in document['exceptions'] if e['entry_id']==entry['id']]
    validate_exceptions({'schema_version':'1.0','exceptions':exceptions}, {'entries':[entry]}, now)
    now=instant(now);reasons=[]
    if entry['state']!='CANDIDATE':reasons.append('not_candidate')
    if entry['purpose']!='component-plan':reasons.append('engineering_or_synthetic_only')
    if entry['source_classification']!='RUNTIME_OR_SELECTED_V7_COMPONENT':reasons.append('selection_required')
    if entry['artifact_type']=='COMPONENT':reasons.append('artifact_type_UNSET')
    for key in ('release','origin','architecture','review_ref','rollback_ref'):
        if not entry[key].strip() or 'UNSET' in entry[key]:reasons.append(key+'_UNSET')
    if entry['digest']['algorithm']=='UNSET':reasons.append('digest_UNSET')
    if entry['license']['review_state']!='REVIEWED' or any(entry['license'][k]=='UNSET' for k in ('expression','evidence_ref')):reasons.append('license_UNSET')
    rights=entry['model_rights']
    if entry['artifact_type'] in ('MODEL','COMFY_NODE'):
        if rights['state']!='REVIEWED' or rights['evidence_ref']=='UNSET':reasons.append('model_rights_UNSET')
    elif rights['state']=='UNSET' or rights['evidence_ref']=='UNSET':reasons.append('rights_disposition_UNSET')
    p=entry['provenance']
    if p['status']!='VERIFIED' or any(p[k]=='UNSET' for k in ('source_ref','attestation_ref','issuer_ref')):reasons.append('provenance_UNVERIFIED')
    sb=entry['sbom']
    if sb['status']!='RECORDED' or sb['format']=='UNSET' or sb['subject_digest']!=entry['digest'] or sb['document_ref']=='UNSET' or sb['document_sha256']=='UNSET':reasons.append('sbom_UNVERIFIED')
    for scan in entry['scans']:
        prefix=scan['kind']
        check_digest(scan['subject_digest'])
        if scan['status']=='PASS' and scan['findings']:reasons.append(prefix+'_contradictory_PASS')
        if not exact_release(scan['tool_release']):
            reasons.append(prefix+'_scanner_release_unpinned')
        if scan['status']=='NOT_RUN':reasons.append(prefix+'_NOT_RUN');continue
        if any(scan[k]=='UNSET' for k in ('tool','tool_release','database_digest','scanned_at','report_ref','report_sha256')) or scan['subject_digest']!=entry['digest']:
            reasons.append(prefix+'_evidence_mismatch');continue
        timestamp=instant(scan['scanned_at'])
        if not now-timedelta(hours=24)<=timestamp<=now:reasons.append(prefix+'_scan_stale')
        for finding in scan['findings']:
            applicable=any(x['status']=='APPROVED' and x['entry_id']==entry['id'] and x['subject_digest']==entry['digest'] and x['scanner_kind']==prefix and x['finding_id']==finding and instant(x['issued_at'])<=now<instant(x['expires_at']) for x in exceptions)
            if not applicable:reasons.append(prefix+'_finding:'+finding)
    return sorted(set(reasons))

def main():
    # Capture once so expiry and freshness use one actual UTC boundary.
    now=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    manifest=validate_manifest(json.loads((ROOT/'locks/supply-chain.lock.json').read_text()))
    document=json.loads((ROOT/'locks/exceptions.json').read_text())
    validate_exceptions(document,manifest,now)
    print(json.dumps({'inventory_entries':len(manifest['entries']),'all_entries_held':all(adoption_blockers(e,now,document['exceptions']) for e in manifest['entries']),'scanning':'NOT_RUN','adoption_authority':False}))

if __name__=='__main__':main()
