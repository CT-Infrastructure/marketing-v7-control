"""Local synthetic-only exports; exclusive controller-owned root, no concurrent writers."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import uuid

POLICY = Path(__file__).resolve().parents[1] / 'fixtures/shared/retention.json'
STAMP = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z'

def instant(value):
    if not isinstance(value, str) or not re.fullmatch(STAMP, value):
        raise ValueError('canonical UTC microsecond timestamp required')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)

class Exports:
    def __init__(self, root, owner, clock, policy=None):
        self.root = Path(root)
        if not self.root.is_absolute() or self.root.anchor == str(self.root):
            raise ValueError('absolute disposable child root required')
        for part in [self.root, *self.root.parents]:
            if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
                raise ValueError('linked root forbidden')
        if not self.root.is_dir() or self.root.resolve() != self.root:
            raise ValueError('canonical existing root required')
        if not isinstance(owner, str) or not re.fullmatch('[a-f0-9]{32}', owner):
            raise ValueError('controller supplied ownership id required')
        policy = json.loads(POLICY.read_text(encoding='utf-8-sig')) if policy is None else policy
        if not isinstance(policy, dict):
            raise ValueError('policy object required')
        for key, expected in [('exported_test_artifact_max_age_days',7), ('exported_test_artifact_max_bytes',1048576)]:
            if type(policy.get(key)) is not int or policy[key] != expected:
                raise ValueError('invalid retention bound')
        for key in ('production_credentials_allowed', 'raw_payload_export_allowed'):
            if policy.get(key) is not False:
                raise ValueError('unsafe policy')
        self.root_identity = (self.root.stat().st_dev, self.root.stat().st_ino)
        self.owner, self.clock = owner, clock
        self.pattern = re.compile(r'synthetic-' + owner + r'-([0-9a-f]{32})\.(json|partial)')
        self.now()

    def now(self):
        # Controller must exclude concurrent mutations; these checks also reject
        # a replaced root between calls, rather than following it elsewhere.
        for part in [self.root, *self.root.parents]:
            if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
                raise ValueError('linked root forbidden')
        info = self.root.stat()
        if self.root.resolve() != self.root or (info.st_dev, info.st_ino) != self.root_identity:
            raise ValueError('artifact root replaced')
        return instant(self.clock())

    def regular(self, path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink()
                or getattr(info, 'st_file_attributes', 0) & 0x400
                or (hasattr(os, 'getuid') and info.st_uid != os.getuid())):
            raise ValueError('single-link regular owned file required')
        if hasattr(path, 'is_junction') and path.is_junction():
            raise ValueError('junction forbidden')
        return info

    def export(self, case, repeats=0):
        # Closed synthetic vocabulary, not a generic secret/PII detector.
        if case not in ('size-boundary', 'retention-boundary', 'synthetic-pass', 'synthetic-fail'):
            raise ValueError('unknown synthetic case')
        if type(repeats) is not int or not 0 <= repeats <= 1048576:
            raise ValueError('invalid synthetic padding count')
        created = self.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        data = json.dumps(dict(case=case, created_at=created, padding='s'*repeats), separators=(',', ':')).encode()
        if len(data) > 1048576:
            raise ValueError('oversize export')
        stem = 'synthetic-' + self.owner + '-' + uuid.uuid4().hex
        partial, final = self.root/(stem+'.partial'), self.root/(stem+'.json')
        published = False
        created_file = False
        try:
            with partial.open('xb') as stream:
                created_file = True
                if stream.write(data) != len(data):
                    raise OSError('short write')
                stream.flush()
                os.fsync(stream.fileno())
            self.regular(partial)
            # Exclusive publication: never replace a sibling, even on a name collision.
            if final.exists() or final.is_symlink():
                raise FileExistsError('publication collision')
            os.rename(partial, final)
            published = True
        except BaseException:
            # Cleanup failure propagates; no success receipt is returned.
            for path, owned in ((partial, created_file), (final, published)):
                if owned and path.exists():
                    path.unlink()
            raise
        return dict(path=final.name, bytes=len(data), created_at=created)

    def sweep(self):
        now = self.now()
        expired = []
        # Validate every owned candidate before any deletion. Never recurse.
        for path in self.root.iterdir():
            if not self.pattern.fullmatch(path.name):
                continue
            info = self.regular(path)
            if info.st_size > 1048576:
                raise ValueError('oversize owned artifact')
            with path.open('rb') as stream:
                raw = stream.read(1048577)
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result: raise ValueError('duplicate field')
                    result[key] = value
                return result
            doc = json.loads(raw, object_pairs_hook=unique)
            if set(doc) != {'case','created_at','padding'} or doc['case'] not in ('size-boundary','retention-boundary','synthetic-pass','synthetic-fail') or not isinstance(doc['padding'], str) or set(doc['padding']) - {'s'}:
                raise ValueError('invalid synthetic artifact')
            created = instant(doc['created_at'])
            if created > now:
                raise ValueError('future artifact')
            if now - created >= timedelta(days=7):
                expired.append(path)
        removed = []
        for path in expired:
            self.regular(path)
            path.unlink()  # failure propagates, never a false success receipt
            removed.append(path.name)
        return removed
