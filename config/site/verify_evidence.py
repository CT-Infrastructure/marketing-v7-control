"""Verify F15 canonical UTF-8/LF text hashes; no mutation, Git or networking."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

ARTIFACT_PATHS = frozenset({
    "config/site/site.example.json", "config/site/validate_site.py", "config/site/test_validate_site.py",
    "config/site/verify_evidence.py", "config/site/test_verify_evidence.py",
    "docs/decisions/site/decision-register.json", "docs/decisions/site/README.md", "docs/decisions/site/RUNBOOK.md",
})
POLICY = {"algorithm": "SHA-256", "encoding": "UTF-8 without BOM", "line_endings": "LF",
          "normalization": "Only uniform CRLF may be explicitly converted to LF; mixed endings and lone CR reject; all other bytes preserved",
          "default_verification": "raw canonical LF bytes", "windows_verification_flag": "--normalize-crlf"}


def canonical_bytes(raw, *, normalize_crlf=False):
    if type(raw) is not bytes or type(normalize_crlf) is not bool:
        raise ValueError("invalid input type")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("BOM is not canonical")
    raw.decode("utf-8", errors="strict")
    without_pairs = raw.replace(b"\r\n", b"")
    if b"\r" in without_pairs:
        raise ValueError("lone CR is forbidden")
    if b"\r\n" in raw:
        if b"\n" in without_pairs:
            raise ValueError("mixed line endings are forbidden")
        if not normalize_crlf:
            raise ValueError("CRLF requires explicit normalization")
        return raw.replace(b"\r\n", b"\n")
    return raw


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def verify(root, *, normalize_crlf=False):
    root = Path(root).resolve()
    path = root / "docs/decisions/site/evidence-manifest.json"
    manifest = json.loads(canonical_bytes(path.read_bytes(), normalize_crlf=normalize_crlf), object_pairs_hook=reject_duplicates)
    if manifest.get("hash_policy") != POLICY or manifest.get("manifest_excludes_itself") is not True:
        raise ValueError("unsupported hash policy")
    hashes = manifest.get("artifact_hashes")
    if type(hashes) is not dict or set(hashes) != ARTIFACT_PATHS:
        raise ValueError("artifact coverage differs from F15 contract")
    for relative, expected in hashes.items():
        rel = PurePosixPath(relative)
        if rel.is_absolute() or ".." in rel.parts or "\\" in relative or ":" in relative:
            raise ValueError("unsafe artifact path")
        artifact = root.joinpath(*rel.parts)
        if artifact.is_symlink() or not artifact.is_file() or not artifact.resolve().is_relative_to(root):
            raise ValueError("artifact is not a contained regular file")
        if type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None:
            raise ValueError("invalid digest")
        actual = hashlib.sha256(canonical_bytes(artifact.read_bytes(), normalize_crlf=normalize_crlf)).hexdigest()
        if actual != expected:
            raise ValueError("artifact digest mismatch: " + relative)
    return len(hashes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--normalize-crlf", action="store_true")
    args = parser.parse_args()
    try:
        count = verify(args.root, normalize_crlf=args.normalize_crlf)
    except (ValueError, OSError, UnicodeError):
        print("FAIL: F15 evidence hash verification")
        return 1
    print(f"PASS: {count} F15 canonical text hashes; not runtime or approval evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
