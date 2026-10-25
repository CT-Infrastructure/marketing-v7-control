"""Verify F15 canonical UTF-8/LF text hashes; no mutation, Git or networking."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

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


def read_contained_file(root, relative):
    """Reject links, link parents, escapes and nonregular files before reading."""
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts or "\\" in relative or ":" in relative:
        raise ValueError("unsafe artifact path")
    path = root
    for index, part in enumerate(rel.parts):
        path = path / part
        mode = path.lstat().st_mode
        # Junctions are link-like directories on Windows and are also forbidden.
        if stat.S_ISLNK(mode) or getattr(path, "is_junction", lambda: False)():
            raise ValueError("linked input is forbidden")
        required_type = stat.S_ISREG if index == len(rel.parts) - 1 else stat.S_ISDIR
        if not required_type(mode):
            raise ValueError("input is not a contained regular file")
    if not path.resolve(strict=True).is_relative_to(root):
        raise ValueError("input escaped root")
    return path.read_bytes()


def verify(root, *, normalize_crlf=False):
    root = Path(root).absolute()
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)() or not root.is_dir():
        raise ValueError("root must be an unlinked directory")
    root = root.resolve(strict=True)
    raw = read_contained_file(root, "docs/decisions/site/evidence-manifest.json")
    # Pass text, not bytes: json.loads(bytes) auto-detects UTF-16/32.
    text = canonical_bytes(raw, normalize_crlf=normalize_crlf).decode("utf-8", errors="strict")
    manifest = json.loads(text, object_pairs_hook=reject_duplicates)
    if type(manifest) is not dict:
        raise ValueError("manifest must be an object")
    if manifest.get("hash_policy") != POLICY or manifest.get("manifest_excludes_itself") is not True:
        raise ValueError("unsupported hash policy")
    hashes = manifest.get("artifact_hashes")
    if type(hashes) is not dict or set(hashes) != ARTIFACT_PATHS:
        raise ValueError("artifact coverage differs from F15 contract")
    for relative, expected in hashes.items():
        if type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None:
            raise ValueError("invalid digest")
        actual = hashlib.sha256(canonical_bytes(read_contained_file(root, relative), normalize_crlf=normalize_crlf)).hexdigest()
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
