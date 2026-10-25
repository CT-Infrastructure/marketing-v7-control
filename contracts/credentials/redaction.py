"""Defense-in-depth redaction for synthetic prompt/log/artifact contracts.

Do not feed real secrets to this fixture. Unknown unlabeled secret formats cannot
be detected reliably; allowlisted structured output is the primary boundary.
"""
import re

MARKER = "[REDACTED]"
PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----.*?-----END (?:[A-Z0-9 ]*PRIVATE KEY)-----", re.S),
    re.compile(r"AGE-SECRET-KEY-[A-Z0-9]+", re.I),
    re.compile(r"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{16,}"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.~=:-]+"),
    re.compile(r"(?i)(?:postgres(?:ql)?|mysql|smtp|sips?)://[^\s/@:]+:[^\s/@]+@"),
    re.compile(r"(?i)\b(?:password|passwd|token|api[_-]?key|client[_-]?secret|smtp[_-]?password|sip[_-]?password|payment[_-]?token)[\"']?\s*[=:]\s*(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;]+)"),
]
SENSITIVE_KEY = re.compile(r"(?i)(?:password|passwd|authorization|private[_-]?key|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|smtp[_-]?credential|sip[_-]?credential|payment[_-]?credential|deploy[_-]?token|^token$|^secret$)")


def redact(value, *, depth=0):
    if depth > 12:
        return MARKER
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                return MARKER
            safe_key = redact(key, depth=depth + 1)
            result[safe_key] = MARKER if SENSITIVE_KEY.search(key) else redact(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, depth=depth + 1) for item in value]
    if type(value) is str:
        for pattern in PATTERNS:
            value = pattern.sub(MARKER, value)
        return value
    if value is None or type(value) in (bool, int, float):
        return value
    return MARKER  # Never stringify opaque objects/bytes into logs.
