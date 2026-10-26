"""Defense-in-depth redaction for synthetic prompt/log/artifact contracts.

Do not feed real secrets to this fixture. Unknown unlabeled secret formats cannot
be detected reliably; allowlisted structured output is the primary boundary.
"""
import json
import re

MARKER = "[REDACTED]"
# Match recognized label components, not words such as client_secretary.
SENSITIVE_LABEL = (r"password|passwd|authorization|private[_-]?key|api[_-]?key|"
                   r"client[_-]?secret|access[_-]?token|refresh[_-]?token|"
                   r"smtp[_-]?credential|sip[_-]?credential|payment[_-]?credential|"
                   r"deploy[_-]?token|payment[_-]?token")
SENSITIVE_KEY = re.compile(r"(?i)(?<![A-Za-z0-9])(?:" + SENSITIVE_LABEL + r"|token|secret)(?![A-Za-z0-9])")
# The same recognized assignment labels drive scalar and composite handling.
ASSIGNMENT_LABEL = (SENSITIVE_LABEL + r"|token|secret|smtp[_-]?password|sip[_-]?password")
COMPOSITE_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:" + ASSIGNMENT_LABEL + r")(?![A-Za-z0-9])(?:\\?[\"'])?\s*[=:]\s*[\[{]")
# Inspect standard JSON-quoted assignment keys even if the enclosing message is
# truncated or embedded. Decode only each bounded key, never guess nested values.
MAX_JSON_TEXT = 65536
PATTERNS = [
    # A recognized private-key header owns its body until the matching footer
    # or EOF. A different/truncated footer must not expose the remaining body.
    re.compile(r"-----BEGIN (?P<pem_kind>[A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END (?P=pem_kind)-----|\Z)", re.S),
    re.compile(r"AGE-SECRET-KEY-[A-Z0-9]+", re.I),
    re.compile(r"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{16,}"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.~=:-]+"),
    re.compile(r"(?i)(?:postgres(?:ql)?|mysql|smtp|sips?)://[^\s/@:]*:[^\s/@]+@"),
    # A quoted assignment either closes normally or consumes through end of
    # input, including a dangling escape. It must not fall back to one token.
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:" + ASSIGNMENT_LABEL + r")(?![A-Za-z0-9])[\"']?\s*[=:]\s*"
               r"(?:\"(?:\\[\s\S]|[^\"\\])*(?:\"|\\?\Z)"
               r"|'(?:\\[\s\S]|[^'\\])*(?:'|\\?\Z)|(?![\"'])[^\s,;]+)"),
]



def _invalid_json_constant(value):
    raise ValueError("not standard JSON")

def _has_sensitive_json_key(value):
    # One forward scan avoids repeatedly rescanning unterminated quoted text.
    index = 0
    while index < len(value):
        if value[index] != '"':
            index += 1
            continue
        start = index
        index += 1
        while index < len(value):
            if value[index] == '\\':
                index += 2
            elif value[index] == '"':
                index += 1
                break
            else:
                index += 1
        else:
            return False
        end = index
        while index < len(value) and value[index] in ' \t\r\n':
            index += 1
        if index < len(value) and value[index] == ':':
            try:
                key = json.loads(value[start:end])
            except (ValueError, TypeError, RecursionError):
                key = None
            if type(key) is str and SENSITIVE_KEY.search(key):
                return True
        # Always reconsider the closing boundary, even when the preceding
        # candidate had a colon or was invalid/non-sensitive. Each span's
        # interior is visited once; end-1 strictly advances beyond start.
        index = end - 1
    return False

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
        if len(value) > MAX_JSON_TEXT:
            return MARKER
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value, parse_constant=_invalid_json_constant)
            except RecursionError:
                return MARKER
            except (ValueError, TypeError):
                return MARKER  # Malformed JSON boundaries cannot be trusted.
            else:
                if type(parsed) in (dict, list):
                    return json.dumps(redact(parsed, depth=depth + 1), ensure_ascii=False)
        # Escaped quotes make embedded assignment boundaries ambiguous. Prefer
        # bounded whole-message redaction over speculative recovery parsing.
        if '\\"' in value and (':' in value or '=' in value):
            return MARKER
        # A scalar regex cannot delimit a nested object/array safely. Discard
        # the entire unparseable/embedded message rather than leak its tail.
        if COMPOSITE_ASSIGNMENT.search(value) or _has_sensitive_json_key(value):
            return MARKER
        for pattern in PATTERNS:
            value = pattern.sub(MARKER, value)
        return value
    if value is None or type(value) in (bool, int, float):
        return value
    return MARKER  # Never stringify opaque objects/bytes into logs.






