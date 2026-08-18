"""
core/logging_utils.py
Requirement 3 (hardening): auth tokens are redacted to first/last 4 chars in
logs and never written to JSON output in full.
"""
from __future__ import annotations

import logging
import re
import sys

TOKEN_PATTERNS = [
    re.compile(r"(Bearer\s+)([A-Za-z0-9\-_\.]{8,})", re.IGNORECASE),
    re.compile(r"([\"']?(?:token|access_token|api_key|apikey|secret)[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-_\.]{8,})(['\"]?)", re.IGNORECASE),
]


def redact_token(value: str) -> str:
    """Reduces a token/secret to first4...last4 for safe logging/output."""
    if not value or len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def redact_text(text: str) -> str:
    """Scrubs bearer tokens / secret-looking key=value pairs out of arbitrary text."""
    if not text:
        return text

    def _sub_bearer(m):
        return m.group(1) + redact_token(m.group(2))

    def _sub_kv(m):
        return m.group(1) + redact_token(m.group(2)) + m.group(3)

    out = TOKEN_PATTERNS[0].sub(_sub_bearer, text)
    out = TOKEN_PATTERNS[1].sub(_sub_kv, out)
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(str(record.msg))
        except Exception:
            pass
        return True


def get_logger(name: str, level=logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
