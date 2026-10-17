"""Masking applied to evidence before it is stored or reported (design §10.3).

IP addresses are intentionally left as-is because they are needed for
investigation; reports can redact them separately.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_MASK = "***"

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._~+/=-]+)")
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_ENV_LINE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=)(.*)$")

_ENTROPY_THRESHOLD = 4.0


def _keep4(value: str) -> str:
    return value[:4] + _MASK


def _entropy(value: str) -> float:
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}{_MASK}@{domain}"


def mask_text(text: str) -> str:
    text = _JWT.sub(lambda m: _keep4(m.group(0)), text)
    text = _AWS_KEY.sub(lambda m: _keep4(m.group(0)), text)
    text = _BEARER.sub(lambda m: m.group(1) + _keep4(m.group(2)), text)
    text = _EMAIL.sub(lambda m: mask_email(m.group(0)), text)
    return _LONG_TOKEN.sub(
        lambda m: _keep4(m.group(0)) if _entropy(m.group(0)) >= _ENTROPY_THRESHOLD else m.group(0),
        text,
    )


def mask_env_content(content: str) -> str:
    """Keep variable names of a dotenv-style file and hide every value."""
    out = []
    for line in content.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        newline = line[len(body) :]
        stripped = body.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        match = _ENV_LINE.match(body)
        if match is None:
            out.append(_MASK + newline)
        elif match.group(2).strip() == "":
            out.append(match.group(1) + newline)
        else:
            out.append(match.group(1) + _MASK + newline)
    return "".join(out)


def mask_evidence(value: Any) -> Any:
    """Return a masked deep copy of an evidence structure."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {k: mask_evidence(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(mask_evidence(v) for v in value)
    return value
