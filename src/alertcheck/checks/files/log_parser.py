"""Access log parsers producing a common record (design §7.4, logs.access).

Each parser yields records lazily so a multi-GB log is processed line by line
without loading it into memory. gzip is read transparently.
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import BinaryIO

_NGINX = re.compile(
    r"(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
_REQUEST = re.compile(r"(?P<method>\S+) (?P<url>\S+)(?: \S+)?")


@dataclass(frozen=True)
class LogRecord:
    ts: dt.datetime | None
    client_ip: str
    method: str
    path: str
    status: int
    bytes: int | None
    user_agent: str = ""
    user: str | None = None


def _int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _parse_clf_time(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _user(value: str | None) -> str | None:
    return value if value and value != "-" else None


def _nginx(lines: Iterable[str]) -> Iterator[LogRecord]:
    for line in lines:
        m = _NGINX.search(line)
        if not m:
            continue
        path = m.group("path")
        yield LogRecord(
            ts=_parse_clf_time(m.group("ts")),
            client_ip=m.group("ip"),
            method=m.group("method"),
            path=path,
            status=int(m.group("status")),
            bytes=_int(m.group("bytes")),
            user_agent=m.group("ua") or "",
            user=_user(m.group("user")),
        )


_JSON_IP = ("remote_addr", "client_ip", "clientIp", "ip", "c-ip")
_JSON_STATUS = ("status", "sc-status", "response_status")
_JSON_BYTES = ("body_bytes_sent", "bytes", "sc-bytes", "response_size")
_JSON_UA = ("http_user_agent", "user_agent", "cs-user-agent", "ua")
_JSON_USER = ("remote_user", "user", "cs-username")
_JSON_TIME = ("time", "timestamp", "@timestamp", "time_iso8601")


def _first(obj: dict, keys: tuple[str, ...]) -> object | None:
    return next((obj[k] for k in keys if k in obj and obj[k] not in ("", "-")), None)


def _json(lines: Iterable[str]) -> Iterator[LogRecord]:
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        method, path = obj.get("method"), obj.get("uri") or obj.get("path")
        if not method and (request := obj.get("request")):
            rm = _REQUEST.match(str(request))
            if rm:
                method, path = rm.group("method"), rm.group("url")
        status = _int(_first(obj, _JSON_STATUS))
        if status is None:
            continue
        yield LogRecord(
            ts=_parse_iso(str(_first(obj, _JSON_TIME)) if _first(obj, _JSON_TIME) else None),
            client_ip=str(_first(obj, _JSON_IP) or ""),
            method=str(method or ""),
            path=str(path or ""),
            status=status,
            bytes=_int(_first(obj, _JSON_BYTES)),
            user_agent=str(_first(obj, _JSON_UA) or ""),
            user=_user(str(_first(obj, _JSON_USER)) if _first(obj, _JSON_USER) else None),
        )


def _alb(lines: Iterable[str]) -> Iterator[LogRecord]:
    for line in lines:
        fields = _split_quoted(line)
        if len(fields) < 13 or fields[0] not in ("http", "https", "h2", "ws", "wss"):
            continue
        client = fields[3].rsplit(":", 1)[0]
        status = _int(fields[8])
        request = fields[12]
        method = path = ""
        rm = _REQUEST.match(request)
        if rm:
            method = rm.group("method")
            url = rm.group("url")
            path = re.sub(r"^https?://[^/]+", "", url) or "/"
        ua = fields[13] if len(fields) > 13 else ""
        yield LogRecord(
            ts=_parse_iso(fields[1]),
            client_ip=client,
            method=method,
            path=path,
            status=status if status is not None else 0,
            bytes=_int(fields[10]),
            user_agent=ua,
        )


def _split_quoted(line: str) -> list[str]:
    tokens = re.findall(r'"[^"]*"|\S+', line.strip())
    return [t[1:-1] if t.startswith('"') and t.endswith('"') else t for t in tokens]


_PARSERS = {
    "nginx_combined": _nginx,
    "apache_combined": _nginx,
    "combined": _nginx,
    "json": _json,
    "jsonl": _json,
    "cloudfront": _json,
    "alb": _alb,
}


def parse_lines(lines: Iterable[str], *, fmt: str) -> Iterator[LogRecord]:
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unknown log format: {fmt!r} (use one of {sorted(_PARSERS)})")
    return parser(lines)


def _decoded_lines(stream: BinaryIO) -> Iterator[str]:
    # peek the gzip magic without consuming it, then stream line by line
    head = stream.read(2)
    stream.seek(0) if stream.seekable() else None
    source: Iterable[bytes]
    if head == b"\x1f\x8b":
        source = gzip.GzipFile(fileobj=_prepend(head, stream) if not stream.seekable() else stream)
    else:
        source = _prepend(head, stream) if not stream.seekable() else stream
    for raw in source:
        yield raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _prepend(head: bytes, stream: BinaryIO) -> BinaryIO:
    import io

    return io.BufferedReader(io.BytesIO(head + stream.read()))  # fallback for non-seekable streams


def parse_stream(stream: BinaryIO, *, fmt: str) -> Iterator[LogRecord]:
    return parse_lines(_decoded_lines(stream), fmt=fmt)
