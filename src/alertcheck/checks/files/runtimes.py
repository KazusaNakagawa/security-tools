"""Detect language runtimes and base images a repository declares, for EOL checks."""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_VERSION = re.compile(r"(\d+(?:\.\d+){0,2})")
_SKIP_DIRS = {
    "node_modules",
    "vendor",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".next",
}
_MAX_DEPTH = 4

_IMAGES = {
    "php": "php",
    "python": "python",
    "node": "nodejs",
    "ruby": "ruby",
    "golang": "go",
    "nginx": "nginx",
    "httpd": "apache-http-server",
    "tomcat": "tomcat",
    "alpine": "alpine-linux",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "eclipse-temurin": "eclipse-temurin",
    "postgres": "postgresql",
    "mysql": "mysql",
    "redis": "redis",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
}
_DEBIAN_CODENAMES = {
    "jessie": "8",
    "stretch": "9",
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
}


@dataclass(frozen=True)
class Runtime:
    product: str
    version: str
    source: str


def _first_version(text: str) -> str | None:
    match = _VERSION.search(text)
    return match.group(1) if match else None


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _from_composer_lock(path: Path) -> Iterator[tuple[str, str]]:
    data = _read_json(path) or {}
    for key in ("platform-overrides", "platform"):
        php = (data.get(key) or {}).get("php") if isinstance(data.get(key), dict) else None
        if php and (v := _first_version(php)):
            yield "php", v
            return


def _from_composer_json(path: Path) -> Iterator[tuple[str, str]]:
    data = _read_json(path) or {}
    php = (data.get("require") or {}).get("php")
    if php and (v := _first_version(php)):
        yield "php", v


def _from_package_json(path: Path) -> Iterator[tuple[str, str]]:
    data = _read_json(path) or {}
    engines = data.get("engines")
    node = engines.get("node") if isinstance(engines, dict) else None
    if node and (v := _first_version(node)):
        yield "nodejs", v


def _from_pyproject(path: Path) -> Iterator[tuple[str, str]]:
    try:
        data = tomllib.loads(_read_text(path))
    except tomllib.TOMLDecodeError:
        return
    spec = (data.get("project") or {}).get("requires-python")
    if spec and (v := _first_version(spec)):
        yield "python", v


def _single_version(product: str):
    def parse(path: Path) -> Iterator[tuple[str, str]]:
        if v := _first_version(_read_text(path)):
            yield product, v

    return parse


def _from_gemfile_lock(path: Path) -> Iterator[tuple[str, str]]:
    match = re.search(r"RUBY VERSION\s+ruby (\d+(?:\.\d+){0,2})", _read_text(path))
    if match:
        yield "ruby", match.group(1)


def _from_go_mod(path: Path) -> Iterator[tuple[str, str]]:
    match = re.search(r"^go (\d+(?:\.\d+){0,2})", _read_text(path), re.MULTILINE)
    if match:
        yield "go", match.group(1)


def _from_dockerfile(path: Path) -> Iterator[tuple[str, str]]:
    for line in _read_text(path).splitlines():
        tokens = line.strip().split()
        if len(tokens) < 2 or tokens[0].upper() != "FROM":
            continue
        refs = [t for t in tokens[1:] if not t.startswith("--")]
        if not refs or "$" in refs[0] or refs[0] == "scratch":
            continue
        ref = refs[0].split("@", 1)[0]
        name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
        image = name.rsplit("/", 1)[-1]
        product = _IMAGES.get(image)
        if not product or not tag:
            continue
        lead = re.match(r"(\d+(?:\.\d+){0,2})", tag)
        if lead:
            yield product, lead.group(1)
        for codename, version in _DEBIAN_CODENAMES.items():
            if (
                re.search(rf"(^|[-_.]){codename}($|[-_.])", tag)
                and product != "debian"
                or product == "debian"
                and tag.startswith(codename)
            ):
                yield "debian", version
        alpine = re.search(r"alpine(\d+\.\d+)", tag)
        if alpine and product != "alpine-linux":
            yield "alpine-linux", alpine.group(1)


_PARSERS = {
    "composer.lock": _from_composer_lock,
    "composer.json": _from_composer_json,
    "package.json": _from_package_json,
    "pyproject.toml": _from_pyproject,
    ".python-version": _single_version("python"),
    "runtime.txt": _single_version("python"),
    ".nvmrc": _single_version("nodejs"),
    ".node-version": _single_version("nodejs"),
    ".php-version": _single_version("php"),
    ".ruby-version": _single_version("ruby"),
    "Gemfile.lock": _from_gemfile_lock,
    "go.mod": _from_go_mod,
}


def _parser_for(name: str):
    if name in _PARSERS:
        return _PARSERS[name]
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return _from_dockerfile
    return None


def _walk(root: Path) -> Iterator[Path]:
    base_depth = len(root.parts)
    for current, dirs, files in os.walk(root):
        depth = len(Path(current).parts) - base_depth
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and depth < _MAX_DEPTH]
        for name in files:
            yield Path(current) / name


def detect_runtimes(path: Path) -> list[Runtime]:
    if path.is_file():
        files, root = [path], path.parent
    elif path.is_dir():
        files, root = list(_walk(path)), path
    else:
        return []
    found: list[Runtime] = []
    for file in sorted(files):
        parser = _parser_for(file.name)
        if parser is None:
            continue
        source = file.relative_to(root).as_posix()
        for product, version in parser(file):
            runtime = Runtime(product, version, source)
            if runtime not in found:
                found.append(runtime)
    return found
