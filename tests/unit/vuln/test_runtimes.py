from pathlib import Path

import pytest

from alertcheck.checks.files.runtimes import Runtime, detect_runtimes

REPOS = Path(__file__).parents[2] / "fixtures" / "repos"


def as_set(runtimes):
    return {(r.product, r.version, r.source) for r in runtimes}


def test_legacy_php_repo():
    found = as_set(detect_runtimes(REPOS / "legacy-php"))
    assert ("php", "7.4", "composer.lock") in found
    assert ("php", "7.4", "Dockerfile") in found
    assert ("debian", "10", "Dockerfile") in found  # buster
    assert ("nginx", "1.25", "Dockerfile") in found


def test_node_versions_and_vendor_dirs_are_skipped():
    found = as_set(detect_runtimes(REPOS / "modern-node"))
    assert found == {("nodejs", "20", "package.json"), ("nodejs", "14.21.3", ".nvmrc")}


@pytest.mark.parametrize(
    "name,content,expected",
    [
        (".python-version", "3.8.18\n", ("python", "3.8.18")),
        ("pyproject.toml", '[project]\nrequires-python = ">=3.9,<4"\n', ("python", "3.9")),
        ("runtime.txt", "python-3.7.12\n", ("python", "3.7.12")),
        (".ruby-version", "ruby-2.7.2\n", ("ruby", "2.7.2")),
        ("Gemfile.lock", "GEM\n\nRUBY VERSION\n   ruby 3.0.6p216\n", ("ruby", "3.0.6")),
        ("go.mod", "module x\n\ngo 1.19\n", ("go", "1.19")),
        ("composer.json", '{"require": {"php": ">=8.1"}}', ("php", "8.1")),
        (".php-version", "8.0\n", ("php", "8.0")),
    ],
)
def test_single_files(tmp_path, name, content, expected):
    (tmp_path / name).write_text(content)
    assert {(r.product, r.version) for r in detect_runtimes(tmp_path)} == {expected}


@pytest.mark.parametrize(
    "line,expected",
    [
        ("FROM python:3.11-slim-bookworm", {("python", "3.11"), ("debian", "12")}),
        ("FROM --platform=linux/amd64 node:18.19.0 AS build", {("nodejs", "18.19.0")}),
        ("FROM golang:1.20", {("go", "1.20")}),
        ("FROM ubuntu:20.04", {("ubuntu", "20.04")}),
        ("FROM postgres:12", {("postgresql", "12")}),
        ("FROM eclipse-temurin:11-jre", {("eclipse-temurin", "11")}),
        ("FROM registry.example.com/team/php:8.2-fpm", {("php", "8.2")}),
        ("FROM python:latest", set()),
        ("FROM scratch", set()),
        ("FROM ${BASE_IMAGE}", set()),
    ],
)
def test_dockerfile_images(tmp_path, line, expected):
    (tmp_path / "Dockerfile").write_text(line + "\n")
    assert {(r.product, r.version) for r in detect_runtimes(tmp_path)} == expected


def test_unparseable_files_are_ignored(tmp_path):
    (tmp_path / "package.json").write_text("{broken")
    (tmp_path / "composer.lock").write_text("[]")
    assert detect_runtimes(tmp_path) == []


def test_single_file_path(tmp_path):
    lock = tmp_path / "composer.lock"
    lock.write_text('{"platform": {"php": "7.4.*"}}')
    assert detect_runtimes(lock) == [Runtime("php", "7.4", "composer.lock")]


def test_missing_path(tmp_path):
    assert detect_runtimes(tmp_path / "nope") == []
