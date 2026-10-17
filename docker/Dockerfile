# alertcheck image (design §4). Tool versions are pinned; bump them deliberately.
FROM aquasec/trivy:0.76.0 AS trivy
FROM ghcr.io/google/osv-scanner:v2.7.0 AS osv
FROM projectdiscovery/nuclei:v3.4.10 AS nuclei
FROM ghcr.io/astral-sh/uv:0.10.12 AS uv

FROM python:3.13-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=build /opt/venv /opt/venv

# Every tool keeps its cache under $HOME, which compose mounts as a volume, so the
# root filesystem can stay read-only.
RUN useradd --uid 10001 --create-home --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
 && mkdir -p /workspace /home/scanner/.cache/alertcheck \
 && chown -R scanner:scanner /workspace /home/scanner
ENV PATH=/opt/venv/bin:$PATH \
    HOME=/home/scanner \
    ALERTCHECK_CACHE=/home/scanner/.cache/alertcheck \
    TRIVY_CACHE_DIR=/home/scanner/.cache/trivy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER scanner
WORKDIR /workspace
ENTRYPOINT ["alertcheck"]
CMD ["--help"]
