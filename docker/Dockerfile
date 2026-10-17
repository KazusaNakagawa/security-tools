# alertcheck image (design §4).
# Every external image is pinned by tag AND digest: a re-pushed tag cannot change the build.
# To bump, pick the new tag, then take its index digest with:
#   docker buildx imagetools inspect <image>:<tag>   (the "Digest:" line)
FROM aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 AS trivy
FROM ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0 AS osv
FROM projectdiscovery/nuclei:v3.4.10@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97 AS nuclei
FROM ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec AS uv

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
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
