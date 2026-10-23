# syntax=docker/dockerfile:1
# Base images are pinned. See docs/adr/0002-dependency-pins.md.
#
# WITH_SCANNER=1 adds the classifier behind the scanner's rules (KS-702, ADR-0011): the extra
# keystone[scanner] (torch for the CPU, transformers) and the model, downloaded now so that the
# container never goes to the network for it. The model alone is 738 MB. Compose builds with it. The
# CI build and a plain `docker build .` do not, and the scanner then runs on its rules alone.

ARG WITH_SCANNER=0

FROM python:3.12.15-slim-trixie AS build
ARG WITH_SCANNER
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    HF_HOME=/opt/hf-cache
WORKDIR /app

# Dependencies first, so source edits do not invalidate this layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    extra=""; if [ "$WITH_SCANNER" = "1" ]; then extra="--extra scanner"; fi; \
    uv sync --locked --no-dev --no-install-project $extra

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    extra=""; if [ "$WITH_SCANNER" = "1" ]; then extra="--extra scanner"; fi; \
    uv sync --locked --no-dev --no-editable $extra

# The model, pinned to a revision (keystone.defense.classifier.SPECS), into /opt/hf-cache. The
# directory exists either way so that the runtime stage can copy it.
RUN mkdir -p /opt/hf-cache \
    && if [ "$WITH_SCANNER" = "1" ]; then \
         /app/.venv/bin/python -m keystone.defense.classifier fetch protectai-deberta-v2; \
       fi \
    && chmod -R a+rX /opt/hf-cache

FROM python:3.12.15-slim-trixie AS runtime
RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent --no-create-home keystone
COPY --from=build /app/.venv /app/.venv
COPY --from=build /opt/hf-cache /opt/hf-cache
# The stdio demo upstream (`python -m examples.upstreams.echo_server`) runs from /app.
WORKDIR /app
COPY examples ./examples
# The policies Keystone starts with, read from /app/policies unless policy.root says otherwise.
# Compose mounts the working copy over them, so an edit on the host is a reload away.
COPY policies ./policies
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/hf-cache \
    HF_HUB_OFFLINE=1
USER keystone
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["keystone"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
