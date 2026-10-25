# syntax=docker/dockerfile:1
# Base images are pinned. See docs/adr/0002-dependency-pins.md.
#
# WITH_SCANNER=1 adds the classifier behind the scanner's rules (KS-702, ADR-0011): the extra
# keystone[scanner] (torch for the CPU, transformers) and the model, downloaded now so that the
# container never goes to the network for it. `docker images` shows 3.13 GB with it and 401 MB
# without (Docker Desktop, measured); the model is 738 MB of the difference. Compose builds with it.
# The CI build and a plain `docker build .` do not, and the scanner then runs on its rules alone.

ARG WITH_SCANNER=0

# The docker client, for the containerized stdio upstreams (KS-803), which Keystone starts with
# `docker run`. Only the binary is used: the daemon is the host's, reached through its socket.
FROM docker:29.9.2-cli AS docker-cli

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

# The model, pinned to a revision (keystone.defense.classifier.SPECS), into /opt/hf-cache. What is
# downloaded stays in a build cache, as uv's does, so that an edit in src does not fetch the 738 MB
# again. Only the files of the pinned revision are copied out of it, as files and not as the links
# of the cache (they point into a store of blobs that is shared by every model in it).
# /opt/hf-cache exists either way so that the runtime stage can copy it.
RUN --mount=type=cache,target=/var/cache/keystone-hf \
    mkdir -p /opt/hf-cache \
    && if [ "$WITH_SCANNER" = "1" ]; then \
         snapshot="$(HF_HOME=/var/cache/keystone-hf \
           /app/.venv/bin/python -m keystone.defense.classifier fetch protectai-deberta-v2)" \
         && test -d "$snapshot" \
         && echo "$snapshot" \
         && model="$(basename "$(dirname "$(dirname "$snapshot")")")" \
         && mkdir -p "/opt/hf-cache/hub/$model/snapshots" \
         && cp -aL "$snapshot" "/opt/hf-cache/hub/$model/snapshots/" \
         && find "/opt/hf-cache/hub/$model/snapshots" -name '*.safetensors' -size +1M | grep -q .; \
       fi \
    && chmod -R a+rX /opt/hf-cache

FROM python:3.12.15-slim-trixie AS runtime
RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent --no-create-home keystone
COPY --from=build /app/.venv /app/.venv
COPY --from=build /opt/hf-cache /opt/hf-cache
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
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
