# syntax=docker/dockerfile:1
# Base images are pinned. See docs/adr/0002-dependency-pins.md.

FROM python:3.12.15-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app

# Dependencies first, so source edits do not invalidate this layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.12.15-slim-trixie AS runtime
RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent --no-create-home keystone
COPY --from=build /app/.venv /app/.venv
# The stdio demo upstream (`python -m examples.upstreams.echo_server`) runs from /app.
WORKDIR /app
COPY examples ./examples
# The policies Keystone starts with, read from /app/policies unless policy.root says otherwise.
# Compose mounts the working copy over them, so an edit on the host is a reload away.
COPY policies ./policies
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1
USER keystone
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["keystone"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
