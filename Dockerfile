# Crawler image: Python 3.12 + Playwright Chromium, runs as a non-root user (DESIGN §5.6).
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS base

ARG PLAYWRIGHT_VERSION=1.63.0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    SCAMHUNTER_HOME=/app

# Browser layer first so code changes don't re-download Chromium.
# Full Chromium (not the headless shell): new headless mode is harder for scam kits to detect.
RUN pip install "playwright==${PLAYWRIGHT_VERSION}" \
    && playwright install --with-deps --no-shell chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

COPY config ./config
COPY data ./data
COPY docker/selftest.py ./docker/selftest.py
# The local mock exchange, for mock mode (`scamhunter agent-mock`); loopback only.
COPY tests/fixtures/mock_exchange ./tests/fixtures/mock_exchange

RUN useradd --create-home --uid 10001 crawler \
    && mkdir -p /app/runs /app/output \
    && chown crawler:crawler /app/runs /app/output
USER crawler

CMD ["scamhunter", "--help"]

# LLM gateway: no browser, only the API client. Holds the API key; the crawler never does.
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS gateway
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore \
    SCAMHUNTER_HOME=/app
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install "anthropic==1.11.0" "pydantic==2.13.5" "pyyaml==6.0.3" && pip install --no-deps .
COPY config ./config
RUN useradd --uid 10002 gateway && mkdir -p /app/llm && chown gateway:gateway /app/llm
USER gateway
CMD ["python", "-m", "scamhunter.llm.gateway"]

# Offline browser tests (make test-browser): same image plus pytest and the tests.
FROM base AS test
USER root
RUN pip install "pytest==9.1.1"
COPY tests ./tests
RUN chown -R crawler:crawler /app/tests
USER crawler
CMD ["pytest", "-q", "-m", "browser", "-p", "no:cacheprovider", "tests/browser"]
