# Crawler image: Python 3.12 + Playwright Chromium, runs as a non-root user (DESIGN §5.6).
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

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

RUN useradd --create-home --uid 10001 crawler \
    && mkdir -p /app/runs /app/output \
    && chown crawler:crawler /app/runs /app/output
USER crawler

CMD ["scamhunter", "--help"]
