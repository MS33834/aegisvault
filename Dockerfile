# Stage 1: Build — compile Python wheels and install dependencies
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==${POETRY_VERSION}

COPY pyproject.toml poetry.lock README.md ./
COPY aegisvault ./aegisvault

# Install production-only dependencies; the GUI and semantic extras are excluded.
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

# Stage 2: Runtime — slim image with only bubblewrap and installed packages
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user
RUN groupadd -r aegisvault && useradd -r -g aegisvault -u 1000 -d /app aegisvault

# Copy installed Python site-packages including the aegisvault console script
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=aegisvault:aegisvault pyproject.toml README.md ./
COPY --chown=aegisvault:aegisvault aegisvault ./aegisvault

# Fix /app ownership for non-root user
RUN chown -R aegisvault:aegisvault /app

USER aegisvault

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD aegisvault --help || exit 1

ENTRYPOINT ["aegisvault"]
CMD ["--no-tray"]
