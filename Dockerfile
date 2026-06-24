FROM python:3.11-slim

# Run Python without bytecode and with unbuffered stdout for cleaner container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3

WORKDIR /app

# Install build dependencies for compiled wheels (cryptography, argon2-cffi) and
# bubblewrap for the Linux sandbox.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin Poetry to the same version used in CI.
RUN pip install --no-cache-dir poetry==${POETRY_VERSION}

# Create an unprivileged user to run the application.
RUN groupadd -r aegisvault && useradd -r -g aegisvault -u 1000 -d /app aegisvault

# Copy only the files needed for dependency resolution first to maximise cache.
COPY --chown=aegisvault:aegisvault pyproject.toml poetry.lock README.md ./
COPY --chown=aegisvault:aegisvault aegisvault ./aegisvault

# Install production dependencies only; the GUI extra is intentionally excluded
# to keep the container image small and headless.
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

USER aegisvault

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD aegisvault --help || exit 1

ENTRYPOINT ["aegisvault"]
CMD ["--help"]
