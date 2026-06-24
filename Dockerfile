FROM python:3.11-slim

WORKDIR /app

# Install build dependencies for compiled wheels (cryptography, argon2-cffi).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin Poetry to the same version used in CI.
RUN pip install --no-cache-dir poetry==1.8.3

# Copy only the files needed for dependency resolution first to maximise cache.
COPY pyproject.toml poetry.lock README.md ./
COPY aegisvault ./aegisvault

# Install production dependencies only; the GUI extra is intentionally excluded
# to keep the container image small and headless.
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

ENTRYPOINT ["aegisvault"]
CMD ["--help"]
