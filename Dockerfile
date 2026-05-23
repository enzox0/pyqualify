# Use Python 3.11 base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy project files
COPY pyproject.toml uv.lock ./
COPY pyqualify ./pyqualify

# Install dependencies
RUN uv sync --frozen --no-dev

# Set up directories for reports and config
RUN mkdir -p /app/reports /app/config

# Set environment variables to map to the mounted volumes
ENV PYQUALIFY_CONFIG_DIR=/app/config
ENV PYQUALIFY_REPORT_DIR=/app/reports

# Entry point
ENTRYPOINT ["uv", "run", "pyqualify"]
