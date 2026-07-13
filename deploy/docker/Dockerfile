FROM python:3.13-slim

LABEL org.opencontainers.image.title="Sovereignty AI Gate"
LABEL org.opencontainers.image.description="User-rooted authority framework for deterministic, offline-first AI governance"
LABEL org.opencontainers.image.source="https://github.com/Appel420/Sovereignty-AI-Gate"

WORKDIR /app

# Install Python package
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e .

# Copy dashboard static files
COPY src/dashboard/ /app/dashboard/

# Non-root user for security
RUN useradd -m -u 1001 sia
USER sia

EXPOSE 8080

# Simple static file server using Python's built-in http.server
CMD ["python3", "-m", "http.server", "8080", "--directory", "/app/dashboard"]
