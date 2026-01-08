# Multi-stage build for Cloud Run IOC Lookup Service (with your startup.sh)
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir --only-binary=all -r requirements.txt

# Runtime stage
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .

# Make startup script executable
COPY startup.sh .
RUN chmod +x startup.sh

ENV PATH=/root/.local/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE $PORT

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Use your existing startup.sh
CMD ["./startup.sh"]
