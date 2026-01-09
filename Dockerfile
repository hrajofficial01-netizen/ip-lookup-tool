FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libevent-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /root/.local /usr/local          
COPY . .
RUN chmod +x startup.sh
ENV PATH=/usr/local/bin:$PATH PYTHONPATH=/app PYTHONUNBUFFERED=1  
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE $PORT
HEALTHCHECK CMD curl -f http://localhost:${PORT}/health || exit 1
CMD ["./startup.sh"]
