#!/bin/bash
set -e
export PORT=${PORT:-8080}
echo "🚀 Starting IOC Lookup on PORT $PORT"

# Skip heavy startup tasks - do them lazily
echo "✅ Skipping alembic/pandas warmup for fast startup"

# Start FAST with minimal workers first
exec gunicorn --worker-class=gevent --workers=1 --threads=10 \
  --worker-connections=1000 --timeout=30 --preload \
  --bind=0.0.0.0:$PORT app:app
