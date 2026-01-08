#!/bin/bash
set -e
export PORT=${PORT:-8080}
echo "🚀 Starting IOC Lookup on PORT $PORT"
echo "DB: ${DATABASE_URL:0:-1}..."

# Test imports (your alembic fix)
python -c "from app import app; print('✅ Flask OK')" || exit 1

# Run migrations safely
alembic upgrade head 2>/dev/null || echo "⚠️ Alembic skipped"

echo "✅ Starting Gunicorn (gevent for 100 IOCs)"
exec gunicorn --worker-class=gevent --workers=2 --threads=25 \
  --worker-connections=1000 --timeout=30 --preload \
  --bind=0.0.0.0:$PORT app:app
