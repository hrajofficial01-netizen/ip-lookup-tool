# Use a specific slim Python base image for lightweight builds
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Install build dependencies and clean apt cache in one step to keep image small
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first to leverage build cache if code changes
COPY requirements.txt .

# Install Python dependencies (+ gevent for concurrency)
RUN pip install --no-cache-dir gunicorn gevent aiohttp flask-caching -r requirements.txt

# Copy application source code (last step to utilize caching)
COPY . .

# Fix your startup.sh permissions (your Windows git issue)
RUN chmod +x startup.sh

# Expose Cloud Run REQUIRED port
EXPOSE 8080

# Ensure Python output is unbuffered (logs show immediately)
ENV PYTHONUNBUFFERED=1

# Use startup.sh instead of direct gunicorn (DB migrations + error handling)
CMD ["./startup.sh"]
