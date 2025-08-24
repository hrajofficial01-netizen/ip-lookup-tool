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

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code (last step to utilize caching)
COPY . .

# Expose the port your app will run on (change if needed)
EXPOSE 5000

# Ensure Python output is unbuffered (logs show immediately)
ENV PYTHONUNBUFFERED=1

# Run your application (adjust if your entrypoint changes)
CMD ["python", "app.py"]
