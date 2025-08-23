# Use official Python 3.11 slim image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Install system dependencies required to build psycopg2
RUN apt-get update && apt-get install -y libpq-dev gcc

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project into container
COPY . .

# Expose the port your app uses (adjust if different)
EXPOSE 5000

ENV PYTHONUNBUFFERED=1

# Command to run your app (update app.py if your main script is different)
CMD ["python", "app.py"]
