FROM python:3.11-slim

WORKDIR /app

# Install lightweight system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy codebase and trained models
COPY . .

# Hugging Face Spaces uses 7860; Render/cloud platforms provide $PORT
ENV PORT=7860
ENV PYTHONPATH=/app

EXPOSE 7860 8000

# Launch all-in-one FastAPI application (serves both API & Frontend Dashboard)
CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
