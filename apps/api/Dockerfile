FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download SpaCy language model for Presidio PII/PHI detection.
# Using 'sm' (small) model to stay within the ≤50ms per-request overhead target.
# This is baked into the image layer so workers load it from disk, not the network.
RUN python -m spacy download en_core_web_sm

# Copy source code
COPY . .

RUN addgroup --system authclaw && \
    adduser --system --ingroup authclaw authclaw && \
    chown -R authclaw:authclaw /app

USER authclaw

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
