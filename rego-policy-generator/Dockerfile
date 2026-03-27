FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install OPA with certificate handling
RUN curl --insecure -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.62.1/opa_linux_amd64_static && \
    chmod 755 /usr/local/bin/opa

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY templates/ ./templates/
COPY tests/ ./tests/
COPY docs/ ./docs/
COPY entrypoint.sh ./entrypoint.sh

# Create necessary directories
RUN mkdir -p /app/output /app/workspace

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Set Python path
ENV PYTHONPATH=/app

# Expose port for API
EXPOSE 8080

# Use entrypoint script
ENTRYPOINT ["./entrypoint.sh"]