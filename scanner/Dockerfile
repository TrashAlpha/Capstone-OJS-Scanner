# ══════════════════════════════════════════════════════════════
# Stage 1: Build Nuclei dari source
# ══════════════════════════════════════════════════════════════
FROM golang:1.25-alpine AS nuclei-builder

RUN apk add --no-cache git \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ══════════════════════════════════════════════════════════════
# Stage 2: Python runtime + Nuclei binary
# ══════════════════════════════════════════════════════════════
FROM python:3.10-slim

# Copy Nuclei binary dari stage 1
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei

# Verify Nuclei installation
RUN nuclei -version || echo "Nuclei installed"

WORKDIR /app

# Install Python dependencies dulu (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Run Flask app
CMD ["python", "app.py"]
