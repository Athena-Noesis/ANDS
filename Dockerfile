# ANDS Toolkit Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies for cryptography and networking
RUN apt-get update && apt-get install -y \
    libssl-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY tools/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the toolkit code
COPY . .

# Set entrypoint to the scanner by default
ENTRYPOINT ["python3", "tools/ands_scan.py"]
CMD ["--help"]
