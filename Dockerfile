# =============================================================================
# YARA REST Service
#
# Multi-stage build:
# - Build stage: Official Go image for compiling
# - Runtime stage: Debian slim with YARA-X
# =============================================================================

# YARA-X version to install
ARG YARA_X_VERSION=1.11.0

# Build stage - use official Go image (Debian-based)
FROM golang:1.23-bookworm AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies (none currently)
RUN go mod download

# Copy source code
COPY *.go ./

# Build the binary - static linking for portability
RUN CGO_ENABLED=0 GOOS=linux go build -o yara-rest .

# =============================================================================
# Runtime stage - Debian slim with YARA-X
# =============================================================================
FROM debian:bookworm-slim

ARG YARA_X_VERSION

# Install curl for healthcheck and YARA-X binary download
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl=7.88.1-10+deb12u14 && \
    rm -rf /var/lib/apt/lists/*

# Download and install YARA-X binary
# The release is a gzipped tar archive containing the 'yr' binary
RUN curl -Lo /tmp/yr.tar.gz "https://github.com/VirusTotal/yara-x/releases/download/v${YARA_X_VERSION}/yara-x-v${YARA_X_VERSION}-x86_64-unknown-linux-gnu.gz" && \
    tar xzf /tmp/yr.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/yr && \
    rm /tmp/yr.tar.gz

# Create non-root user and directories
# Using specific UID for consistency across environments
RUN useradd -m -u 1000 -s /bin/false scanner && \
    mkdir -p /rules && \
    chown scanner:scanner /rules

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/yara-rest .

# Change ownership of app directory
RUN chown -R scanner:scanner /app

# Run as non-root user
USER scanner

# =============================================================================
# Environment Variables
# =============================================================================
# Server settings
ENV PORT=9001
ENV LOG_LEVEL=info

# HTTP server timeouts (prevents slowloris attacks)
ENV HTTP_READ_TIMEOUT_SECONDS=60
ENV HTTP_WRITE_TIMEOUT_SECONDS=300
ENV HTTP_IDLE_TIMEOUT_SECONDS=120

# YARA-X settings
ENV YARA_RULES_PATH=/rules

# Upload and extraction limits
ENV MAX_UPLOAD_SIZE_MB=512
ENV MAX_EXTRACTED_SIZE_MB=1024
ENV MAX_FILE_COUNT=100000
ENV MAX_SINGLE_FILE_MB=256

# Scan settings
ENV SCAN_TIMEOUT_MINUTES=5
ENV MAX_RECURSION=0
# =============================================================================

EXPOSE 9001

# Health check - must match PORT
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

ENTRYPOINT ["./yara-rest"]
