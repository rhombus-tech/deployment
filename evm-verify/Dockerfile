# ZODA-WARP zkEVM Production Dockerfile
# Multi-stage build for optimized production container

# Build stage
FROM rust:1.81-slim-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy project files
COPY evm-verify/ ./
# Copy demo-playground files for embedding
COPY demo-playground/ ./demo-playground/

# Build production binaries
RUN cargo build --release --bin live-proving-service

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r zkvm && useradd -r -g zkvm zkvm

# Create app directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/target/release/live-proving-service ./bin/live-proving-service

# Copy configuration files
COPY config/ ./config/

# Create data directories
RUN mkdir -p data logs metrics && \
    chown -R zkvm:zkvm /app

# Set executable permissions
RUN chmod +x bin/*

# Switch to non-root user
USER zkvm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8090 9090

# Default command
CMD ["./bin/live-proving-service"]
