# ZODA-WARP zkEVM Production Dockerfile
# Multi-stage build for optimized production container

# Build stage
FROM rust:1.75-slim-bullseye as builder

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

# Copy Cargo files for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY */Cargo.toml ./*/

# Cache dependencies (optimization)
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/dummy.rs && \
    cargo build --release --bin dummy && \
    rm -rf src/

# Copy source code
COPY . .

# Build production binaries
RUN cargo build --release --bin zoda_proof_size_analyzer
RUN cargo build --release --bin ultimate_zoda_warp_demo
RUN cargo build --release --bin zkvm_server

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
COPY --from=builder /app/target/release/zoda_proof_size_analyzer ./bin/
COPY --from=builder /app/target/release/ultimate_zoda_warp_demo ./bin/
COPY --from=builder /app/target/release/zkvm_server ./bin/

# Copy configuration files
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create data directories
RUN mkdir -p data logs metrics && \
    chown -R zkvm:zkvm /app

# Set executable permissions
RUN chmod +x bin/* scripts/*

# Switch to non-root user
USER zkvm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8090 9090

# Default command
CMD ["./bin/zkvm_server", "--config", "config/production.toml"]
