# FRAC RPC - Production Docker Image

FROM rust:1.75 as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/frac-rpc /usr/local/bin/frac-rpc

# Create non-root user
RUN useradd -m -u 1000 frac && \
    mkdir -p /data && \
    chown -R frac:frac /data

USER frac
WORKDIR /data

EXPOSE 8545 9090

CMD ["frac-rpc"]
