# Multi-stage build to compile Rust binary inside Linux container
FROM rust:1.82-bullseye AS builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy Rust workspace files
COPY evm-verify ./evm-verify
COPY config ./config
COPY demo-playground ./demo-playground

# Set working directory to evm-verify for the build
WORKDIR /app/evm-verify

# Build the live-proving-service binary
RUN cargo build --release --bin live-proving-service

# Runtime stage with proper SSL libraries
FROM debian:bullseye-slim

# Install ALL SSL runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    libssl-dev \
    openssl \
    libc6 \
    libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Create symbolic links for SSL libraries (in case of version mismatches)
RUN ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so || true
RUN ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so || true

# Copy the binary, config, and website files
COPY --from=builder /app/evm-verify/target/release/live-proving-service /zkvm-server
COPY --from=builder /app/config /app/config
COPY --from=builder /app/demo-playground /app/demo-playground

# Make sure binary is executable
RUN chmod +x /zkvm-server

# Create non-root user
RUN useradd -r -s /bin/false zkvm
USER zkvm

# Expose port 8080
EXPOSE 8080

# Run the production zkEVM server
CMD ["/zkvm-server"]
