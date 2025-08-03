#!/bin/bash

# StatelessVM Service Startup Script
# This script starts the StatelessVM service with production configuration

# Configuration
PORT=7548                   # Service port
LOG_LEVEL=info              # Logging level (debug, info, warn, error)
AVALANCHE_RPC_URL="https://api.avax.network/ext/bc/C/rpc"  # Avalanche C-Chain RPC URL

# Executable path
EXECUTABLE="./target/release/server"

# Create logs directory if it doesn't exist
mkdir -p logs

# Start the service with logging
echo "Starting StatelessVM service on port $PORT..."
RUST_LOG=$LOG_LEVEL PORT=$PORT AVALANCHE_RPC_URL=$AVALANCHE_RPC_URL nohup $EXECUTABLE > logs/statelessvm_$(date +%Y%m%d_%H%M%S).log 2>&1 &

# Get the process ID
PID=$!
echo "StatelessVM service started with PID: $PID"
echo $PID > statelessvm.pid

echo "Service logs are being written to logs/ directory"
echo "To stop the service, run: kill \$(cat statelessvm.pid)"
