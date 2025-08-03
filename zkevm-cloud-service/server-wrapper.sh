#!/bin/bash

# Wrapper script to start zkvm-server with proper networking for cloud deployment
echo "🚀 Starting zkEVM Production Server"
echo "📡 Network configuration: 0.0.0.0:8080"
echo "🌍 Cloud-ready deployment"

# Use socat to proxy traffic from 0.0.0.0:8080 to localhost:3030
socat TCP-LISTEN:8080,fork,bind=0.0.0.0 TCP:127.0.0.1:3030 &
SOCAT_PID=$!

echo "🔗 Port forwarding: 0.0.0.0:8080 -> 127.0.0.1:3030 (PID: $SOCAT_PID)"

# Start the zkvm server
/usr/local/bin/zkvm-server &
SERVER_PID=$!

echo "⚡ zkEVM server started (PID: $SERVER_PID)"

# Wait for either process to exit
wait -n

# Cleanup
echo "🛑 Shutting down services"
kill $SOCAT_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
