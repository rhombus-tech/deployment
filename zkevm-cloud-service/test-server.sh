#!/bin/bash
echo "🚀 Starting zkEVM Test Server on port $PORT"
echo "Testing simple-production-server binary..."

# Test if binary exists and is executable
if [ -f "/app/simple-production-server" ]; then
    echo "✅ Binary exists"
    ls -la /app/simple-production-server
    file /app/simple-production-server
else 
    echo "❌ Binary missing"
    ls -la /app/
fi

# Try to run with simple command first
echo "Starting server..."
exec /app/simple-production-server --port ${PORT:-8080} --config /app/config/zkvm-prod.toml
