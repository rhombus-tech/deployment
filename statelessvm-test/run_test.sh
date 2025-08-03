#!/bin/bash

# StatelessVM Connectivity Test Runner
# This script builds and runs the standalone StatelessVM connectivity test

echo "=== StatelessVM Connectivity Test ==="
echo "This script will verify connectivity to the StatelessVM service running on port 7548"
echo ""

# Build the test
echo "Building connectivity test..."
cargo build

# Check if the StatelessVM service is running
if ! curl -s http://localhost:7548/health > /dev/null; then
    echo "StatelessVM service is not running. Starting it..."
    cd ../stateless-vm && ./start_statelessvm_service.sh
    cd - > /dev/null
    
    # Wait for service to start
    echo "Waiting for StatelessVM service to start..."
    sleep 5
    
    if ! curl -s http://localhost:7548/health > /dev/null; then
        echo "ERROR: Failed to start StatelessVM service"
        exit 1
    fi
    
    echo "StatelessVM service started successfully"
else
    echo "StatelessVM service is already running on port 7548"
fi

# Run the connectivity test
echo ""
echo "Running StatelessVM connectivity test..."
echo "----------------------------------------"
STATELESSVM_URL=http://localhost:7548 ./target/debug/statelessvm-test

echo ""
echo "=== Test Complete ==="
