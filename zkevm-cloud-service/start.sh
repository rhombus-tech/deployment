#!/bin/bash
chmod +x ./simple-production-server
echo "Starting zkEVM Production Server on port $PORT"
./simple-production-server --port $PORT
