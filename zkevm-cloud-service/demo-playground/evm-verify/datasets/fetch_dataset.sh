#!/bin/bash
# Script to fetch and process the SmartBugs dataset

set -e

cd "$(dirname "$0")/.."
echo "Current directory: $(pwd)"

# Compile and run the Rust script
echo "Compiling and running Rust script..."
rustc -o datasets/fetch_smartbugs datasets/fetch_smartbugs.rs
chmod +x datasets/fetch_smartbugs
datasets/fetch_smartbugs

echo "Dataset fetching complete!"
