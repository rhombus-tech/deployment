#!/bin/bash

# Get the current directory
CURRENT_DIR=$(pwd)
echo "Current directory: $CURRENT_DIR"

# Create necessary directories if they don't exist
mkdir -p datasets/processed
mkdir -p datasets/processed/unclassified

echo "Preparing directory structure..."
# Create directories for each vulnerability category
for category in reentrancy cross_contract_reentrancy integer_overflow integer_underflow precision_loss uninitialized_storage access_control gas_griefing unchecked_calls
do
    mkdir -p "datasets/processed/$category"
done

# Compile and run the Rust labeling script
echo "Compiling and running Rust dataset labeling script..."
rustc -o label_dataset datasets/label_dataset.rs && ./label_dataset
rm -f label_dataset  # Clean up the executable

echo "Dataset labeling complete!"
