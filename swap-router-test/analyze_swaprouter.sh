#!/bin/bash

# Change to the EVM-Verify directory
cd /Users/talzisckind/Downloads/deployment/evm-verify

# Run the chain analyzer on the SwapRouter contract
cargo run --bin chain_analyzer analyze \
  --address 0x062c62cA66E50Cfe277A95564Fe5bB504db1Fab8 \
  --rpc-url https://polygon-rpc.com \
  --format text \
  --output /Users/talzisckind/Downloads/deployment/swap-router-test/report.txt
