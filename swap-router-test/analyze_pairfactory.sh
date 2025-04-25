#!/bin/bash

# Change to the EVM-Verify directory
cd /Users/talzisckind/Downloads/deployment/evm-verify

# Run the chain analyzer on the PairFactory contract
cargo run --bin chain_analyzer analyze \
  --address 0xAAA16c016BF556fcD620328f0759252E29b1AB57 \
  --rpc-url https://polygon-rpc.com \
  --format text \
  --output /Users/talzisckind/Downloads/deployment/swap-router-test/pairfactory_report.txt
