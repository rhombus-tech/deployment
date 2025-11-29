#!/bin/bash
# Quick 2-block scan to test the fix

cd /Users/talzisckind/Downloads/deployment/evm-verify

echo "Running quick 2-block scan to verify fix..."
echo ""

# Modify the scanner to only scan 2 blocks
sed -i '' 's/let blocks_to_scan = 10;/let blocks_to_scan = 2;/' examples/live_block_vulnerability_scanner.rs

cargo run --example live_block_vulnerability_scanner --release 2>&1 | grep -E "(📦 BLOCK|Scanning 0x|Critical|High|Medium|Low|Clean|SUMMARY)" | head -50

# Restore original
sed -i '' 's/let blocks_to_scan = 2;/let blocks_to_scan = 10;/' examples/live_block_vulnerability_scanner.rs
