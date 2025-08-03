#!/bin/bash
cd /Users/talzisckind/Downloads/deployment/evm-verify
echo "Testing syntax for hybrid_zoda_warp_strategy.rs..."
rustc --edition 2021 --crate-type lib src/api/hybrid_zoda_warp_strategy.rs -o /tmp/test_compile --allow warnings 2>&1 | head -20
echo "Exit code: $?"
