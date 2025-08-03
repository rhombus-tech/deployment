#!/bin/bash
cd /Users/talzisckind/Downloads/deployment/ai-trading-agent
echo "Running connection pool test with verbose output..."
MOCK_MODE=true RUST_LOG=debug cargo test --test connection_pool_test -- --nocapture test_connection_pooling_performance > test_output.log 2>&1
echo "Test completed. Showing output:"
cat test_output.log | grep -v "warning:" | grep -v "^   Compiling" | grep -v "^   Building" | grep -v "^    Finished"
