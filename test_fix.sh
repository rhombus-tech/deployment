#!/bin/bash
# Quick test of the filtering fix

cd /Users/talzisckind/Downloads/deployment/evm-verify

echo "Testing contract: 0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae"
echo "This was showing 'Critical (22 findings)' before the fix"
echo ""

cargo run --example analyze_specific_contract --release -- 0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae 2>&1 | grep -E "(Total vulnerabilities:|VERDICT)"
