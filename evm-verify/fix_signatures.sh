#!/bin/bash

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Replace all 2-argument calls with 1-argument versions in helper methods
sed -i '' 's/has_timestamp_dependency(location, [0-9]*)/has_timestamp_dependency(location)/g' vulnerability_validator.rs
sed -i '' 's/has_conditional_branching(location, [0-9]*)/has_conditional_branching(location)/g' vulnerability_validator.rs
sed -i '' 's/has_storage_read(location, [0-9]*)/has_storage_read(location)/g' vulnerability_validator.rs
sed -i '' 's/has_storage_write(location, [0-9]*)/has_storage_write(location)/g' vulnerability_validator.rs
sed -i '' 's/has_arithmetic_operations(location, [0-9]*)/has_arithmetic_operations(location)/g' vulnerability_validator.rs
sed -i '' 's/has_division_operations(location, [0-9]*)/has_division_operations(location)/g' vulnerability_validator.rs
sed -i '' 's/has_loop_pattern(location, [0-9]*)/has_loop_pattern(location)/g' vulnerability_validator.rs
sed -i '' 's/has_price_comparison(location, [0-9]*)/has_price_comparison(location)/g' vulnerability_validator.rs
sed -i '' 's/count_external_calls(location, [0-9]*)/has_external_calls(location)/g' vulnerability_validator.rs

echo "Fixed all signature mismatches"
