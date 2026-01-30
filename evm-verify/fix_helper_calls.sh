#!/bin/bash

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Fix helper methods that incorrectly call other helpers with 2 args
sed -i '' 's/has_loop_pattern(location, range)/has_loop_pattern(location)/g' vulnerability_validator.rs
sed -i '' 's/has_storage_read(location, range)/has_storage_read(location)/g' vulnerability_validator.rs
sed -i '' 's/has_conditional_branching(location, range)/has_conditional_branching(location)/g' vulnerability_validator.rs
sed -i '' 's/has_arithmetic_operations(location, range)/has_arithmetic_operations(location)/g' vulnerability_validator.rs
sed -i '' 's/has_timestamp_dependency(location, range)/has_timestamp_dependency(location)/g' vulnerability_validator.rs
sed -i '' 's/has_external_calls(location, range)/has_external_calls(location)/g' vulnerability_validator.rs
sed -i '' 's/has_storage_write(location, range)/has_storage_write(location, 100)/g' vulnerability_validator.rs

echo "Fixed helper method calls"
