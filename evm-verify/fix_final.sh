#!/bin/bash

cd /Users/talzisckind/Downloads/deployment/evm-verify/src/analysis

# Fix all storage_write calls that need 2 arguments
sed -i '' 's/has_storage_write(location)/has_storage_write(location, 100)/g' vulnerability_validator.rs

# Fix count_external_calls -> has_external_calls
sed -i '' 's/count_external_calls(/has_external_calls(/g' vulnerability_validator.rs

# Fix remaining 2-arg helper calls in ExploitPatternMatcher section
sed -i '' 's/self\.has_cycle_protection(location, [0-9]*)/self.has_cycle_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_boosting_mechanism(location, [0-9]*)/self.has_boosting_mechanism(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_ragequit_protection(location, [0-9]*)/self.has_ragequit_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_threshold_protection(location, [0-9]*)/self.has_threshold_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_juror_protection(location, [0-9]*)/self.has_juror_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_reputation_protection(location, [0-9]*)/self.has_reputation_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_stake_protection(location, [0-9]*)/self.has_stake_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_execution_protection(location, [0-9]*)/self.has_execution_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_gsm_bypass_opportunity(location, [0-9]*)/self.has_gsm_bypass_opportunity(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_flash_loan_protection(location, [0-9]*)/self.has_flash_loan_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_collusion_protection(location, [0-9]*)/self.has_collusion_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_relay_redundancy(location, [0-9]*)/self.has_relay_redundancy(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_frontrun_protection(location, [0-9]*)/self.has_frontrun_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_invalidation_protection(location, [0-9]*)/self.has_invalidation_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_circumvention_protection(location, [0-9]*)/self.has_circumvention_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_leak_opportunity(location, [0-9]*)/self.has_leak_opportunity(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_timing_protection(location, [0-9]*)/self.has_timing_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_solver_protection(location, [0-9]*)/self.has_solver_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_resolver_protection(location, [0-9]*)/self.has_resolver_protection(location)/g' vulnerability_validator.rs
sed -i '' 's/self\.has_auction_protection(location, [0-9]*)/self.has_auction_protection(location)/g' vulnerability_validator.rs

echo "Fixed all final issues"
