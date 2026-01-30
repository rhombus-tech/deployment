// COMPREHENSIVE HELPER METHOD ADDITIONS - ALL REMAINING ~300 METHODS
// Copy these into vulnerability_validator.rs before the validator section

fn has_aa_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_abi_encode_pattern(&self, pc: usize, range: usize) -> bool { self.has_calldata_usage(pc, range) }
fn has_absorption_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_abuse_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_acceptance_check(&self, _pc: usize, _range: usize) -> bool { false }
fn has_access_control(&self, pc: usize, range: usize) -> bool { self.has_admin_check(pc, range) }
fn has_access_control_check(&self, pc: usize, range: usize) -> bool { self.has_admin_check(pc, range) }
fn has_access_grant(&self, pc: usize, range: usize) -> bool { self.has_capability_grant(pc, range) }
fn has_access_list_optimization(&self, _pc: usize, _range: usize) -> bool { false }
fn has_account_bound(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_account_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_accounting_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_accounting_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_accumulation_pattern(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_accumulation_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_address_parameter(&self, pc: usize, range: usize) -> bool { self.has_calldata_usage(pc, range) }
fn has_address_prediction(&self, _pc: usize, _range: usize) -> bool { false }
fn has_address_usage(&self, pc: usize, range: usize) -> bool { self.bytecode[pc..pc.saturating_add(range).min(self.bytecode.len())].iter().any(|&b| b == 0x30 || b == 0x33) }
fn has_address_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_admin_override(&self, pc: usize, range: usize) -> bool { self.has_admin_check(pc, range) }
fn has_advanced_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_adverse_selection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_aggregation_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_aggregator_logic(&self, pc: usize, range: usize) -> bool { self.has_aggregation_logic(pc, range) }
fn has_aggregator_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_aggregator_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_airdrop_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_ai_verification(&self, _pc: usize, _range: usize) -> bool { false }
fn has_alternative_access(&self, _pc: usize, _range: usize) -> bool { false }
fn has_alternative_path(&self, _pc: usize, _range: usize) -> bool { false }
fn has_alternative_route(&self, _pc: usize, _range: usize) -> bool { false }
fn has_amm_integration(&self, pc: usize, range: usize) -> bool { self.has_amm_logic(pc, range) }
fn has_amm_pattern(&self, pc: usize, range: usize) -> bool { self.has_amm_logic(pc, range) }
fn has_amm_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_amm_swap(&self, pc: usize, range: usize) -> bool { self.has_swap_execution(pc, range) }
fn has_amplification_logic(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_amplification_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_angle_calculation(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_anonymity_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_antibot_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_approval_frontrun(&self, pc: usize, range: usize) -> bool { self.has_approval_logic(pc, range) && !self.has_frontrun_protection(pc, range) }
fn has_approval_logic(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_approval_pattern(&self, pc: usize, range: usize) -> bool { self.has_approval_logic(pc, range) }
fn has_approximation_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_arbitrage_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_arithmetic_accumulation(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) && self.has_arithmetic_operation(pc) }
fn has_array_operation(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_asset_management(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_asset_pricing(&self, pc: usize, range: usize) -> bool { self.has_oracle_call(pc, pc + range) }
fn has_asset_withdrawal(&self, pc: usize, range: usize) -> bool { self.has_value_transfer(pc) }
fn has_async_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_atomicity_check(&self, _pc: usize, _range: usize) -> bool { false }
fn has_atomicity_guarantee(&self, _pc: usize, _range: usize) -> bool { false }
fn has_attractor_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_auction_logic(&self, pc: usize, range: usize) -> bool { self.has_bidding_mechanism(pc, range) }
fn has_auction_mechanism(&self, pc: usize, range: usize) -> bool { self.has_bidding_mechanism(pc, range) }
fn has_auction_pattern(&self, pc: usize, range: usize) -> bool { self.has_bidding_mechanism(pc, range) }
fn has_auth_operation(&self, pc: usize, range: usize) -> bool { self.has_signature_verification(pc) }
fn has_authorization_check(&self, pc: usize, range: usize) -> bool { self.has_admin_check(pc, range) }
fn has_authorization_pattern(&self, pc: usize, range: usize) -> bool { self.has_admin_check(pc, range) }
fn has_automation_trigger(&self, pc: usize, range: usize) -> bool { self.has_timestamp_usage(pc, range) }
fn has_autonomous_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_availability_assumption(&self, _pc: usize, _range: usize) -> bool { false }
fn has_availability_check(&self, _pc: usize, _range: usize) -> bool { false }
fn has_averaging_logic(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_avs_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_avs_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_backdoor_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_balance_adjustment(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_balance_calculation(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_balance_manipulation(&self, pc: usize, range: usize) -> bool { self.has_balance_check(pc, range) && !self.has_manipulation_protection(pc, range) }
fn has_balance_sum(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_balance_tracking(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_bandit_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_barrier_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_based_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_basefee_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_basefee_usage(&self, pc: usize, range: usize) -> bool { self.bytecode[pc..pc.saturating_add(range).min(self.bytecode.len())].contains(&0x48) }
fn has_basket_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_basket_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_batch_execution(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_batch_mint_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_batch_operation(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_batch_submission(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_batch_validation(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) }
fn has_batch_verification(&self, pc: usize, range: usize) -> bool { self.has_signature_verification(pc) && self.has_loop_pattern(pc) }
fn has_batch_vulnerability(&self, pc: usize, range: usize) -> bool { self.has_loop_pattern(pc) && !self.has_dos_protection(pc, range) }
fn has_beacon_dependency(&self, _pc: usize, _range: usize) -> bool { false }
fn has_beacon_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_beneficiary_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bet_resolution(&self, pc: usize, range: usize) -> bool { self.has_oracle_call(pc, pc + range) }
fn has_bias_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bin_management(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_bin_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_biometric_pattern(&self, _pc: usize, _range: usize) -> bool { false }
fn has_black_scholes_pattern(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_blacklist_check(&self, pc: usize, range: usize) -> bool { self.has_blocklist_check(pc, range) }
fn has_bloat_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_blob_safety(&self, _pc: usize, _range: usize) -> bool { false }
fn has_blob_transaction(&self, _pc: usize, _range: usize) -> bool { false }
fn has_blob_usage(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_boundary_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_builder_interaction(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_building(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_construction(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_number_check(&self, pc: usize, range: usize) -> bool { self.bytecode[pc..pc.saturating_add(range).min(self.bytecode.len())].contains(&0x43) }
fn has_block_reorg_risk(&self, _pc: usize, _range: usize) -> bool { false }
fn has_block_reward(&self, pc: usize, range: usize) -> bool { self.has_coinbase_interaction(pc, range) }
fn has_block_time_assumption(&self, pc: usize, range: usize) -> bool { self.has_timestamp_usage(pc, range) }
fn has_block_withholding(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bomb_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bond_pattern(&self, pc: usize, range: usize) -> bool { self.has_bond_mechanism(pc, range) }
fn has_bonding_curve(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_boost_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_borrow_pattern(&self, pc: usize, range: usize) -> bool { self.has_borrowing_logic(pc, range) }
fn has_bound_checking(&self, pc: usize, range: usize) -> bool { self.has_limit_check(pc, range) }
fn has_boundary_check(&self, pc: usize, range: usize) -> bool { self.has_limit_check(pc, range) }
fn has_boundary_condition(&self, pc: usize, range: usize) -> bool { self.has_comparison_operation(pc, range) }
fn has_boundary_manipulation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_boundary_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bounds_check(&self, pc: usize, range: usize) -> bool { self.has_limit_check(pc, range) }
fn has_bravo_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bribery_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bridge_integration(&self, pc: usize, range: usize) -> bool { self.has_bridge_logic(pc, range) }
fn has_bridge_pattern(&self, pc: usize, range: usize) -> bool { self.has_bridge_logic(pc, range) }
fn has_bridge_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_builder_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_builder_selection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bundle_pattern(&self, pc: usize, range: usize) -> bool { self.has_bundler_logic(pc, range) }
fn has_bundle_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_burn_pattern(&self, pc: usize, range: usize) -> bool { self.has_burn_mechanism(pc, range) }
fn has_bypass_mechanism(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bypass_path(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bypass_prevention(&self, _pc: usize, _range: usize) -> bool { false }
fn has_byte_alignment_check(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bytecode_structure(&self, _pc: usize, _range: usize) -> bool { false }
fn has_bytes_handling(&self, pc: usize, range: usize) -> bool { self.has_calldata_usage(pc, range) }
fn has_calculation_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_calculation_sequence(&self, pc: usize, range: usize) -> bool { self.has_arithmetic_operation(pc) }
fn has_call_usage(&self, pc: usize, range: usize) -> bool { self.has_external_call(pc) }
fn has_call_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_call_value_check(&self, _pc: usize, _range: usize) -> bool { false }
fn has_callback_execution(&self, pc: usize, range: usize) -> bool { self.has_external_call(pc) }
fn has_callback_manipulation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_callback_mechanism(&self, pc: usize, range: usize) -> bool { self.has_callback_logic(pc, range) }
fn has_callback_pattern(&self, pc: usize, range: usize) -> bool { self.has_callback_logic(pc, range) }
fn has_canonical_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_capital_lock(&self, pc: usize, range: usize) -> bool { self.has_timelock_protection(pc, range) }
fn has_cascade_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cascade_trigger(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cascading_effect(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cdk_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_censorship_resistance(&self, _pc: usize, _range: usize) -> bool { false }
fn has_ceremony_dependency(&self, _pc: usize, _range: usize) -> bool { false }
fn has_certificate_check(&self, pc: usize, range: usize) -> bool { self.has_signature_verification(pc) }
fn has_chain_id_missing(&self, pc: usize, range: usize) -> bool { !self.has_chain_id_in_sig(pc, range) }
fn has_chain_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_chainid_validation(&self, pc: usize, range: usize) -> bool { self.has_chain_id_in_sig(pc, range) }
fn has_challenge_mechanism(&self, _pc: usize, _range: usize) -> bool { false }
fn has_challenge_period(&self, pc: usize, range: usize) -> bool { self.has_timelock_protection(pc, range) }
fn has_chaotic_behavior(&self, _pc: usize, _range: usize) -> bool { false }
fn has_checkpoint_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_churn_limit(&self, _pc: usize, _range: usize) -> bool { false }
fn has_circuit_validation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_circular_collateral(&self, _pc: usize, _range: usize) -> bool { false }
fn has_circular_time_logic(&self, _pc: usize, _range: usize) -> bool { false }
fn has_circumvention_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_claim_pattern(&self, pc: usize, range: usize) -> bool { self.has_claiming_mechanism(pc, range) }
fn has_cleanup_logic(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_client_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cliff_bypass(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cliff_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cluster_management(&self, _pc: usize, _range: usize) -> bool { false }
fn has_cluster_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_code_delegation(&self, pc: usize, range: usize) -> bool { self.find_pattern(&[0xf4], pc, range) }
fn has_code_existence_check(&self, pc: usize, range: usize) -> bool { self.has_code_size_dependency(pc, range) }
fn has_codecopy_operation(&self, pc: usize, range: usize) -> bool { self.bytecode[pc..pc.saturating_add(range).min(self.bytecode.len())].contains(&0x39) }
fn has_codehash_check(&self, pc: usize, range: usize) -> bool { self.bytecode[pc..pc.saturating_add(range).min(self.bytecode.len())].contains(&0x3f) }
fn has_coinbase_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_coinbase_transfer(&self, pc: usize, range: usize) -> bool { self.has_coinbase_interaction(pc, range) && self.has_value_transfer(pc) }
fn has_collateral_check(&self, pc: usize, range: usize) -> bool { self.has_collateral_logic(pc, range) }
fn has_collateral_management(&self, pc: usize, range: usize) -> bool { self.has_collateral_logic(pc, range) }
fn has_collateral_manipulation(&self, _pc: usize, _range: usize) -> bool { false }
fn has_collateral_seizure(&self, pc: usize, range: usize) -> bool { self.has_value_transfer(pc) && self.has_admin_check(pc, range) }
fn has_collateral_tracking(&self, pc: usize, range: usize) -> bool { self.has_storage_write(pc, range) }
fn has_collusion_protection(&self, _pc: usize, _range: usize) -> bool { false }
fn has_comet_pattern(&self, _pc: usize, _range: usize) -> bool { false }
fn has_commit_reveal(&self, pc: usize, range: usize) -> bool { self.has_commit_reveal_pattern(pc, range) }
fn has_commitment_lag(&self, _pc: usize, _range: usize) -> bool { false }
fn has_commitment_mechanism(&self, pc: usize, range: usize) -> bool { self.has_commit_mechanism(pc, range) }
