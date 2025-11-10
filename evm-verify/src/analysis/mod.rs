pub mod cross_contract;
pub mod defi_composability;
pub mod cross_contract_race;
pub mod cross_protocol_arbitrage;
pub mod economic_attacks;
pub mod upgradeable_risks;
pub mod sandwich_attacks;
pub mod time_attacks;
pub mod comprehensive_analyzer;
pub mod test_runner;
// New comprehensive security analysis modules
pub mod bridge_security;
pub mod proxy_attack_detector;
pub mod composability_attack_detector;
pub mod protocol_dependency_mapping;
pub mod defi_primitive_analyzer;
// Advanced cross-contract attack detection modules
pub mod cross_contract_state_manipulation;
pub mod mev_attack_chain_detector;
pub mod oracle_manipulation_network;
pub mod cross_contract_access_control;

// Advanced security modules
pub mod governance_attack_detector;
pub mod oracle_infrastructure_analyzer;
pub mod lp_economic_attack_analyzer;
pub mod black_swan_simulator;
pub mod multi_vector_attack_simulator;
pub mod ai_adaptive_attack_detector;
pub mod infrastructure_risk_analyzer;

// Latest detection modules
pub mod atomic_composability_detector;
pub mod protocol_integration_detector;
pub mod advanced_mev_detector;
pub mod gas_economic_detector;
pub mod multi_protocol_flashloan_detector;
pub mod data_integrity_detector;
pub mod slippage_exploit_detector;

// Neutral verification - no allowlists, pure math
pub mod defi_invariant_checker;
pub mod precision_exploit_detector;

// World-class cross-contract analysis
pub mod call_graph;
pub mod transaction_trace_analyzer;
pub mod rpc_bytecode_fetcher;
pub mod stack_state_tracker;
pub mod data_flow_analyzer;
pub mod taint_tracker;
pub mod state_dependency_analyzer;
pub mod cross_contract_pcc_bridge;
pub mod tarjan_scc; // Tarjan's algorithm for strongly connected components (elite cycle detection)

#[cfg(test)]
mod tests {
    pub mod cross_contract_tests;
    pub mod defi_composability_tests;
    pub mod cross_contract_race_tests;
    pub mod cross_protocol_arbitrage_tests;
    pub mod elite_testing; // Elite-level property-based and fuzzing tests
}
