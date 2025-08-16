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

#[cfg(test)]
mod tests {
    pub mod cross_contract_tests;
    pub mod defi_composability_tests;
    pub mod cross_contract_race_tests;
    pub mod cross_protocol_arbitrage_tests;
}
