use crate::analysis::defi_composability::{
    DeFiComposabilityAnalyzer, ComposabilityRisk, ComposabilityRiskKind,
    TokenRole, ContractRole, EconomicImpact, economic_models
};
use crate::analysis::cross_contract::ContractProtocol;
use crate::bytecode::security::SecuritySeverity;
use ethers::types::H160;
use std::collections::HashMap;
use std::str::FromStr;

/// Sample bytecode for a token contract
const TOKEN_CONTRACT: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];

/// Sample bytecode for an AMM pool
const AMM_POOL_CONTRACT: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

/// Sample bytecode for a lending pool
const LENDING_POOL_CONTRACT: &[u8] = &[0xFE, 0xED, 0xFA, 0xCE];

/// Sample bytecode for an oracle
const ORACLE_CONTRACT: &[u8] = &[0x12, 0x34, 0x56, 0x78];

#[test]
fn test_new_defi_analyzer() {
    // Create a protocol
    let protocol = ContractProtocol::new();
    
    // Create analyzer
    let analyzer = DeFiComposabilityAnalyzer::new(protocol);
    
    // Check that it doesn't have any risks initially
    assert_eq!(analyzer.risks.len(), 0);
}

#[test]
fn test_analyze_defi_protocol() {
    // Create addresses for testing
    let token_address = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let amm_address = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    let lending_address = H160::from_str("0xaabbccddeeff00112233445566778899001122aa").unwrap();
    let oracle_address = H160::from_str("0xaabbccddeeff00112233445566778899001122bb").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(token_address, TOKEN_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(amm_address, AMM_POOL_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(lending_address, LENDING_POOL_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(oracle_address, ORACLE_CONTRACT.to_vec()).unwrap();
    
    // Create analyzer
    let mut analyzer = DeFiComposabilityAnalyzer::new(protocol);
    
    // Run analysis
    let risks = analyzer.analyze().unwrap();
    
    // Verify we found some risks (our implementation should always find some in test data)
    assert!(!risks.is_empty());
    println!("Found {} DeFi composability risks", risks.len());
    
    // Verify we can convert to protocol findings
    let findings = analyzer.to_protocol_findings();
    assert!(!findings.is_empty());
}

#[test]
fn test_economic_security_analysis() {
    // Create asset parameters for a simple protocol
    let mut assets = HashMap::new();
    let token_address = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    
    let mut correlations = HashMap::new();
    correlations.insert(token_address, 1.0);
    
    assets.insert(
        token_address,
        economic_models::AssetParameters {
            volatility: 0.5,
            correlations,
            liquidity_depth: 1000000.0,
            is_protocol_native: true,
        }
    );
    
    // Create a protocol economic model
    let model = economic_models::ProtocolEconomicModel {
        assets,
        max_ltv: 0.75,
        liquidation_threshold: 0.825,
        stress_test_params: economic_models::StressTestParameters {
            max_price_deviation: 0.5,
            liquidity_shock: 0.7,
            correlation_shock: 0.9,
        },
    };
    
    // Analyze economic security
    let analysis = economic_models::analyze_economic_security(&model).unwrap();
    
    // Verify analysis results
    assert!(!analysis.recommendations.is_empty());
    println!("Economic security analysis recommendations: {:?}", analysis.recommendations);
}

#[test]
fn test_token_flow_analysis() {
    // Create addresses for testing
    let token_address = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let amm_address = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    let lending_address = H160::from_str("0xaabbccddeeff00112233445566778899001122aa").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(token_address, TOKEN_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(amm_address, AMM_POOL_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(lending_address, LENDING_POOL_CONTRACT.to_vec()).unwrap();
    
    // Create analyzer
    let mut analyzer = DeFiComposabilityAnalyzer::new(protocol);
    
    // Build token flows explicitly
    analyzer.build_token_flows().unwrap();
    
    // We don't have access to internal token_flows field in this test,
    // but the function shouldn't panic
}

#[test]
fn test_access_control_analysis() {
    // Create addresses for testing
    let token_address = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let amm_address = H160::from_str("0x1122334455667788990011223344556677889901").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(token_address, TOKEN_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(amm_address, AMM_POOL_CONTRACT.to_vec()).unwrap();
    
    // Create analyzer
    let mut analyzer = DeFiComposabilityAnalyzer::new(protocol);
    
    // Detect access controls explicitly
    analyzer.detect_access_controls().unwrap();
    
    // Our implementation should add at least one risk
    assert!(!analyzer.risks.is_empty());
    
    // Check if we found access control inconsistency risks
    let has_access_control_risk = analyzer.risks.iter().any(|r| 
        matches!(r.kind, ComposabilityRiskKind::AccessControlInconsistency)
    );
    
    assert!(has_access_control_risk);
}

#[test]
fn test_oracle_dependencies() {
    // Create addresses for testing
    let token_address = H160::from_str("0x1122334455667788990011223344556677889900").unwrap();
    let oracle_address = H160::from_str("0xaabbccddeeff00112233445566778899001122bb").unwrap();
    
    // Create protocol
    let mut protocol = ContractProtocol::new();
    protocol.add_contract(token_address, TOKEN_CONTRACT.to_vec()).unwrap();
    protocol.add_contract(oracle_address, ORACLE_CONTRACT.to_vec()).unwrap();
    
    // Create analyzer
    let mut analyzer = DeFiComposabilityAnalyzer::new(protocol);
    
    // Analyze oracle dependencies explicitly
    analyzer.analyze_oracle_dependencies().unwrap();
    
    // Our implementation should add at least one risk
    assert!(!analyzer.risks.is_empty());
    
    // Check if we found oracle manipulation risks
    let has_oracle_risk = analyzer.risks.iter().any(|r| 
        matches!(r.kind, ComposabilityRiskKind::OracleManipulation)
    );
    
    assert!(has_oracle_risk);
}
