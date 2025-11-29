// Analyzer Accuracy Test Suite
// Tests analyzers against known vulnerable and safe contracts

use evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalyzer;

#[derive(Debug)]
pub struct TestContract {
    pub name: &'static str,
    pub address: &'static str,
    pub known_vulnerabilities: Vec<&'static str>,
    pub category: ContractCategory,
}

#[derive(Debug, PartialEq)]
pub enum ContractCategory {
    KnownVulnerable,
    KnownSafe,
    Unknown,
}

pub struct TestResult {
    pub contract: String,
    pub expected_vulns: Vec<String>,
    pub detected_vulns: Vec<String>,
    pub false_positives: Vec<String>,
    pub false_negatives: Vec<String>,
    pub correct: bool,
}

impl TestResult {
    pub fn is_false_positive(&self) -> bool {
        !self.false_positives.is_empty()
    }
    
    pub fn is_false_negative(&self) -> bool {
        !self.false_negatives.is_empty()
    }
}

// Known vulnerable contracts with documented CVEs
pub fn get_known_vulnerable_contracts() -> Vec<TestContract> {
    vec![
        // The DAO - Reentrancy vulnerability
        TestContract {
            name: "The DAO (Reentrancy)",
            address: "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
            known_vulnerabilities: vec!["reentrancy"],
            category: ContractCategory::KnownVulnerable,
        },
        
        // Parity Multisig - Access control vulnerability
        TestContract {
            name: "Parity Multisig (Access Control)",
            address: "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
            known_vulnerabilities: vec!["access_control"],
            category: ContractCategory::KnownVulnerable,
        },
        
        // BeautyChain - Integer overflow (batchTransfer)
        TestContract {
            name: "BeautyChain (Integer Overflow)",
            address: "0xc5d105e63711398af9bbff092d4b6769c82f793d",
            known_vulnerabilities: vec!["integer_overflow"],
            category: ContractCategory::KnownVulnerable,
        },
    ]
}

// Known safe contracts (well-audited, no known vulnerabilities)
pub fn get_known_safe_contracts() -> Vec<TestContract> {
    vec![
        // USDC - Audited by multiple firms
        TestContract {
            name: "USDC Token",
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            known_vulnerabilities: vec![],
            category: ContractCategory::KnownSafe,
        },
        
        // Uniswap V2 Router - Battle tested
        TestContract {
            name: "Uniswap V2 Router",
            address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            known_vulnerabilities: vec![],
            category: ContractCategory::KnownSafe,
        },
        
        // Compound cDAI - Audited
        TestContract {
            name: "Compound cDAI",
            address: "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643",
            known_vulnerabilities: vec![],
            category: ContractCategory::KnownSafe,
        },
        
        // Aave V2 Pool - Audited
        TestContract {
            name: "Aave V2 LendingPool",
            address: "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
            known_vulnerabilities: vec![],
            category: ContractCategory::KnownSafe,
        },
    ]
}

// Test a single contract
pub async fn test_contract(
    contract: &TestContract,
    bytecode: &[u8],
) -> TestResult {
    let analyzer = ComprehensiveAnalyzer::new();
    
    // Run analysis
    let detected = analyzer.analyze_all(bytecode);
    
    // Extract vulnerability types
    let detected_vulns: Vec<String> = detected
        .iter()
        .map(|v| v.vulnerability_type.clone())
        .collect();
    
    let expected_vulns: Vec<String> = contract
        .known_vulnerabilities
        .iter()
        .map(|v| v.to_string())
        .collect();
    
    // Calculate false positives and false negatives
    let false_positives: Vec<String> = detected_vulns
        .iter()
        .filter(|v| !expected_vulns.contains(v))
        .cloned()
        .collect();
    
    let false_negatives: Vec<String> = expected_vulns
        .iter()
        .filter(|v| !detected_vulns.contains(v))
        .cloned()
        .collect();
    
    let correct = false_positives.is_empty() && false_negatives.is_empty();
    
    TestResult {
        contract: contract.name.to_string(),
        expected_vulns,
        detected_vulns,
        false_positives,
        false_negatives,
        correct,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn verify_test_contract_lists() {
        let vulnerable = get_known_vulnerable_contracts();
        let safe = get_known_safe_contracts();
        
        assert!(!vulnerable.is_empty(), "Need vulnerable contracts for testing");
        assert!(!safe.is_empty(), "Need safe contracts for testing");
        
        println!("Test suite configured with:");
        println!("  {} known vulnerable contracts", vulnerable.len());
        println!("  {} known safe contracts", safe.len());
    }
}
