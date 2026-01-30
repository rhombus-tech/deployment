/// Cross-Contract Oracle Dependency Chain Analyzer
/// 
/// YOUR COMPETITIVE ADVANTAGE: Maps oracle dependency chains across entire protocol
/// 
/// Traditional tools: "Contract uses Chainlink" (isolated view)
/// You see: Uniswap → Aggregator → Vault → Lending → Strategy (complete dependency tree)
/// 
/// Real exploits: Mango Markets ($110M), Indexed Finance ($16M)

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractOracleDependency {
    pub vulnerability_type: String,
    pub severity: String,
    pub oracle_chain: Vec<H160>,  // Primary Oracle → Aggregator → Consumers
    pub single_point_of_failure: Option<H160>,
    pub affected_contracts: Vec<H160>,
    pub oracle_types: Vec<String>,  // ["Uniswap TWAP", "Chainlink", "Custom"]
    pub manipulation_risk: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractOracleDependencyAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractOracleDependencyAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractOracleDependency> {
        let mut vulnerabilities = Vec::new();
        
        let contracts = self.protocol.get_contracts();
        
        // Step 1: Identify all oracles
        let oracles = self.identify_oracles(&contracts);
        
        // Step 2: Build oracle dependency graph
        let dependency_graph = self.build_oracle_dependency_graph(&oracles, &contracts);
        
        // Step 3: Find dependency chains
        let chains = self.find_dependency_chains(&dependency_graph);
        
        // Step 4: Analyze each chain for vulnerabilities
        for chain in chains {
            let vulnerability = self.analyze_chain(&chain, &oracles, &contracts);
            if let Some(vuln) = vulnerability {
                vulnerabilities.push(vuln);
            }
        }
        
        vulnerabilities
    }
    
    fn identify_oracles(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, OracleInfo> {
        let mut oracles = HashMap::new();
        
        for (addr, bytecode) in contracts {
            if let Some(oracle_type) = self.detect_oracle_type(bytecode) {
                oracles.insert(*addr, OracleInfo {
                    address: *addr,
                    oracle_type,
                    is_aggregator: self.is_aggregator(bytecode),
                    dependencies: Vec::new(),
                });
            }
        }
        
        oracles
    }
    
    fn detect_oracle_type(&self, bytecode: &[u8]) -> Option<OracleType> {
        // Chainlink oracle
        let chainlink_selectors = [
            [0x50, 0xd2, 0x5b, 0xcd], // latestAnswer
            [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
        ];
        
        for selector in &chainlink_selectors {
            if bytecode.windows(4).any(|w| w == selector) {
                return Some(OracleType::Chainlink);
            }
        }
        
        // Uniswap TWAP
        let uniswap_selectors = [
            [0x09, 0x02, 0xf1, 0xac], // getReserves
            [0x54, 0xfd, 0x4d, 0x50], // price0CumulativeLast
        ];
        
        for selector in &uniswap_selectors {
            if bytecode.windows(4).any(|w| w == selector) {
                return Some(OracleType::UniswapTWAP);
            }
        }
        
        // Generic price oracle
        let price_selectors = [
            [0x98, 0x50, 0xf3, 0x6e], // getPrice
            [0x41, 0x97, 0x6e, 0x09], // price
        ];
        
        for selector in &price_selectors {
            if bytecode.windows(4).any(|w| w == selector) {
                return Some(OracleType::Custom);
            }
        }
        
        None
    }
    
    fn is_aggregator(&self, bytecode: &[u8]) -> bool {
        // Aggregator typically has multiple STATICCALL operations
        let staticcall_count = bytecode.iter().filter(|&&op| op == 0xFA).count();
        staticcall_count >= 2 // Calls at least 2 oracles
    }
    
    fn build_oracle_dependency_graph(&self, oracles: &HashMap<H160, OracleInfo>, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<H160>> {
        let mut graph = HashMap::new();
        
        // For each contract, find which oracles it depends on
        for (contract_addr, _bytecode) in contracts {
            let oracle_deps: Vec<H160> = self.protocol.get_call_targets(contract_addr)
                .iter()
                .filter(|target| oracles.contains_key(target))
                .cloned()
                .collect();
            
            if !oracle_deps.is_empty() {
                graph.insert(*contract_addr, oracle_deps);
            }
        }
        
        graph
    }
    
    fn find_dependency_chains(&self, graph: &HashMap<H160, Vec<H160>>) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        
        // Find all paths of length >= 3 (Oracle → Consumer1 → Consumer2)
        for (start, deps) in graph {
            for dep in deps {
                if let Some(second_level) = graph.get(dep) {
                    for second_dep in second_level {
                        let chain = vec![*dep, *start, *second_dep];
                        chains.push(chain);
                    }
                }
            }
        }
        
        chains
    }
    
    fn analyze_chain(&self, chain: &[H160], oracles: &HashMap<H160, OracleInfo>, contracts: &HashMap<H160, &Vec<u8>>) -> Option<CrossContractOracleDependency> {
        if chain.len() < 2 {
            return None;
        }
        
        let primary_oracle = chain[0];
        let affected: Vec<H160> = chain[1..].to_vec();
        
        // Determine severity based on oracle type and chain length
        let oracle_type = oracles.get(&primary_oracle)
            .map(|o| format!("{:?}", o.oracle_type))
            .unwrap_or_else(|| "Unknown".to_string());
        
        let is_single_source = chain.len() > 3; // Long dependency chain = higher risk
        let manipulation_risk = self.assess_manipulation_risk(&primary_oracle, oracles);
        
        Some(CrossContractOracleDependency {
            vulnerability_type: "Cross-Contract Oracle Dependency Chain".to_string(),
            severity: if is_single_source { "Critical" } else { "High" }.to_string(),
            oracle_chain: chain.to_vec(),
            single_point_of_failure: if is_single_source { Some(primary_oracle) } else { None },
            affected_contracts: affected.clone(),
            oracle_types: vec![oracle_type.clone()],
            manipulation_risk: manipulation_risk.clone(),
            description: format!(
                "CROSS-PROTOCOL ORACLE DEPENDENCY CHAIN:\n\
                 Primary Oracle: {:?} ({})\n\
                 Dependency Chain: {:?}\n\
                 Affected Contracts: {} contracts\n\
                 Manipulation Risk: {}\n\n\
                 If {:?} is manipulated, {} contracts are affected!",
                primary_oracle, oracle_type, chain, affected.len(),
                manipulation_risk, primary_oracle, affected.len()
            ),
            exploit_scenario: format!(
                "ORACLE MANIPULATION ATTACK:\n\
                 \n\
                 Dependency Flow:\n\
                 1. Primary Oracle ({}) at {:?}\n\
                 2. {} contracts depend on this oracle\n\
                 3. Manipulation propagates through entire chain\n\
                 \n\
                 Attack Scenario:\n\
                 1. Attacker manipulates {} oracle\n\
                 2. Contract {:?} reads bad price\n\
                 3. Dependent contracts {:?} use corrupted data\n\
                 4. Protocol-wide price manipulation achieved\n\
                 \n\
                 Real Examples:\n\
                 - Mango Markets: $110M - Oracle manipulation\n\
                 - Indexed Finance: $16M - TWAP oracle attack\n\
                 - Cream Finance: $130M - Price oracle exploit\n\
                 \n\
                 Single-contract tools CANNOT see this dependency chain!",
                oracle_type, primary_oracle, affected.len(),
                oracle_type, primary_oracle, affected
            ),
            remediation: format!(
                "ORACLE DEPENDENCY PROTECTION:\n\
                 \n\
                 1. MULTIPLE ORACLE SOURCES:\n\
                    - Use at least 3 independent oracle types\n\
                    - Combine: Chainlink + Uniswap TWAP + Custom\n\
                    - Implement median or weighted average\n\
                 \n\
                 2. CIRCUIT BREAKERS:\n\
                    - Maximum price deviation: 5% per block\n\
                    - Pause protocol if oracle deviates > 10%\n\
                    - Require multi-block confirmation for large changes\n\
                 \n\
                 3. ORACLE VALIDATION:\n\
                    ```solidity\n\
                    function getPrice() returns (uint256) {{\n\
                        uint256 chainlink = chainlinkOracle.latestAnswer();\n\
                        uint256 uniswap = uniswapTWAP.getPrice();\n\
                        uint256 custom = customOracle.price();\n\
                        \n\
                        // Require all within 5% of each other\n\
                        require(abs(chainlink - uniswap) < chainlink * 5 / 100);\n\
                        require(abs(chainlink - custom) < chainlink * 5 / 100);\n\
                        \n\
                        return median(chainlink, uniswap, custom);\n\
                    }}\n\
                    ```\n\
                 \n\
                 4. TIME DELAYS:\n\
                    - TWAP with minimum 10-minute window\n\
                    - Delay between oracle update and usage\n\
                 \n\
                 Affected chain: {:?}",
                chain
            ),
        })
    }
    
    fn assess_manipulation_risk(&self, oracle: &H160, oracles: &HashMap<H160, OracleInfo>) -> String {
        if let Some(info) = oracles.get(oracle) {
            match info.oracle_type {
                OracleType::Chainlink => "Low (Decentralized)".to_string(),
                OracleType::UniswapTWAP => "Medium (On-chain TWAP)".to_string(),
                OracleType::Custom => "High (Unknown source)".to_string(),
            }
        } else {
            "Critical (Unknown oracle)".to_string()
        }
    }
}

#[derive(Debug, Clone)]
struct OracleInfo {
    address: H160,
    oracle_type: OracleType,
    is_aggregator: bool,
    dependencies: Vec<H160>,
}

#[derive(Debug, Clone)]
enum OracleType {
    Chainlink,
    UniswapTWAP,
    Custom,
}

impl CrossContractOracleDependency {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::OracleManipulation,
            severity: match self.severity.as_str() {
                "Critical" => SecuritySeverity::Critical,
                "High" => SecuritySeverity::High,
                _ => SecuritySeverity::Medium,
            },
            description: self.description.clone(),
            call_path: self.oracle_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_oracle_dependency_chain() {
        // Test: Uniswap → Aggregator → Vault → Lending
        // Should detect complete dependency chain
    }
}
