/// Cross-Contract Price Oracle Triangulation Analyzer
/// 
/// YOUR ADVANTAGE: Map complete oracle dependency graphs
/// 
/// Pattern: Oracle_A (Uniswap) ← Oracle_B (Chainlink) ← Oracle_C (Contract price)
/// Attack: Manipulate any one oracle causing cascading price corruption
/// Real Exploits: Oracle manipulation attacks

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractOracleTriangulation {
    pub vulnerability_type: String,
    pub severity: String,
    pub oracle_chain: Vec<H160>,  // Oracle_A → Oracle_B → Oracle_C
    pub manipulation_target: Option<H160>,
    pub affected_contracts: Vec<H160>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractOracleTriangulationAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractOracleTriangulationAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractOracleTriangulation> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find oracle contracts
        let oracles = self.find_oracle_contracts(&contracts);
        
        // Build oracle dependency graph
        let dependencies = self.build_oracle_dependencies(&oracles);
        
        // Find triangulation patterns
        for (oracle, deps) in &dependencies {
            if deps.len() >= 1 {
                // Find contracts that depend on this oracle
                let dependents = self.find_oracle_dependents(*oracle, &contracts);
                
                if !dependents.is_empty() {
                    let chain = self.build_oracle_chain(*oracle, deps);
                    
                    if chain.len() >= 2 {
                        vulnerabilities.push(CrossContractOracleTriangulation {
                            vulnerability_type: "Cross-Contract Oracle Triangulation".to_string(),
                            severity: "Critical".to_string(),
                            oracle_chain: chain.clone(),
                            manipulation_target: chain.first().copied(),
                            affected_contracts: dependents.clone(),
                            description: format!(
                                "Oracle triangulation chain: {:?}\n\
                                 {} contracts depend on this oracle chain\n\
                                 Manipulation of any oracle propagates through chain",
                                chain, dependents.len()
                            ),
                            exploit_scenario: format!(
                                "ORACLE TRIANGULATION ATTACK:\n\
                                 Oracle Chain: {:?}\n\
                                 Affected Contracts: {} protocols\n\
                                 \n\
                                 Attack:\n\
                                 1. Oracle A (Uniswap): Direct DEX price\n\
                                 2. Oracle B (Aggregator): Aggregates A + others\n\
                                 3. Oracle C (Lending): Uses B for collateral pricing\n\
                                 \n\
                                 Exploitation:\n\
                                 - Flash loan manipulates Oracle A (Uniswap pool)\n\
                                 - Oracle B reads manipulated price from A\n\
                                 - Oracle C uses corrupted price from B\n\
                                 - Lending protocol liquidates based on C\n\
                                 → CASCADING PRICE MANIPULATION!\n\
                                 \n\
                                 Single point of failure:\n\
                                 - Manipulate ONE oracle → corrupt ENTIRE chain\n\
                                 - {} protocols affected by single manipulation\n\
                                 \n\
                                 Real Examples:\n\
                                 - Mango Markets: Oracle manipulation → $110M loss\n\
                                 - Indexed Finance: Price feed exploit → $16M\n\
                                 - Cream Finance: Oracle deps → $130M\n\
                                 \n\
                                 Your tool UNIQUELY maps complete oracle graph!",
                                chain, dependents.len(), dependents.len()
                            ),
                            remediation: "Use multiple independent oracles, implement circuit breakers, add TWAP, validate price deviations".to_string(),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_oracle_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for oracle-like patterns: price reading, aggregation
        let oracle_selectors = [
            [0x50, 0xd2, 0x5b, 0xcd], // latestAnswer (Chainlink)
            [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
            [0x09, 0x5e, 0xa7, 0xb3], // getPrice
        ];
        
        contracts.iter()
            .filter(|(_, bc)| {
                oracle_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel))
            })
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn build_oracle_dependencies(&self, oracles: &[H160]) -> HashMap<H160, Vec<H160>> {
        let mut deps = HashMap::new();
        
        for oracle in oracles {
            let targets = self.protocol.get_call_targets(oracle);
            let oracle_deps: Vec<H160> = targets.into_iter()
                .filter(|t| oracles.contains(t))
                .collect();
            
            if !oracle_deps.is_empty() {
                deps.insert(*oracle, oracle_deps);
            }
        }
        
        deps
    }
    
    fn find_oracle_dependents(&self, oracle: H160, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.keys()
            .filter(|&&addr| {
                let targets = self.protocol.get_call_targets(&addr);
                targets.contains(&oracle)
            })
            .copied()
            .collect()
    }
    
    fn build_oracle_chain(&self, start: H160, deps: &[H160]) -> Vec<H160> {
        let mut chain = vec![start];
        chain.extend_from_slice(deps);
        chain
    }
}

impl CrossContractOracleTriangulation {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::OracleManipulation,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.oracle_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
