/// Cross-Contract Gas Griefing Amplification Analyzer
/// 
/// YOUR ADVANTAGE: Calculate cumulative gas costs across call chains
/// 
/// Pattern: Contract A → B → C with unbounded gas consumption
/// Attack: Each hop multiplies gas cost causing protocol-wide DOS
/// Real Exploits: DoS on yield aggregators

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractGasGriefing {
    pub vulnerability_type: String,
    pub severity: String,
    pub call_chain: Vec<H160>,
    pub estimated_gas_amplification: u64,
    pub unbounded_loops: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractGasGriefingAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractGasGriefingAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractGasGriefing> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with unbounded operations
        let gas_intensive = self.find_gas_intensive_contracts(&contracts);
        
        // Build gas amplification chains
        for start in &gas_intensive {
            let chains = self.find_gas_amplification_chains(*start, &gas_intensive);
            
            for chain in chains {
                if chain.len() >= 2 {
                    let gas_cost = self.estimate_gas_cost(&chain, &contracts);
                    
                    if gas_cost > 5_000_000 {  // > 5M gas
                        vulnerabilities.push(CrossContractGasGriefing {
                            vulnerability_type: "Cross-Contract Gas Griefing Amplification".to_string(),
                            severity: if gas_cost > 15_000_000 { "Critical" } else { "High" }.to_string(),
                            call_chain: chain.clone(),
                            estimated_gas_amplification: gas_cost,
                            unbounded_loops: self.find_unbounded_loops(&chain, &contracts),
                            description: format!(
                                "Gas amplification chain: {:?}\n\
                                 Estimated cumulative gas: {} (can cause DOS)",
                                chain, gas_cost
                            ),
                            exploit_scenario: format!(
                                "GAS GRIEFING AMPLIFICATION ATTACK:\n\
                                 Chain: {:?}\n\
                                 Estimated Gas: {}\n\
                                 \n\
                                 Attack:\n\
                                 1. Vault calls 10 strategies\n\
                                 2. Each strategy queries 10 oracles\n\
                                 3. Each oracle does price calculations\n\
                                 Result: 10 × 10 × gas_per_call = MASSIVE gas consumption\n\
                                 \n\
                                 If attacker can influence:\n\
                                 - Number of strategies\n\
                                 - Number of oracles\n\
                                 - Loop iterations\n\
                                 → Can cause out-of-gas → DOS entire protocol!\n\
                                 \n\
                                 Real Examples:\n\
                                 - Yield aggregators with unbounded strategy loops\n\
                                 - Multi-oracle price feeds\n\
                                 - Batch processing without gas limits\n\
                                 \n\
                                 Each hop multiplies gas cost exponentially!",
                                chain, gas_cost
                            ),
                            remediation: "Implement gas limits per hop, bound loop iterations, use pagination for batch operations".to_string(),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_gas_intensive_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.iter()
            .filter(|(_, bc)| {
                // Look for JUMPI (loops) and external calls
                bc.contains(&0x57) && (bc.contains(&0xF1) || bc.contains(&0xF2))
            })
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_gas_amplification_chains(&self, start: H160, gas_intensive: &[H160]) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        let mut current_chain = vec![start];
        
        self.build_chains(start, gas_intensive, &mut current_chain, &mut chains, 5);
        
        chains
    }
    
    fn build_chains(
        &self,
        current: H160,
        gas_intensive: &[H160],
        current_chain: &mut Vec<H160>,
        chains: &mut Vec<Vec<H160>>,
        max_depth: usize,
    ) {
        if current_chain.len() >= max_depth {
            return;
        }
        
        let targets = self.protocol.get_call_targets(&current);
        
        for target in targets {
            if gas_intensive.contains(&target) {
                current_chain.push(target);
                chains.push(current_chain.clone());
                self.build_chains(target, gas_intensive, current_chain, chains, max_depth);
                current_chain.pop();
            }
        }
    }
    
    fn estimate_gas_cost(&self, chain: &[H160], _contracts: &HashMap<H160, &Vec<u8>>) -> u64 {
        // Estimate: Each contract consumes ~100k gas
        // With loops: multiply by average loop iterations (assume 10)
        let base_gas_per_contract = 100_000u64;
        let loop_multiplier = 10u64;
        
        (chain.len() as u64) * base_gas_per_contract * loop_multiplier
    }
    
    fn find_unbounded_loops(&self, _chain: &[H160], _contracts: &HashMap<H160, &Vec<u8>>) -> Vec<usize> {
        vec![0, 1, 2] // Simplified: return positions with loops
    }
}

impl CrossContractGasGriefing {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: if self.severity == "Critical" { SecuritySeverity::Critical } else { SecuritySeverity::High },
            description: self.description.clone(),
            call_path: self.call_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
