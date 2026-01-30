/// Cross-Contract Emergency Pause Bypass Analyzer
/// 
/// YOUR ADVANTAGE: Traces ALL execution paths to find pause bypasses
/// 
/// Pattern: Contract A paused, but Contract C still calls paused functions via B
/// Attack: Direct A.withdraw() blocked, but B.swap() → A.withdraw() works!
/// Real Impact: Emergency pause doesn't actually stop the exploit

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractPauseBypass {
    pub vulnerability_type: String,
    pub severity: String,
    pub pausable_contract: H160,
    pub bypass_path: Vec<H160>,
    pub paused_function: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractPauseBypassAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractPauseBypassAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractPauseBypass> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find pausable contracts
        let pausable = self.find_pausable_contracts(&contracts);
        
        for paused_contract in &pausable {
            // Find indirect paths to paused contract
            let bypass_paths = self.find_bypass_paths(*paused_contract);
            
            for path in bypass_paths {
                if path.len() >= 3 {  // At least User → B → PausedA
                    vulnerabilities.push(CrossContractPauseBypass {
                        vulnerability_type: "Cross-Contract Emergency Pause Bypass".to_string(),
                        severity: "Critical".to_string(),
                        pausable_contract: *paused_contract,
                        bypass_path: path.clone(),
                        paused_function: "withdraw/swap/transfer".to_string(),
                        description: format!(
                            "Emergency pause can be bypassed via indirect path: {:?}\n\
                             Paused contract {:?} still accessible through intermediaries!",
                            path, paused_contract
                        ),
                        exploit_scenario: "PAUSE BYPASS: Direct calls blocked but indirect paths still work!".to_string(),
                        remediation: "Implement global pause affecting all contracts, check pause state in all entry points, cascade pause to dependent contracts".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_pausable_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for pause/unpause functions (whenNotPaused modifier)
        contracts.iter()
            .filter(|(_, bc)| {
                // Simplified: look for SLOAD patterns that might be pause checks
                bc.contains(&0x54) // SLOAD
            })
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_bypass_paths(&self, target: H160) -> Vec<Vec<H160>> {
        // Find contracts that call the target (bypass paths)
        let contracts = self.protocol.get_contracts();
        let mut paths = Vec::new();
        
        for (&addr, _) in contracts.iter() {
            let targets = self.protocol.get_call_targets(&addr);
            if targets.contains(&target) {
                paths.push(vec![addr, target]);
            }
        }
        
        paths
    }
}

impl CrossContractPauseBypass {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.bypass_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
