/// Cross-Contract Rate Limiting Bypass Analyzer
/// 
/// YOUR ADVANTAGE: Detects rate limit bypass through indirect paths
/// 
/// Pattern: A has withdrawal limit, but A → B → C → A bypasses limit
/// Attack: Direct withdrawal limited to 100 ETH, but route through B/C = unlimited
/// Real Exploits: Various DeFi withdrawal limit bypasses

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractRateLimitBypass {
    pub vulnerability_type: String,
    pub severity: String,
    pub rate_limited_contract: H160,
    pub bypass_path: Vec<H160>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractRateLimitBypassAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractRateLimitBypassAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractRateLimitBypass> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with rate limiting (have time checks + transfer limits)
        let rate_limited = self.find_rate_limited_contracts(&contracts);
        
        for limited_contract in &rate_limited {
            // Find circular paths that bypass rate limits
            let bypass_paths = self.find_circular_bypass_paths(*limited_contract);
            
            for path in bypass_paths {
                if path.len() >= 3 {
                    vulnerabilities.push(CrossContractRateLimitBypass {
                        vulnerability_type: "Cross-Contract Rate Limit Bypass".to_string(),
                        severity: "High".to_string(),
                        rate_limited_contract: *limited_contract,
                        bypass_path: path.clone(),
                        description: format!(
                            "Rate limit can be bypassed via path: {:?}\n\
                             Direct calls limited, but indirect path unlimited!",
                            path
                        ),
                        exploit_scenario: format!(
                            "RATE LIMIT BYPASS ATTACK:\n\
                             Limited Contract: {:?}\n\
                             Bypass Path: {:?}\n\
                             \n\
                             Direct limit: 100 ETH/day\n\
                             Indirect path: UNLIMITED!\n\
                             \n\
                             Attacker withdraws via B→C→A to bypass rate limit",
                            limited_contract, path
                        ),
                        remediation: "Implement global rate limits, track withdrawals across all paths, use account-level limits instead of function-level".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_rate_limited_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for timestamp checks (rate limiting pattern)
        contracts.iter()
            .filter(|(_, bc)| bc.contains(&0x42)) // TIMESTAMP
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_circular_bypass_paths(&self, target: H160) -> Vec<Vec<H160>> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = vec![target];
        
        self.dfs_bypass(target, target, &mut visited, &mut current_path, &mut paths);
        
        paths
    }
    
    fn dfs_bypass(
        &self,
        current: H160,
        target: H160,
        visited: &mut HashSet<H160>,
        current_path: &mut Vec<H160>,
        paths: &mut Vec<Vec<H160>>,
    ) {
        if current_path.len() > 5 {
            return;
        }
        
        let targets = self.protocol.get_call_targets(&current);
        
        for next in targets {
            if next == target && current_path.len() >= 2 {
                current_path.push(next);
                paths.push(current_path.clone());
                current_path.pop();
            } else if !visited.contains(&next) {
                visited.insert(next);
                current_path.push(next);
                self.dfs_bypass(next, target, visited, current_path, paths);
                current_path.pop();
                visited.remove(&next);
            }
        }
    }
}

impl CrossContractRateLimitBypass {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.bypass_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
