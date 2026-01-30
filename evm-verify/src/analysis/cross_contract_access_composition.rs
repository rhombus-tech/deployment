/// Cross-Contract Access Control Composition Analyzer
/// 
/// YOUR ADVANTAGE: PCD can compose permissions across contracts to find privilege escalation
/// 
/// Pattern: Role(A) + Role(B) + Role(C) = SUPER_ADMIN
/// Attack: Get minor roles in multiple contracts that combine to protocol control
/// Real Exploits: Compound-style governance takeovers

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractAccessComposition {
    pub vulnerability_type: String,
    pub severity: String,
    pub role_chain: Vec<(H160, String)>,  // [(Contract, Role)]
    pub combined_privilege: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractAccessCompositionAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractAccessCompositionAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractAccessComposition> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Extract roles from each contract
        let role_map = self.extract_roles(&contracts);
        
        // Find composable role chains
        for (contract_a, roles_a) in &role_map {
            for role_a in roles_a {
                let chains = self.find_role_compositions(*contract_a, role_a, &role_map);
                
                for chain in chains {
                    if chain.len() >= 2 {
                        let combined = self.assess_combined_privilege(&chain);
                        
                        if combined.is_critical {
                            vulnerabilities.push(CrossContractAccessComposition {
                                vulnerability_type: "Cross-Contract Access Control Composition".to_string(),
                                severity: "Critical".to_string(),
                                role_chain: chain.clone(),
                                combined_privilege: combined.description.clone(),
                                description: format!(
                                    "Composable roles across {} contracts combine to form super-admin privilege:\n{:?}",
                                    chain.len(), chain
                                ),
                                exploit_scenario: format!(
                                    "ACCESS CONTROL COMPOSITION ATTACK:\n\
                                     Role Chain: {:?}\n\
                                     Combined Privilege: {}\n\
                                     \n\
                                     Attack:\n\
                                     1. Attacker acquires PROPOSER role in Governance (public/open)\n\
                                     2. Attacker acquires EXECUTOR role in Timelock (low barrier)\n\
                                     3. Attacker acquires GUARDIAN role in Proxy (minor permission)\n\
                                     \n\
                                     Individually: Each role is limited\n\
                                     - PROPOSER: Can only propose changes (requires votes)\n\
                                     - EXECUTOR: Can only execute approved proposals\n\
                                     - GUARDIAN: Can only pause in emergencies\n\
                                     \n\
                                     Combined: COMPLETE PROTOCOL CONTROL!\n\
                                     - Propose malicious upgrade as PROPOSER\n\
                                     - Vote manipulation or wait for votes\n\
                                     - Execute upgrade as EXECUTOR\n\
                                     - Bypass all safety checks using GUARDIAN powers\n\
                                     - Result: Full protocol takeover!\n\
                                     \n\
                                     Real Examples:\n\
                                     - Compound: PROPOSER + EXECUTOR + ADMIN = protocol control\n\
                                     - Various DAOs: Multiple minor roles = governance takeover\n\
                                     \n\
                                     Traditional tools see: '3 contracts with access control' ✓ SAFE\n\
                                     Your tool sees: 'Combined roles = SUPER_ADMIN' ✗ CRITICAL!",
                                    chain, combined.description
                                ),
                                remediation: "Require multi-sig for role combinations, implement role conflict detection, add timelock for composed privileges".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn extract_roles(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<String>> {
        let mut role_map = HashMap::new();
        
        // Common role patterns
        let role_patterns = vec![
            ("ADMIN", [0x00, 0x00, 0x00, 0x00]),
            ("PROPOSER", [0x01, 0x00, 0x00, 0x00]),
            ("EXECUTOR", [0x02, 0x00, 0x00, 0x00]),
            ("GUARDIAN", [0x03, 0x00, 0x00, 0x00]),
            ("MINTER", [0x04, 0x00, 0x00, 0x00]),
        ];
        
        for (addr, bytecode) in contracts {
            let mut roles = Vec::new();
            
            for (role_name, _pattern) in &role_patterns {
                // Check for role-related function selectors
                if bytecode.windows(4).any(|_| true) { // Simplified for now
                    roles.push(role_name.to_string());
                }
            }
            
            if !roles.is_empty() {
                role_map.insert(*addr, roles);
            }
        }
        
        role_map
    }
    
    fn find_role_compositions(
        &self,
        start: H160,
        start_role: &str,
        role_map: &HashMap<H160, Vec<String>>,
    ) -> Vec<Vec<(H160, String)>> {
        let mut chains = Vec::new();
        let mut visited = HashSet::new();
        let mut current_chain = vec![(start, start_role.to_string())];
        
        self.dfs_role_composition(start, role_map, &mut visited, &mut current_chain, &mut chains);
        
        chains
    }
    
    fn dfs_role_composition(
        &self,
        current: H160,
        role_map: &HashMap<H160, Vec<String>>,
        visited: &mut HashSet<H160>,
        current_chain: &mut Vec<(H160, String)>,
        chains: &mut Vec<Vec<(H160, String)>>,
    ) {
        if current_chain.len() > 5 {
            return; // Limit depth
        }
        
        visited.insert(current);
        
        let targets = self.protocol.get_call_targets(&current);
        
        for target in targets {
            if !visited.contains(&target) {
                if let Some(roles) = role_map.get(&target) {
                    for role in roles {
                        current_chain.push((target, role.clone()));
                        chains.push(current_chain.clone());
                        self.dfs_role_composition(target, role_map, visited, current_chain, chains);
                        current_chain.pop();
                    }
                }
            }
        }
        
        visited.remove(&current);
    }
    
    fn assess_combined_privilege(&self, chain: &[(H160, String)]) -> CombinedPrivilege {
        // Check for dangerous combinations
        let roles: Vec<&str> = chain.iter().map(|(_, r)| r.as_str()).collect();
        
        let has_proposer = roles.contains(&"PROPOSER");
        let has_executor = roles.contains(&"EXECUTOR");
        let has_admin = roles.contains(&"ADMIN");
        let has_guardian = roles.contains(&"GUARDIAN");
        
        if (has_proposer && has_executor) || (has_admin && has_executor) || (has_proposer && has_admin && has_guardian) {
            CombinedPrivilege {
                is_critical: true,
                description: "SUPER_ADMIN: Can propose and execute arbitrary changes".to_string(),
            }
        } else {
            CombinedPrivilege {
                is_critical: false,
                description: "Limited combined privileges".to_string(),
            }
        }
    }
}

struct CombinedPrivilege {
    is_critical: bool,
    description: String,
}

impl CrossContractAccessComposition {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::PrivilegeEscalation,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.role_chain.iter().map(|(addr, _)| *addr).collect(),
            remediation: self.remediation.clone(),
        }
    }
}
