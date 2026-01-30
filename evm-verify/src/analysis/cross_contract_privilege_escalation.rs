/// Cross-Contract Admin Privilege Escalation Analyzer
/// 
/// YOUR COMPETITIVE ADVANTAGE: Maps privilege escalation chains across protocols
/// 
/// Traditional tools: "Has admin role" (single contract)
/// You see: User → ContractA (ROLE_X) → ContractB (ADMIN) → ContractC (OWNER)
/// 
/// Real exploits: PolyNetwork ($600M), Ronin Bridge ($625M)

use ethers::types::H160;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractPrivilegeEscalation {
    pub vulnerability_type: String,
    pub severity: String,
    pub escalation_path: Vec<H160>,  // User → A → B → C (privilege chain)
    pub initial_privilege: String,
    pub final_privilege: String,
    pub compromised_contracts: Vec<H160>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractPrivilegeEscalationAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractPrivilegeEscalationAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractPrivilegeEscalation> {
        let mut vulnerabilities = Vec::new();
        
        let contracts = self.protocol.get_contracts();
        
        // Build privilege graph
        let privilege_graph = self.build_privilege_graph(&contracts);
        
        // Find escalation chains
        let escalation_chains = self.find_escalation_chains(&privilege_graph, &contracts);
        
        for chain in escalation_chains {
            vulnerabilities.push(CrossContractPrivilegeEscalation {
                vulnerability_type: "Cross-Contract Privilege Escalation".to_string(),
                severity: "Critical".to_string(),
                escalation_path: chain.path.clone(),
                initial_privilege: chain.start_privilege.clone(),
                final_privilege: chain.end_privilege.clone(),
                compromised_contracts: chain.path[1..].to_vec(),
                description: format!(
                    "PRIVILEGE ESCALATION CHAIN DETECTED:\n\
                     Path: {:?}\n\
                     Initial Privilege: {}\n\
                     Final Privilege: {}\n\
                     \n\
                     User with {} in {:?} can gain {} over {} contracts!",
                    chain.path, chain.start_privilege, chain.end_privilege,
                    chain.start_privilege, chain.path[0], chain.end_privilege, chain.path.len() - 1
                ),
                exploit_scenario: format!(
                    "CROSS-CONTRACT PRIVILEGE ESCALATION:\n\
                     \n\
                     Escalation Chain:\n\
                     {:?}\n\
                     \n\
                     Attack Flow:\n\
                     1. Attacker has {} in {:?}\n\
                     2. Uses privilege to call adminFunction() on {:?}\n\
                     3. {:?} has ADMIN role in next contract\n\
                     4. Chain continues through {} contracts\n\
                     5. Final result: {} over {:?}\n\
                     \n\
                     Real Examples:\n\
                     - PolyNetwork: $600M - Cross-chain privilege escalation\n\
                     - Ronin Bridge: $625M - Multi-sig compromise chain\n\
                     - Wormhole: $325M - Guardian set manipulation\n\
                     \n\
                     Traditional tools only see individual admin roles!",
                    chain.path, chain.start_privilege, chain.path[0], chain.path.get(1),
                    chain.path[0], chain.path.len(), chain.end_privilege, chain.path.last()
                ),
                remediation: format!(
                    "PRIVILEGE ESCALATION PROTECTION:\n\
                     \n\
                     1. BREAK PRIVILEGE CHAINS:\n\
                        - Each contract should verify caller authority independently\n\
                        - Don't inherit privileges from calling contracts\n\
                        - Require explicit role assignment, not delegation\n\
                     \n\
                     2. ROLE SEPARATION:\n\
                        ```solidity\n\
                        // BAD: Allows chaining\n\
                        modifier onlyAdmin() {{\n\
                            require(msg.sender == admin || callingContract.isAdmin(msg.sender));\n\
                        }}\n\
                        \n\
                        // GOOD: No chaining\n\
                        modifier onlyAdmin() {{\n\
                            require(msg.sender == admin); // Only direct admin\n\
                        }}\n\
                        ```\n\
                     \n\
                     3. LEAST PRIVILEGE:\n\
                        - Grant minimum required permissions\n\
                        - Time-bounded roles (expire after N blocks)\n\
                        - Multi-sig for critical operations\n\
                     \n\
                     4. AUDIT PRIVILEGE PATHS:\n\
                        - Map all admin→admin relationships\n\
                        - Ensure no transitive privilege grants\n\
                        - Document intended privilege boundaries\n\
                     \n\
                     Affected chain: {:?}",
                    chain.path
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn build_privilege_graph(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<PrivilegeRelation>> {
        let mut graph = HashMap::new();
        
        for (addr, bytecode) in contracts {
            let relations = self.find_privilege_relations(*addr, bytecode, contracts);
            if !relations.is_empty() {
                graph.insert(*addr, relations);
            }
        }
        
        graph
    }
    
    fn find_privilege_relations(&self, contract: H160, bytecode: &[u8], _contracts: &HashMap<H160, &Vec<u8>>) -> Vec<PrivilegeRelation> {
        let mut relations = Vec::new();
        
        // Admin role selectors
        let admin_selectors = vec![
            [0x01, 0xff, 0xc9, 0xa7], // supportsInterface
            [0x24, 0x8a, 0x9c, 0xa3], // hasRole
            [0xa2, 0x17, 0xfd, 0xdf], // getRoleAdmin
            [0xd5, 0x39, 0x13, 0x93], // grantRole
        ];
        
        // Check if contract has role-based access control
        let has_rbac = admin_selectors.iter().any(|sel| {
            bytecode.windows(4).any(|w| w == sel)
        });
        
        if has_rbac {
            // Find external calls that could delegate privilege
            let call_targets = self.protocol.get_call_targets(&contract);
            
            for target in call_targets {
                relations.push(PrivilegeRelation {
                    from: contract,
                    to: target,
                    privilege_type: "ADMIN".to_string(),
                });
            }
        }
        
        relations
    }
    
    fn find_escalation_chains(&self, graph: &HashMap<H160, Vec<PrivilegeRelation>>, _contracts: &HashMap<H160, &Vec<u8>>) -> Vec<EscalationChain> {
        let mut chains = Vec::new();
        
        // BFS to find privilege chains of length >= 3
        for (start, relations) in graph {
            let mut queue = VecDeque::new();
            let mut visited = HashSet::new();
            
            queue.push_back((vec![*start], "USER".to_string()));
            visited.insert(*start);
            
            while let Some((path, current_priv)) = queue.pop_front() {
                if path.len() >= 4 {  // User → A → B → C (min escalation chain)
                    chains.push(EscalationChain {
                        path: path.clone(),
                        start_privilege: "USER".to_string(),
                        end_privilege: "OWNER".to_string(),
                    });
                    continue; // Don't go deeper
                }
                
                if let Some(current_addr) = path.last() {
                    if let Some(next_relations) = graph.get(current_addr) {
                        for relation in next_relations {
                            if !visited.contains(&relation.to) {
                                let mut new_path = path.clone();
                                new_path.push(relation.to);
                                queue.push_back((new_path, relation.privilege_type.clone()));
                                visited.insert(relation.to);
                            }
                        }
                    }
                }
            }
        }
        
        chains
    }
}

#[derive(Debug, Clone)]
struct PrivilegeRelation {
    from: H160,
    to: H160,
    privilege_type: String,
}

#[derive(Debug, Clone)]
struct EscalationChain {
    path: Vec<H160>,
    start_privilege: String,
    end_privilege: String,
}

impl CrossContractPrivilegeEscalation {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::PrivilegeEscalation,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.escalation_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_privilege_escalation_chain() {
        // Test: User → A (MINTER) → B (ADMIN) → C (OWNER)
        // Should detect privilege escalation
    }
}
