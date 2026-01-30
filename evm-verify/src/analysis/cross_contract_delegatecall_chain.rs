/// Cross-Contract Delegatecall Chain Analyzer
/// 
/// YOUR ADVANTAGE: Tracks delegatecall chains that can corrupt caller storage
/// 
/// Real Exploits: Parity Wallet ($150M+), various proxy bugs
/// Pattern: ProxyA → delegatecall(ImplB) → delegatecall(ImplC)
/// Attack: Deep delegatecall chains can corrupt storage layout

use ethers::types::H160;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractDelegatecallChain {
    pub vulnerability_type: String,
    pub severity: String,
    pub delegatecall_chain: Vec<H160>,  // Proxy → Impl1 → Impl2 → ...
    pub chain_depth: usize,
    pub storage_corruption_risk: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractDelegatecallChainAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractDelegatecallChainAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractDelegatecallChain> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with DELEGATECALL
        let delegatecall_contracts = self.find_delegatecall_contracts(&contracts);
        
        // Build delegatecall chains
        for start in &delegatecall_contracts {
            let chains = self.find_delegatecall_chains(*start, &delegatecall_contracts);
            
            for chain in chains {
                if chain.len() >= 3 {  // Proxy → Impl → Impl (nested delegation)
                    vulnerabilities.push(CrossContractDelegatecallChain {
                        vulnerability_type: "Cross-Contract Delegatecall Chain".to_string(),
                        severity: if chain.len() >= 4 { "Critical" } else { "High" }.to_string(),
                        delegatecall_chain: chain.clone(),
                        chain_depth: chain.len(),
                        storage_corruption_risk: format!(
                            "Chain depth {} increases storage slot collision risk",
                            chain.len()
                        ),
                        description: format!(
                            "Delegatecall chain of depth {}: {:?}\n\
                             Each hop executes in caller's storage context - high collision risk!",
                            chain.len(), chain
                        ),
                        exploit_scenario: format!(
                            "DELEGATECALL CHAIN ATTACK:\n\
                             Chain: {:?}\n\
                             Depth: {}\n\
                             \n\
                             Attack:\n\
                             1. Proxy delegates to Implementation A\n\
                             2. Implementation A delegates to Implementation B\n\
                             3. All execute in Proxy's storage context\n\
                             4. Storage layouts must match EXACTLY across all contracts\n\
                             5. Any mismatch → storage corruption → critical vulnerabilities\n\
                             \n\
                             Real examples:\n\
                             - Parity Wallet: Delegatecall to library with selfdestruct\n\
                             - Multiple proxy upgrades with storage layout bugs\n\
                             \n\
                             Each additional hop in chain multiplies risk:\n\
                             - Slot 0 in Proxy vs Impl A vs Impl B might store different things\n\
                             - Owner in Proxy could be totalSupply in deep implementation!",
                            chain, chain.len()
                        ),
                        remediation: "Avoid nested delegatecalls, use storage gaps, implement EIP-1967 storage slots, formal verification of layouts".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_delegatecall_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.iter()
            .filter(|(_, bc)| bc.contains(&0xF4)) // DELEGATECALL opcode
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_delegatecall_chains(
        &self,
        start: H160,
        delegatecall_contracts: &[H160],
    ) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        
        queue.push_back(vec![start]);
        visited.insert(start);
        
        while let Some(chain) = queue.pop_front() {
            if chain.len() >= 6 {  // Prevent infinite loops
                if chain.len() >= 3 {
                    chains.push(chain);
                }
                continue;
            }
            
            if let Some(&last) = chain.last() {
                let targets = self.protocol.get_call_targets(&last);
                
                for target in targets {
                    if delegatecall_contracts.contains(&target) {
                        let mut new_chain = chain.clone();
                        new_chain.push(target);
                        
                        if visited.contains(&target) {
                            // Circular delegatecall - VERY dangerous!
                            chains.push(new_chain);
                        } else {
                            queue.push_back(new_chain);
                            visited.insert(target);
                        }
                    }
                }
            }
        }
        
        chains
    }
}

impl CrossContractDelegatecallChain {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::UpgradeDependencyRisk,
            severity: if self.severity == "Critical" { SecuritySeverity::Critical } else { SecuritySeverity::High },
            description: self.description.clone(),
            call_path: self.delegatecall_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
