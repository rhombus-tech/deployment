/// Cross-Contract Token Approval Chain Analyzer
/// 
/// YOUR ADVANTAGE: Tracks multi-hop approval delegation
/// 
/// Real Exploits: Uranium Finance ($50M), Spartan Protocol ($30M)
/// Pattern: User approves A → A approves B → B approves C → C drains User
/// Attack: Unintended delegation through approval chains

use ethers::types::H160;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractApprovalChain {
    pub vulnerability_type: String,
    pub severity: String,
    pub approval_chain: Vec<H160>,  // User → A → B → C → Attacker
    pub max_chain_length: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractApprovalChainAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractApprovalChainAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractApprovalChain> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts that use approve() and transferFrom()
        let approval_contracts = self.find_approval_contracts(&contracts);
        
        // Build approval graph
        for start_contract in &approval_contracts {
            let chains = self.find_approval_chains(*start_contract, &approval_contracts, 5);
            
            for chain in chains {
                if chain.len() >= 3 {  // At least User → A → B
                    vulnerabilities.push(CrossContractApprovalChain {
                        vulnerability_type: "Cross-Contract Approval Chain".to_string(),
                        severity: if chain.len() >= 4 { "Critical" } else { "High" }.to_string(),
                        approval_chain: chain.clone(),
                        max_chain_length: chain.len(),
                        description: format!(
                            "Approval delegation chain of length {}: {:?}\n\
                             Final contract in chain can drain tokens approved to first contract!",
                            chain.len(), chain
                        ),
                        exploit_scenario: format!(
                            "APPROVAL CHAIN EXPLOITATION:\n\
                             Chain: {:?}\n\
                             \n\
                             Attack:\n\
                             1. User approves {} tokens to Contract A\n\
                             2. Contract A approves Contract B (for legitimate operations)\n\
                             3. Contract B approves Contract C (vault/strategy pattern)\n\
                             4. If C is malicious or compromised → drains User's tokens!\n\
                             \n\
                             Real examples:\n\
                             - Uranium Finance: $50M via approval chain\n\
                             - Spartan Protocol: $30M via delegation bug\n\
                             \n\
                             User thought they only approved A, but C got access!",
                            chain, "unlimited"
                        ),
                        remediation: "Limit approval amounts, avoid delegating approvals, implement approval whitelists".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_approval_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let approve_selector = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
        let transfer_from_selector = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom
        
        contracts.iter()
            .filter(|(_, bc)| {
                bc.windows(4).any(|w| w == &approve_selector) ||
                bc.windows(4).any(|w| w == &transfer_from_selector)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_approval_chains(
        &self,
        start: H160,
        approval_contracts: &[H160],
        max_depth: usize,
    ) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        
        queue.push_back(vec![start]);
        visited.insert(start);
        
        while let Some(chain) = queue.pop_front() {
            if chain.len() >= max_depth {
                if chain.len() >= 3 {
                    chains.push(chain);
                }
                continue;
            }
            
            if let Some(&last) = chain.last() {
                let targets = self.protocol.get_call_targets(&last);
                
                for target in targets {
                    if approval_contracts.contains(&target) && !visited.contains(&target) {
                        let mut new_chain = chain.clone();
                        new_chain.push(target);
                        queue.push_back(new_chain);
                        visited.insert(target);
                    }
                }
            }
        }
        
        chains
    }
}

impl CrossContractApprovalChain {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::ValueLeakage,
            severity: if self.severity == "Critical" { SecuritySeverity::Critical } else { SecuritySeverity::High },
            description: self.description.clone(),
            call_path: self.approval_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
