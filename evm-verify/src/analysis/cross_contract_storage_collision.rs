/// Cross-Contract Storage Collision in Delegate Chains
/// 
/// Detects: Proxy → Implementation_A → delegatecall → Implementation_B
/// Risk: Storage layouts collide across the delegation chain

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractStorageCollision {
    pub vulnerability_type: String,
    pub severity: String,
    pub delegation_chain: Vec<H160>,
    pub collision_risk: String,
    pub description: String,
    pub remediation: String,
}

pub struct CrossContractStorageCollisionAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractStorageCollisionAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractStorageCollision> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find delegatecall chains
        let delegate_chains = self.find_delegatecall_chains(&contracts);
        
        for chain in delegate_chains {
            if chain.len() >= 3 { // Proxy → Impl → Impl chain
                vulnerabilities.push(CrossContractStorageCollision {
                    vulnerability_type: "Cross-Contract Storage Collision".to_string(),
                    severity: "High".to_string(),
                    delegation_chain: chain.clone(),
                    collision_risk: "Storage layout mismatch across delegation chain".to_string(),
                    description: format!(
                        "Delegatecall chain detected: {:?}\n\
                         Storage collision risk if layouts don't match!",
                        chain
                    ),
                    remediation: "Use storage gaps, verify layouts match, use EIP-1967 slots".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_delegatecall_chains(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        
        for (addr, bytecode) in contracts {
            if bytecode.iter().any(|&op| op == 0xF4) { // DELEGATECALL
                let targets = self.protocol.get_call_targets(addr);
                for target in targets {
                    chains.push(vec![*addr, target]);
                }
            }
        }
        
        chains
    }
}

impl CrossContractStorageCollision {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::UpgradeDependencyRisk,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.delegation_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
