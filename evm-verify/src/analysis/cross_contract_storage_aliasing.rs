/// Cross-Contract Storage Pointer Aliasing Analyzer
/// 
/// YOUR ADVANTAGE: Detect storage collisions across delegatecall chains
/// 
/// Pattern: Proxy → Impl_A → Impl_B with overlapping storage layouts
/// Attack: Delegate to contract with different storage layout → corruption
/// Real Exploits: Parity multi-sig wallet ($150M+)

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractStorageAliasing {
    pub vulnerability_type: String,
    pub severity: String,
    pub delegatecall_chain: Vec<H160>,
    pub storage_collision_risk: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractStorageAliasingAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractStorageAliasingAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractStorageAliasing> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts using delegatecall
        let delegatecall_contracts = self.find_delegatecall_contracts(&contracts);
        
        for contract in &delegatecall_contracts {
            let chain = self.build_delegatecall_chain(*contract);
            
            if chain.len() >= 2 {
                vulnerabilities.push(CrossContractStorageAliasing {
                    vulnerability_type: "Cross-Contract Storage Pointer Aliasing".to_string(),
                    severity: "Critical".to_string(),
                    delegatecall_chain: chain.clone(),
                    storage_collision_risk: "High - different storage layouts can corrupt state".to_string(),
                    description: format!(
                        "Storage collision risk in delegatecall chain: {:?}\n\
                         Different contracts may have overlapping storage layouts!",
                        chain
                    ),
                    exploit_scenario: format!(
                        "STORAGE ALIASING ATTACK:\n\
                         Delegatecall Chain: {:?}\n\
                         \n\
                         Attack:\n\
                         Proxy has: slot0=owner, slot1=balance\n\
                         Implementation has: slot0=paused, slot1=admin\n\
                         \n\
                         Delegatecall executes in Proxy's storage context\n\
                         → Implementation writes to slot0 thinking it's 'paused'\n\
                         → Actually overwrites Proxy's 'owner'!\n\
                         \n\
                         Result: Complete takeover via storage corruption\n\
                         Real example: Parity multi-sig wallet ($150M+ lost)",
                        chain
                    ),
                    remediation: "Use consistent storage layouts, implement storage gaps, use EIP-1967 for upgradeable contracts".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_delegatecall_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // DELEGATECALL opcode = 0xF4
        contracts.iter()
            .filter(|(_, bc)| bc.contains(&0xF4))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn build_delegatecall_chain(&self, start: H160) -> Vec<H160> {
        let targets = self.protocol.get_call_targets(&start);
        let mut chain = vec![start];
        chain.extend(targets);
        chain
    }
}

impl CrossContractStorageAliasing {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.delegatecall_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
