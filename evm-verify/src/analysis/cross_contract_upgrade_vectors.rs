/// Cross-Contract Upgrade Attack Vectors
/// 
/// Detects: Contract A depends on Contract B interface → B upgrades → A breaks

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractUpgradeVector {
    pub vulnerability_type: String,
    pub severity: String,
    pub dependency_chain: Vec<H160>,
    pub upgradeable_contracts: Vec<H160>,
    pub dependent_contracts: Vec<H160>,
    pub description: String,
    pub remediation: String,
}

pub struct CrossContractUpgradeVectorAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractUpgradeVectorAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractUpgradeVector> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find upgradeable contracts (proxies)
        let upgradeables = self.find_upgradeable_contracts(&contracts);
        
        // For each upgradeable, find dependents
        for upgradeable in &upgradeables {
            let dependents = self.find_dependent_contracts(*upgradeable, &contracts);
            
            if !dependents.is_empty() {
                vulnerabilities.push(CrossContractUpgradeVector {
                    vulnerability_type: "Cross-Contract Upgrade Risk".to_string(),
                    severity: "High".to_string(),
                    dependency_chain: {
                        let mut chain = dependents.clone();
                        chain.insert(0, *upgradeable);
                        chain
                    },
                    upgradeable_contracts: vec![*upgradeable],
                    dependent_contracts: dependents.clone(),
                    description: format!(
                        "Upgradeable contract {:?} has {} dependents. \
                         Malicious upgrade could break dependent contracts!",
                        upgradeable, dependents.len()
                    ),
                    remediation: "Use immutable interfaces, version checks, or timelock upgrades".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_upgradeable_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let upgrade_selectors = [[0x3d, 0x18, 0xb9, 0x12]]; // implementation()
        contracts.iter()
            .filter(|(_, bc)| upgrade_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_dependent_contracts(&self, upgradeable: H160, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.keys()
            .filter(|&&addr| addr != upgradeable && self.protocol.get_call_targets(&addr).contains(&upgradeable))
            .cloned()
            .collect()
    }
}

impl CrossContractUpgradeVector {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::UpgradeDependencyRisk,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.dependency_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
