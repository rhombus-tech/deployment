/// Cross-Contract Fund Draining Path Analyzer
/// 
/// Detects multiple withdrawal/transfer paths across contracts that allow value extraction

use ethers::types::H160;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractFundDraining {
    pub vulnerability_type: String,
    pub severity: String,
    pub draining_path: Vec<H160>,
    pub value_flow: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractFundDrainingAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractFundDrainingAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractFundDraining> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with funds (have balance/assets)
        let fund_holders = self.find_fund_holders(&contracts);
        
        // Find withdrawal paths from each fund holder
        for holder in &fund_holders {
            let drain_paths = self.find_drain_paths(*holder, &contracts);
            
            for path in drain_paths {
                if path.len() >= 2 {
                    vulnerabilities.push(CrossContractFundDraining {
                        vulnerability_type: "Cross-Contract Fund Draining Path".to_string(),
                        severity: "Critical".to_string(),
                        draining_path: path.clone(),
                        value_flow: format!("{:?} → ... → Attacker", holder),
                        description: format!(
                            "Value draining path detected: {:?}\n\
                             Funds can flow from {:?} through {} contracts to attacker!",
                            path, holder, path.len() - 1
                        ),
                        exploit_scenario: format!(
                            "FUND DRAINING ATTACK:\n\
                             Path: {:?}\n\
                             \n\
                             Attack:\n\
                             1. Exploit contract {:?} to initiate transfer\n\
                             2. Value flows through {} intermediary contracts\n\
                             3. Final destination: Attacker wallet\n\
                             \n\
                             This circular/chained path bypasses single-contract protections!",
                            path, path.first(), path.len() - 2
                        ),
                        remediation: "Add transfer limits, multi-sig approvals, or whitelist destinations".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_fund_holders(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let asset_selectors = [[0x01, 0xe1, 0xd1, 0x14]]; // totalAssets()
        contracts.iter()
            .filter(|(_, bc)| asset_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_drain_paths(&self, start: H160, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<Vec<H160>> {
        let mut paths = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        
        queue.push_back(vec![start]);
        visited.insert(start);
        
        while let Some(path) = queue.pop_front() {
            if path.len() >= 4 {
                paths.push(path.clone());
                continue;
            }
            
            if let Some(&last) = path.last() {
                let targets = self.protocol.get_call_targets(&last);
                for target in targets {
                    if !visited.contains(&target) && self.has_transfer_capability(&target, contracts) {
                        let mut new_path = path.clone();
                        new_path.push(target);
                        queue.push_back(new_path);
                        visited.insert(target);
                    }
                }
            }
        }
        
        paths
    }
    
    fn has_transfer_capability(&self, contract: &H160, contracts: &HashMap<H160, &Vec<u8>>) -> bool {
        if let Some(bytecode) = contracts.get(contract) {
            let transfer_selectors = [[0xa9, 0x05, 0x9c, 0xbb]]; // transfer()
            transfer_selectors.iter().any(|sel| bytecode.windows(4).any(|w| w == sel))
        } else {
            false
        }
    }
}

impl CrossContractFundDraining {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::ValueLeakage,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.draining_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
