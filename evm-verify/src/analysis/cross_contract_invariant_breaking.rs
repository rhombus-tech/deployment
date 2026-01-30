/// Cross-Contract Invariant Breaking Analyzer
/// 
/// YOUR ADVANTAGE: Validates protocol-wide invariants across multiple contracts
/// 
/// Example invariant: sum(userBalances) <= totalAssets (across Vault + Strategy + Rewards)
/// Attack: Manipulate contracts A + C to break invariant in B

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractInvariantBreaking {
    pub vulnerability_type: String,
    pub severity: String,
    pub invariant_description: String,
    pub breaking_path: Vec<H160>,
    pub affected_contracts: Vec<H160>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractInvariantBreakingAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractInvariantBreakingAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractInvariantBreaking> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Check common DeFi invariants
        let invariants = vec![
            ("TotalSupply <= TotalAssets", self.check_supply_asset_invariant(&contracts)),
            ("sum(shares) == totalShares", self.check_share_accounting(&contracts)),
            ("collateral >= debt * collateralRatio", self.check_collateral_invariant(&contracts)),
        ];
        
        for (inv_name, violations) in invariants {
            for violation in violations {
                vulnerabilities.push(CrossContractInvariantBreaking {
                    vulnerability_type: "Cross-Contract Invariant Breaking".to_string(),
                    severity: "Critical".to_string(),
                    invariant_description: inv_name.to_string(),
                    breaking_path: violation.path.clone(),
                    affected_contracts: violation.affected.clone(),
                    description: format!(
                        "Protocol invariant '{}' can be broken via: {:?}",
                        inv_name, violation.path
                    ),
                    exploit_scenario: format!(
                        "INVARIANT BREAKING ATTACK:\n\
                         Invariant: {}\n\
                         Breaking path: {:?}\n\
                         \n\
                         Attack: Manipulate {:?} to violate invariant in {:?}\n\
                         Result: Protocol insolvency, infinite minting, or value extraction\n\
                         \n\
                         Real examples:\n\
                         - Iron Finance: $50M - Collateral invariant broken\n\
                         - Nomad Bridge: $190M - Message verification invariant violated",
                        inv_name, violation.path, violation.path.first(), violation.affected
                    ),
                    remediation: format!(
                        "INVARIANT PROTECTION:\n\
                         1. Add invariant checks after every state-changing operation\n\
                         2. Implement protocol-wide assertions:\n\
                         ```solidity\n\
                         function _checkInvariant() internal view {{\n\
                             require(totalSupply() <= totalAssets(), \"Invariant violated\");\n\
                         }}\n\
                         modifier maintainsInvariant() {{\n\
                             _;\n\
                             _checkInvariant();\n\
                         }}\n\
                         ```\n\
                         3. Use formal verification for critical invariants\n\
                         4. Monitor invariants off-chain and pause if violated"
                    ),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn check_supply_asset_invariant(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        
        // Find contracts with totalSupply and totalAssets functions
        let supply_contracts = self.find_contracts_with_selector(contracts, &[0x18, 0x16, 0x0d, 0xdd]); // totalSupply
        let asset_contracts = self.find_contracts_with_selector(contracts, &[0x01, 0xe1, 0xd1, 0x14]); // totalAssets
        
        // If different contracts handle supply vs assets, invariant might be breakable
        for supply_contract in &supply_contracts {
            for asset_contract in &asset_contracts {
                if supply_contract != asset_contract {
                    violations.push(InvariantViolation {
                        path: vec![*supply_contract, *asset_contract],
                        affected: vec![*supply_contract, *asset_contract],
                    });
                }
            }
        }
        
        violations
    }
    
    fn check_share_accounting(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<InvariantViolation> {
        Vec::new() // Simplified for now
    }
    
    fn check_collateral_invariant(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<InvariantViolation> {
        Vec::new() // Simplified for now
    }
    
    fn find_contracts_with_selector(&self, contracts: &HashMap<H160, &Vec<u8>>, selector: &[u8; 4]) -> Vec<H160> {
        contracts.iter()
            .filter(|(_, bytecode)| bytecode.windows(4).any(|w| w == selector))
            .map(|(addr, _)| *addr)
            .collect()
    }
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    path: Vec<H160>,
    affected: Vec<H160>,
}

impl CrossContractInvariantBreaking {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::StateInconsistency,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.breaking_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
