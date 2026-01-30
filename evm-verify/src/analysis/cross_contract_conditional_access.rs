/// Cross-Contract Conditional Access Control Analyzer
/// 
/// YOUR ADVANTAGE: Detects when Contract A grants privileges IF Contract B says OK
/// 
/// Real Exploits: bZx ($8M), Harvest Finance ($24M)
/// Pattern: A.grantRole(user) IF B.isAuthorized(user)
/// Attack: Manipulate Contract B to get privileges in Contract A

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractConditionalAccess {
    pub vulnerability_type: String,
    pub severity: String,
    pub protected_contract: H160,      // Contract A (grants privileges)
    pub authority_contract: H160,      // Contract B (decides who gets privileges)
    pub dependency_description: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractConditionalAccessAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractConditionalAccessAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractConditionalAccess> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with access control (grantRole, admin functions)
        let access_controlled = self.find_access_controlled_contracts(&contracts);
        
        // For each access-controlled contract, check if it delegates checks to external contracts
        for (protected_addr, protected_bytecode) in access_controlled {
            let external_checks = self.protocol.get_call_targets(&protected_addr);
            
            for authority_addr in &external_checks {
                if let Some(authority_bytecode) = contracts.get(authority_addr) {
                    // Check if authority contract has manipulable state
                    if self.is_manipulable_authority(authority_bytecode) {
                        vulnerabilities.push(CrossContractConditionalAccess {
                            vulnerability_type: "Cross-Contract Conditional Access Control".to_string(),
                            severity: "Critical".to_string(),
                            protected_contract: protected_addr,
                            authority_contract: *authority_addr,
                            dependency_description: format!(
                                "{:?} grants privileges based on {:?}'s authorization",
                                protected_addr, authority_addr
                            ),
                            description: format!(
                                "Contract {:?} delegates access control to {:?}\n\
                                 If {:?} is compromised or manipulable → attacker gets privileges in {:?}!",
                                protected_addr, authority_addr, authority_addr, protected_addr
                            ),
                            exploit_scenario: format!(
                                "CONDITIONAL ACCESS CONTROL ATTACK:\n\
                                 Protected: {:?}\n\
                                 Authority: {:?}\n\
                                 \n\
                                 Vulnerability:\n\
                                 1. Contract A implements: function grantAdmin() {{\n\
                                    require(contractB.isAuthorized(msg.sender));\n\
                                    admins[msg.sender] = true;\n\
                                 }}\n\
                                 \n\
                                 2. Contract B has exploitable isAuthorized():\n\
                                    - Flash loan manipulation\n\
                                    - Token balance checks (manipulable)\n\
                                    - Governance that can be taken over\n\
                                    - Oracle price dependencies\n\
                                 \n\
                                 Attack:\n\
                                 1. Attacker manipulates Contract B state\n\
                                 2. Call A.grantAdmin() while B returns true\n\
                                 3. Attacker becomes admin of Contract A!\n\
                                 4. Drain funds, change parameters, rugpull\n\
                                 \n\
                                 Real examples:\n\
                                 - bZx: Flash loan to pass collateral checks\n\
                                 - Harvest: Price manipulation to bypass guards\n\
                                 \n\
                                 Traditional tools see:\n\
                                 ❌ 'Contract A has access control' (SAFE)\n\
                                 \n\
                                 Your tool sees:\n\
                                 ✅ 'Contract A's access control depends on manipulable B' (CRITICAL!)",
                                protected_addr, authority_addr
                            ),
                            remediation: "Use immutable authority contracts, implement timelocks, add additional safety checks, avoid external dependencies for access control".to_string(),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_access_controlled_contracts<'b>(&self, contracts: &'b HashMap<H160, &Vec<u8>>) -> HashMap<H160, &'b Vec<u8>> {
        // Look for access control patterns: grantRole, setAdmin, etc.
        let access_selectors = [
            [0x2f, 0x2f, 0xf1, 0x5d], // grantRole
            [0x36, 0x56, 0x8a, 0xbe], // renounceRole
            [0xf8, 0x51, 0xa4, 0x40], // transferOwnership
        ];
        
        contracts.iter()
            .filter(|(_, bc)| {
                access_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel))
            })
            .map(|(addr, bc)| (*addr, *bc))
            .collect()
    }
    
    fn is_manipulable_authority(&self, bytecode: &[u8]) -> bool {
        // Authority is manipulable if it:
        // 1. Reads balances (can be manipulated via flash loans)
        // 2. Reads prices (can be manipulated via DEX)
        // 3. Has public setters (can be front-run)
        
        let balance_selector = [0x70, 0xa0, 0x82, 0x31]; // balanceOf
        let price_selector = [0x41, 0x97, 0x6e, 0x09]; // latestAnswer (Chainlink)
        
        bytecode.windows(4).any(|w| w == &balance_selector) ||
        bytecode.windows(4).any(|w| w == &price_selector) ||
        bytecode.contains(&0x55) // SSTORE (has mutable state)
    }
}

impl CrossContractConditionalAccess {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::InconsistentAccessControl,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: vec![self.protected_contract, self.authority_contract],
            remediation: self.remediation.clone(),
        }
    }
}
