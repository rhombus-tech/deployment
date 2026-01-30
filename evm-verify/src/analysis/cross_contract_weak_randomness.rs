/// Cross-Contract Weak Randomness Analyzer
/// 
/// YOUR COMPETITIVE ADVANTAGE: Tracks randomness propagation across protocol
/// 
/// Contract A generates weak random number (blockhash)
/// Contract B uses A's random value for critical decision
/// Contract C depends on B's outcome
/// 
/// Attacker can manipulate ENTIRE PROTOCOL by controlling single random source!

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractWeakRandomness {
    pub vulnerability_type: String,
    pub severity: String,
    pub randomness_source: H160,        // Contract generating weak random
    pub randomness_type: String,        // blockhash, timestamp, etc.
    pub dependent_contracts: Vec<H160>, // Contracts using this randomness
    pub propagation_path: Vec<H160>,    // How randomness flows through protocol
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractWeakRandomnessAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractWeakRandomnessAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractWeakRandomness> {
        let mut vulnerabilities = Vec::new();
        
        let contracts = self.protocol.get_contracts();
        
        // Step 1: Find all contracts generating weak randomness
        let random_sources = self.find_weak_randomness_sources(&contracts);
        
        // Step 2: For each source, trace how randomness propagates
        for (source_addr, random_type) in random_sources {
            let propagation = self.trace_randomness_propagation(source_addr, &contracts);
            
            if !propagation.dependent_contracts.is_empty() {
                vulnerabilities.push(CrossContractWeakRandomness {
                    vulnerability_type: "Cross-Contract Weak Randomness Propagation".to_string(),
                    severity: self.calculate_severity(&propagation),
                    randomness_source: source_addr,
                    randomness_type: random_type.clone(),
                    dependent_contracts: propagation.dependent_contracts.clone(),
                    propagation_path: propagation.path.clone(),
                    description: format!(
                        "CROSS-CONTRACT WEAK RANDOMNESS VULNERABILITY:\n\
                         Contract {:?} generates weak randomness using: {}\n\
                         This randomness propagates through protocol:\n\
                         {:?}\n\n\
                         {} contracts depend on this manipulable randomness!\n\
                         Attacker can control outcomes across ENTIRE PROTOCOL.",
                        source_addr, random_type, propagation.path,
                        propagation.dependent_contracts.len()
                    ),
                    exploit_scenario: format!(
                        "MULTI-CONTRACT RANDOMNESS MANIPULATION:\n\
                         \n\
                         Randomness source: {:?} using {}\n\
                         Propagation: {:?}\n\
                         \n\
                         Attack scenario:\n\
                         1. Contract A uses {} for random number\n\
                         2. Contract B calls A to get random value\n\
                         3. Contract C uses B's result for distribution\n\
                         4. Contract D relies on C's state\n\
                         \n\
                         Attacker manipulates {}:\n\
                         - Miners can adjust timestamp by ~15 seconds\n\
                         - Miners can withhold blocks to change blockhash\n\
                         - Attacker can brute-force by trying multiple blocks\n\
                         \n\
                         Result: Attacker controls randomness for {} contracts!\n\
                         \n\
                         Real examples:\n\
                         - Lottery contract using blockhash → exploited\n\
                         - NFT reveal using timestamp → manipulated\n\
                         - Reward distribution using block.number → gamed\n\
                         \n\
                         Single-contract tools miss the propagation!",
                        source_addr, random_type, propagation.path,
                        random_type, random_type,
                        propagation.dependent_contracts.len()
                    ),
                    remediation: format!(
                        "CROSS-CONTRACT RANDOMNESS PROTECTION:\n\
                         \n\
                         Current vulnerable flow: {:?}\n\
                         \n\
                         1. REPLACE WEAK RANDOMNESS SOURCE:\n\
                            - Remove {} from {:?}\n\
                            - Use Chainlink VRF (verifiable randomness)\n\
                            - Implement commit-reveal across protocol\n\
                         \n\
                         2. PROTOCOL-WIDE VRF INTEGRATION:\n\
                            ```solidity\n\
                            // Single VRF source for entire protocol\n\
                            contract RandomnessOracle {{\n\
                                VRFCoordinatorV2Interface COORDINATOR;\n\
                                \n\
                                function requestRandom() external returns (uint256 requestId) {{\n\
                                    return COORDINATOR.requestRandomWords(...);\n                                }}\n\
                                \n\
                                function fulfillRandom(uint256 requestId, uint256[] memory randomWords) {{\n\
                                    // Distribute to all dependent contracts\n\
                                }}\n\
                            }}\n\
                            ```\n\
                         \n\
                         3. ISOLATE RANDOMNESS DEPENDENCIES:\n\
                            - Don't cascade random values\n\
                            - Each contract should request VRF independently\n\
                            - Add delay between request and use\n\
                         \n\
                         4. DOCUMENT RANDOMNESS REQUIREMENTS:\n\
                            - Protocol-level randomness security policy\n\
                            - Audit all contracts for random number usage\n\
                            - Ban weak randomness sources (blockhash, timestamp)",
                        propagation.path, random_type, source_addr
                    ),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_weak_randomness_sources(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<(H160, String)> {
        let mut sources = Vec::new();
        
        for (addr, bytecode) in contracts {
            // Check for weak randomness opcodes
            for (i, &opcode) in bytecode.iter().enumerate() {
                let random_type = match opcode {
                    0x42 => {
                        // TIMESTAMP - check if used in arithmetic (randomness generation)
                        if self.used_for_randomness(bytecode, i) {
                            Some("block.timestamp")
                        } else {
                            None
                        }
                    }
                    0x40 => Some("blockhash"), // BLOCKHASH
                    0x43 => {
                        // NUMBER - check if used for randomness
                        if self.used_for_randomness(bytecode, i) {
                            Some("block.number")
                        } else {
                            None
                        }
                    }
                    0x44 => Some("block.difficulty/prevrandao"), // DIFFICULTY
                    _ => None,
                };
                
                if let Some(rtype) = random_type {
                    sources.push((*addr, rtype.to_string()));
                    break; // One per contract is enough
                }
            }
        }
        
        sources
    }
    
    fn used_for_randomness(&self, bytecode: &[u8], opcode_pos: usize) -> bool {
        // Check if opcode result is used with MOD (common for randomness)
        let window_end = (opcode_pos + 15).min(bytecode.len());
        bytecode[opcode_pos..window_end]
            .iter()
            .any(|&op| op == 0x06) // MOD
    }
    
    fn trace_randomness_propagation(&self, source: H160, contracts: &HashMap<H160, &Vec<u8>>) -> RandomnessPropagation {
        let mut propagation = RandomnessPropagation {
            path: vec![source],
            dependent_contracts: Vec::new(),
        };
        
        // Find contracts that call the randomness source
        let direct_users = self.find_contracts_calling(source, contracts);
        propagation.dependent_contracts.extend(&direct_users);
        propagation.path.extend(&direct_users);
        
        // Find second-order dependencies (contracts calling the users)
        for user in &direct_users {
            let indirect_users = self.find_contracts_calling(*user, contracts);
            for indirect in indirect_users {
                if !propagation.dependent_contracts.contains(&indirect) {
                    propagation.dependent_contracts.push(indirect);
                    propagation.path.push(indirect);
                }
            }
        }
        
        propagation
    }
    
    fn find_contracts_calling(&self, target: H160, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let mut callers = Vec::new();
        
        for (addr, bytecode) in contracts {
            if *addr == target {
                continue;
            }
            
            // Check if this contract has external calls (could call target)
            let has_external_calls = bytecode.iter().any(|&op| {
                matches!(op, 0xF1 | 0xF4 | 0xFA) // CALL, DELEGATECALL, STATICCALL
            });
            
            // In real impl, would check if calls go to target specifically
            // For now, conservatively assume external call could be to target
            if has_external_calls {
                callers.push(*addr);
            }
        }
        
        callers
    }
    
    fn calculate_severity(&self, propagation: &RandomnessPropagation) -> String {
        match propagation.dependent_contracts.len() {
            0 => "Low".to_string(),
            1..=2 => "Medium".to_string(),
            3..=5 => "High".to_string(),
            _ => "Critical".to_string(),
        }
    }
}

struct RandomnessPropagation {
    path: Vec<H160>,
    dependent_contracts: Vec<H160>,
}

impl CrossContractWeakRandomness {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: match self.severity.as_str() {
                "Critical" => SecuritySeverity::Critical,
                "High" => SecuritySeverity::High,
                "Medium" => SecuritySeverity::Medium,
                _ => SecuritySeverity::Low,
            },
            description: self.description.clone(),
            call_path: self.propagation_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cross_contract_randomness_propagation() {
        // Test: RNG contract using blockhash
        // Lottery contract calls RNG
        // Distribution contract uses Lottery results
        // Should detect propagation chain
    }
}
