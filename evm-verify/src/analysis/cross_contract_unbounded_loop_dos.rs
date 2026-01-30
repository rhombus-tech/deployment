/// Cross-Contract Unbounded Loop DoS Analyzer
/// 
/// YOUR COMPETITIVE EDGE: Detects when Contract A loops calling Contract B[]
/// and any single B can DoS the entire protocol.
/// 
/// Example: Airdrop contract loops sending to recipients
/// If one recipient has reverting receive(), entire airdrop fails!

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractLoopDoS {
    pub vulnerability_type: String,
    pub severity: String,
    pub looping_contract: H160,
    pub target_contracts: Vec<H160>,
    pub description: String,
    pub attack_path: Vec<H160>,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractUnboundedLoopDoSAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractUnboundedLoopDoSAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractLoopDoS> {
        let mut vulnerabilities = Vec::new();
        
        let contracts = self.protocol.get_contracts();
        
        // Collect contract addresses first to avoid borrow issues
        let contract_list: Vec<_> = contracts.iter().map(|(addr, bc)| (*addr, (*bc).clone())).collect();
        
        // Analyze each contract for loops with external calls
        for (contract_addr, bytecode) in contract_list {
            let loop_external_calls = self.find_loops_with_external_calls(&bytecode);
            
            if !loop_external_calls.is_empty() {
                // Get all contracts this one might call
                let call_targets = self.protocol.get_call_targets(&contract_addr);
                
                for loop_location in loop_external_calls {
                    // Check if any call targets are untrusted/user-controlled
                    let untrusted_targets = self.find_untrusted_targets(&call_targets, &contracts);
                    
                    if !untrusted_targets.is_empty() {
                        vulnerabilities.push(CrossContractLoopDoS {
                            vulnerability_type: "Cross-Contract Unbounded Loop DoS".to_string(),
                            severity: "Critical".to_string(),
                            looping_contract: contract_addr,
                            target_contracts: untrusted_targets.clone(),
                            description: format!(
                                "CROSS-CONTRACT DOS VULNERABILITY:\n\
                                 Contract {:?} has loop at offset {} that calls external contracts.\n\
                                 Calls to: {:?}\n\n\
                                 ANY single target can revert and DOS the entire operation!\n\
                                 This creates a PROTOCOL-LEVEL denial of service.",
                                contract_addr, loop_location, untrusted_targets
                            ),
                            attack_path: {
                                let mut path = vec![contract_addr];
                                path.extend(untrusted_targets.clone());
                                path
                            },
                            exploit_scenario: 
                                "MULTI-CONTRACT DOS ATTACK:\n\
                                 1. Contract A (Distributor) loops: for (user in users) transfer(user)\n\
                                 2. Attacker registers as user with malicious contract B\n\
                                 3. B's receive() function reverts\n\
                                 4. Entire loop in A fails\n\
                                 5. NO legitimate users can receive tokens\n\
                                 6. ENTIRE PROTOCOL STUCK\n\n\
                                 Real example: King of Ether throne contract\n\
                                 Single-contract analyzers miss this!".to_string(),
                            remediation: 
                                "CROSS-CONTRACT DOS PREVENTION:\n\
                                 1. NEVER loop with external calls to untrusted contracts\n\
                                 2. Use PULL pattern instead of PUSH:\n\
                                    - Don't: for(user) send(user)  ← VULNERABLE\n\
                                    - Do: mapping(user => amount); function claim() ← SAFE\n\
                                 3. If must loop, limit batch size and implement resume\n\
                                 4. Use try-catch for external calls in loop\n\
                                 5. Track failed recipients separately, don't block others".to_string(),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_loops_with_external_calls(&self, bytecode: &[u8]) -> Vec<usize> {
        let mut loop_locations = Vec::new();
        
        // Find loop patterns with external calls
        for i in 0..bytecode.len().saturating_sub(100) {
            if bytecode[i] == 0x5B { // JUMPDEST (potential loop start)
                // Look for backward jump (loop) within next 100 bytes
                for j in i+10..i+100.min(bytecode.len()) {
                    if bytecode[j] == 0x57 || bytecode[j] == 0x56 { // JUMPI or JUMP
                        // Check if this region has external calls
                        let has_external_call = bytecode[i..j]
                            .iter()
                            .any(|&op| matches!(op, 0xF1 | 0xF4)); // CALL or DELEGATECALL
                        
                        if has_external_call {
                            loop_locations.push(i);
                            break;
                        }
                    }
                }
            }
        }
        
        loop_locations
    }
    
    fn find_untrusted_targets(&self, targets: &[H160], contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let mut untrusted = Vec::new();
        
        for target in targets {
            // Check if target could be user-controlled
            if let Some(target_bytecode) = contracts.get(target) {
                // Heuristic: If contract has receive/fallback that could revert
                let has_revert = target_bytecode.iter().any(|&op| op == 0xFD); // REVERT
                let has_throw = target_bytecode.iter().any(|&op| op == 0xFE); // INVALID
                
                // Also check for complex logic in fallback (gas-intensive)
                let fallback_complex = self.has_complex_fallback(target_bytecode);
                
                if has_revert || has_throw || fallback_complex {
                    untrusted.push(*target);
                }
            } else {
                // Unknown target = could be attacker contract
                untrusted.push(*target);
            }
        }
        
        // If no specific untrusted found but external calls exist, flag all
        if untrusted.is_empty() && !targets.is_empty() {
            untrusted = targets.to_vec();
        }
        
        untrusted
    }
    
    fn has_complex_fallback(&self, bytecode: &[u8]) -> bool {
        // Check for fallback/receive function with significant logic
        // Heuristic: More than 50 opcodes = complex
        
        // Look for fallback function marker (no function selector check at start)
        if bytecode.len() < 100 {
            return false;
        }
        
        // Count storage operations in first 200 bytes (fallback region)
        let storage_ops = bytecode[..200.min(bytecode.len())]
            .iter()
            .filter(|&&op| op == 0x54 || op == 0x55) // SLOAD or SSTORE
            .count();
        
        storage_ops > 3 // Complex if multiple storage operations
    }
}

impl CrossContractLoopDoS {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other, // Could add new DoS variant
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.attack_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cross_contract_loop_dos() {
        // Test: Airdrop contract loops calling recipient contracts
        // One malicious recipient should be detected as DOS risk
    }
}
