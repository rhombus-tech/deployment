use serde::{Serialize, Deserialize};

/// Nomad Bridge Replica Bypass Detection ($190M August 2022)
/// 
/// The Nomad hack exploited a critical vulnerability where:
/// 1. Bridge replica contract had an uninitialized trusted root
/// 2. The `process()` function accepted any message as valid
/// 3. Attacker could prove ANY message against address(0) as root
/// 4. This allowed arbitrary token withdrawals without deposits
/// 5. Essentially: if (proof.verify(message, ZERO_HASH)) → execute withdrawal
///
/// Key patterns:
/// - Merkle proof verification against uninitialized storage (zero hash)
/// - Missing initialization checks in upgrade/proxy patterns
/// - Replica contract accepting messages without proper root validation
/// - Bridge message processing without origin chain verification

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NomadBridgeVulnerability {
    /// Critical: Merkle root verification against zero/uninitialized value
    UninitializedTrustedRoot {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// Critical: Message processing without proper root validation
    MissingRootValidation {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Proxy/Replica pattern with initialization vulnerability
    ProxyInitializationBypass {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Bridge message acceptance without origin verification
    NoOriginChainVerification {
        description: String,
        location: usize,
        confidence: f32,
    },
}

pub struct NomadBridgeReplicaBypassDetector {
    bytecode: Vec<u8>,
}

impl NomadBridgeReplicaBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NomadBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Uninitialized trusted root in Merkle verification
        vulnerabilities.extend(self.detect_uninitialized_trusted_root());
        
        // Pattern 2: Missing root validation in message processing
        vulnerabilities.extend(self.detect_missing_root_validation());
        
        // Pattern 3: Proxy initialization vulnerabilities
        vulnerabilities.extend(self.detect_proxy_initialization_issues());
        
        // Pattern 4: No origin chain verification
        vulnerabilities.extend(self.detect_missing_origin_verification());
        
        vulnerabilities
    }
    
    fn detect_uninitialized_trusted_root(&self) -> Vec<NomadBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for Merkle proof verification patterns
        // The Nomad bug: verify(proof, leaf, 0x00...00) returns true
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                
                // Look for Merkle proof verification (keccak256 in loops)
                let has_keccak = section.windows(2).any(|w| w == &[0x20, 0x20]); // SHA3
                let has_loop = section.contains(&0x57); // JUMPI (loop pattern)
                
                if has_keccak && has_loop {
                    // Check if comparing against SLOAD that might be uninitialized
                    let sload_pos = section.windows(1).position(|w| w[0] == 0x54);
                    
                    if let Some(pos) = sload_pos {
                        // Check if there's an ISZERO check after SLOAD (initialization check)
                        let after_sload = &section[pos..std::cmp::min(pos + 20, section.len())];
                        let has_init_check = after_sload.contains(&0x15); // ISZERO
                        let has_revert = after_sload.contains(&0xFD); // REVERT
                        
                        if !has_init_check || !has_revert {
                            vulnerabilities.push(NomadBridgeVulnerability::UninitializedTrustedRoot {
                                description: format!(
                                    "Merkle proof verification at PC {} may accept zero hash as valid root. \
                                    This is the EXACT Nomad bridge exploit pattern ($190M). \
                                    The trusted root storage slot is not checked for initialization, \
                                    allowing attackers to prove arbitrary messages against 0x00...00.",
                                    i
                                ),
                                location: i,
                                confidence: 0.93,
                            });
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_missing_root_validation(&self) -> Vec<NomadBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for message processing functions (process, handle, execute, etc.)
        let process_sigs = [
            &[0x02, 0x8c, 0x4c, 0x4e][..], // process()
            &[0xb2, 0x58, 0xd6, 0xe5][..], // handle()  
            &[0xfe, 0x9d, 0x93, 0x03][..], // execute()
        ];
        
        for sig in &process_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    // Found a processing function
                    let func_section = &self.bytecode[i..std::cmp::min(i + 300, self.bytecode.len())];
                    
                    // Check for Merkle proof verification
                    let has_merkle_verify = func_section.windows(2).any(|w| w == &[0x20, 0x20]); // SHA3
                    
                    // Check for trusted root loading
                    let has_root_load = func_section.contains(&0x54); // SLOAD
                    
                    // Check for comparison of computed root with trusted root
                    let has_root_comparison = func_section.contains(&0x14); // EQ
                    
                    if has_merkle_verify && (!has_root_load || !has_root_comparison) {
                        vulnerabilities.push(NomadBridgeVulnerability::MissingRootValidation {
                            description: format!(
                                "Bridge message processing at PC {} lacks proper root validation. \
                                Function accepts messages without comparing computed Merkle root \
                                to the trusted root. Nomad bridge was exploited because process() \
                                didn't validate the root parameter, accepting 0x00 as valid.",
                                i
                            ),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_proxy_initialization_issues(&self) -> Vec<NomadBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Nomad used a proxy pattern - look for initialize() functions
        let init_sigs = [
            vec![0x81, 0x29, 0xfc, 0x1c], // initialize()
            vec![0xc4, 0xd6, 0x6d, 0xe8], // initialize(address)
        ];
        
        for sig_bytes in &init_sigs {
            let sig = &sig_bytes[..];
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if self.bytecode.len() >= i + 4 && &self.bytecode[i..i + 4] == sig {
                    let func_section = &self.bytecode[i..std::cmp::min(i + 200, self.bytecode.len())];
                    
                    // Check for initialization guard (initialized flag)
                    let has_init_guard = func_section.windows(3).any(|w| {
                        w[0] == 0x54 && // SLOAD
                        w[1] == 0x15 && // ISZERO
                        w[2] == 0x57    // JUMPI
                    });
                    
                    // Check for critical state variable writes
                    let has_state_writes = func_section.contains(&0x55); // SSTORE
                    
                    if has_state_writes && !has_init_guard {
                        vulnerabilities.push(NomadBridgeVulnerability::ProxyInitializationBypass {
                            description: format!(
                                "Initialization function at PC {} lacks proper guards. \
                                Can be called multiple times or on wrong implementation. \
                                Nomad's replica contract was initialized with committedRoot = 0, \
                                making all Merkle proofs valid against the zero hash.",
                                i
                            ),
                            location: i,
                            confidence: 0.87,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_missing_origin_verification(&self) -> Vec<NomadBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for cross-chain message handling without domain/chain ID checks
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if i + 150 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 150];
                
                // Look for message data extraction (CALLDATALOAD patterns)
                let has_calldata = section.contains(&0x35); // CALLDATALOAD
                
                // Look for external call or state modification
                let has_call = section.contains(&0xF1) || // CALL
                               section.contains(&0xFA) || // STATICCALL
                               section.contains(&0x55);   // SSTORE
                
                if has_calldata && has_call {
                    // Check for chain ID or domain verification
                    let has_chainid_check = section.contains(&0x46); // CHAINID
                    let has_domain_verify = section.windows(10).any(|w| {
                        // Pattern: CALLDATALOAD → compare with expected domain
                        w.contains(&0x35) && w.contains(&0x14) // CALLDATALOAD + EQ
                    });
                    
                    if !has_chainid_check && !has_domain_verify {
                        vulnerabilities.push(NomadBridgeVulnerability::NoOriginChainVerification {
                            description: format!(
                                "Cross-chain message processing at PC {} doesn't verify origin domain. \
                                Messages from any chain could be replayed or spoofed. \
                                Should check message.origin matches expected remote domain ID.",
                                i
                            ),
                            location: i,
                            confidence: 0.82,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nomad_vulnerable_pattern() {
        // Simulate Nomad's vulnerable pattern:
        // Merkle verify loop without checking root != 0
        let bytecode = vec![
            0x54, // SLOAD (trusted root)
            0x20, // SHA3 (Merkle compute)
            0x20, // SHA3
            0x57, // JUMPI (loop)
            0x14, // EQ (compare)
            // Missing ISZERO check for root initialization
        ];
        
        let detector = NomadBridgeReplicaBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect Nomad-style vulnerability");
    }
    
    #[test]
    fn test_safe_initialized_root() {
        // Simulate safe pattern with initialization check
        let bytecode = vec![
            0x54, // SLOAD (trusted root)
            0x15, // ISZERO (check if zero)
            0x60, 0x00, // PUSH1 0
            0x57, // JUMPI (revert if zero)
            0xFD, // REVERT
            0x20, // SHA3 (Merkle compute)
            0x14, // EQ (compare)
        ];
        
        let detector = NomadBridgeReplicaBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should have fewer vulnerabilities due to initialization check
        let critical = vulns.iter().filter(|v| matches!(v, 
            NomadBridgeVulnerability::UninitializedTrustedRoot { confidence, .. } if *confidence > 0.9
        )).count();
        
        assert_eq!(critical, 0, "Should not flag safe initialization pattern");
    }
}
