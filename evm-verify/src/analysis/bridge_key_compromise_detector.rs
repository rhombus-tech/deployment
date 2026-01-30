use serde::{Serialize, Deserialize};

/// Bridge Key Compromise Detection (Multichain $126M, Ronin $600M+ patterns)
/// 
/// Detects centralization risks in bridge designs:
/// 1. Single signature controls massive funds
/// 2. Multisig with too low threshold
/// 3. No time delays on key changes
/// 4. Upgradeable with single admin
/// 5. Missing emergency pause mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeKeyCompromiseVulnerability {
    /// Critical: Single EOA controls bridge
    SinglePointOfFailure {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Multisig threshold too low
    InsecureMultisigThreshold {
        description: String,
        location: usize,
        threshold: u32,
        total_signers: u32,
    },
    /// High: No timelock on admin changes
    NoTimelockProtection {
        description: String,
        location: usize,
    },
    /// High: Upgradeable without sufficient protection
    DangerousUpgradeability {
        description: String,
        location: usize,
    },
    /// Medium: Missing emergency pause
    MissingEmergencyPause {
        description: String,
        location: usize,
    },
}

pub struct BridgeKeyCompromiseDetector {
    bytecode: Vec<u8>,
}

impl BridgeKeyCompromiseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BridgeKeyCompromiseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for single owner pattern (Ownable)
        // owner() function: 0x8da5cb5b
        let has_owner_function = self.find_function_selector(0x8da5cb5b);
        
        if let Some(owner_loc) = has_owner_function {
            // Check if this owner controls critical functions
            let has_withdraw = self.find_function_selector(0x3ccfd60b); // withdraw()
            let has_transfer_ownership = self.find_function_selector(0xf2fde38b); // transferOwnership
            
            if has_withdraw.is_some() || has_transfer_ownership.is_some() {
                // Check for bridge-specific patterns (lock/unlock functions)
                let has_lock = self.contains_function_with_name_pattern(&["lock", "deposit", "bridge"]);
                let has_unlock = self.contains_function_with_name_pattern(&["unlock", "release", "withdraw"]);
                
                if has_lock || has_unlock {
                    vulnerabilities.push(BridgeKeyCompromiseVulnerability::SinglePointOfFailure {
                        description: "Single owner controls bridge lock/unlock - Multichain-style risk".to_string(),
                        location: owner_loc,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        // Pattern 2: Check for multisig implementation
        // Common multisig function: execTransaction (Gnosis Safe)
        // Selector: 0x6a761202
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                if selector == 0x6a761202 { // execTransaction
                    // Try to find threshold value
                    if let Some((threshold, total)) = self.find_multisig_threshold(i) {
                        // Unsafe thresholds: 1-of-N, or less than 60% consensus
                        if threshold == 1 {
                            vulnerabilities.push(BridgeKeyCompromiseVulnerability::InsecureMultisigThreshold {
                                description: "Multisig with 1-of-N threshold - single key compromise risk".to_string(),
                                location: i,
                                threshold,
                                total_signers: total,
                            });
                        } else if (threshold as f32 / total as f32) < 0.6 {
                            vulnerabilities.push(BridgeKeyCompromiseVulnerability::InsecureMultisigThreshold {
                                description: format!(
                                    "Multisig threshold too low: {}/{} (<60% consensus)",
                                    threshold, total
                                ),
                                location: i,
                                threshold,
                                total_signers: total,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 3: Check for timelock protection
        // Timelock.sol patterns: MINIMUM_DELAY, MAXIMUM_DELAY
        let has_timelock = self.detect_timelock_pattern();
        
        if !has_timelock && has_owner_function.is_some() {
            // Critical functions without timelock
            let has_upgrade = self.find_function_selector(0x3659cfe6); // upgradeTo
            let has_set_implementation = self.find_function_selector(0x5c60da1b); // setImplementation
            
            if has_upgrade.is_some() || has_set_implementation.is_some() {
                vulnerabilities.push(BridgeKeyCompromiseVulnerability::NoTimelockProtection {
                    description: "Upgradeable contract without timelock - no delay for malicious changes".to_string(),
                    location: has_upgrade.or(has_set_implementation).unwrap(),
                });
            }
        }
        
        // Pattern 4: Check for upgradeable patterns with single admin
        // UUPSUpgradeable: _authorizeUpgrade function
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for upgrade authorization logic
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // upgradeTo: 0x3659cfe6, upgradeToAndCall: 0x4f1ef286
                if selector == 0x3659cfe6 || selector == 0x4f1ef286 {
                    // Check if there's multisig protection
                    let has_multisig_check = self.bytecode[i..std::cmp::min(i+60, self.bytecode.len())]
                        .windows(10)
                        .any(|w| {
                            // Look for signature verification patterns
                            w.iter().any(|&b| b == 0x01) && // ECRECOVER might be nearby
                            w.iter().any(|&b| b == 0x14)    // EQ check
                        });
                    
                    if !has_multisig_check {
                        vulnerabilities.push(BridgeKeyCompromiseVulnerability::DangerousUpgradeability {
                            description: "Upgrade function without multisig protection - single key can change logic".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for emergency pause mechanism
        // Pausable: pause(), unpause() functions
        let has_pause = self.find_function_selector(0x8456cb59); // pause()
        let has_unpause = self.find_function_selector(0x3f4ba83a); // unpause()
        
        if has_pause.is_none() && has_unpause.is_none() {
            // Bridge without pause mechanism
            let is_bridge = self.contains_function_with_name_pattern(&[
                "bridge", "lock", "unlock", "deposit", "withdraw", "relay"
            ]);
            
            if is_bridge {
                vulnerabilities.push(BridgeKeyCompromiseVulnerability::MissingEmergencyPause {
                    description: "Bridge contract without emergency pause - cannot stop ongoing attack".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 6: Check for validator/relayer centralization
        // Look for validator management functions
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for validator addition/removal
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // addValidator, removeValidator type functions
                // We'll detect by looking for array push/pop patterns
                let modifies_validator_set = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        // Array modification: SLOAD, ADD/SUB, SSTORE
                        w[0] == 0x54 && (w[1] == 0x01 || w[1] == 0x03) && 
                        w[2] == 0x55
                    });
                
                if modifies_validator_set {
                    // Check if protected by multisig
                    let has_multisig = self.bytecode[i.saturating_sub(30)..i]
                        .windows(5)
                        .any(|w| {
                            // Multiple signature checks
                            w.iter().filter(|&&b| b == 0x14).count() > 2 // Multiple EQ checks
                        });
                    
                    if !has_multisig {
                        vulnerabilities.push(BridgeKeyCompromiseVulnerability::SinglePointOfFailure {
                            description: "Validator set modification without multisig - single key can control consensus".to_string(),
                            location: i,
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
        
        // Pattern 7: Check for MPC (Multi-Party Computation) key management
        // Lack of proper key rotation
        let has_key_rotation = self.contains_function_with_name_pattern(&["rotate", "refresh", "update_key"]);
        
        if !has_key_rotation && has_owner_function.is_some() {
            // Bridge with static keys
            vulnerabilities.push(BridgeKeyCompromiseVulnerability::SinglePointOfFailure {
                description: "No key rotation mechanism - compromised keys cannot be safely replaced".to_string(),
                location: 0,
                confidence: 0.65,
            });
        }
        
        vulnerabilities
    }
    
    fn find_function_selector(&self, selector: u32) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let found = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                if found == selector {
                    return Some(i);
                }
            }
        }
        None
    }
    
    fn find_multisig_threshold(&self, start: usize) -> Option<(u32, u32)> {
        // Look for threshold and owner count in nearby storage
        for i in start..std::cmp::min(start + 100, self.bytecode.len()).saturating_sub(5) {
            // Look for PUSH values that might be threshold/count
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                let threshold = self.bytecode[i+1] as u32;
                // Look for another PUSH nearby (total count)
                for j in i+2..std::cmp::min(i+20, self.bytecode.len()).saturating_sub(2) {
                    if self.bytecode[j] == 0x60 && j + 1 < self.bytecode.len() {
                        let total = self.bytecode[j+1] as u32;
                        if total > threshold && total < 100 {
                            return Some((threshold, total));
                        }
                    }
                }
            }
        }
        None
    }
    
    fn detect_timelock_pattern(&self) -> bool {
        // Look for TIMESTAMP opcode used in delay checks
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Followed by ADD (delay addition) and comparison
                let has_delay = self.bytecode[i..std::cmp::min(i+15, self.bytecode.len())]
                    .windows(3)
                    .any(|w| w[0] == 0x01 && (w[1] == 0x10 || w[1] == 0x11)); // ADD then LT/GT
                if has_delay {
                    return true;
                }
            }
        }
        false
    }
    
    fn contains_function_with_name_pattern(&self, patterns: &[&str]) -> bool {
        // Simple heuristic: look for function selectors that might match
        // In reality, we'd need to decode function names from metadata
        // Here we check for common selector patterns
        let common_selectors = vec![
            0x3ccfd60b, // withdraw
            0x47e7ef24, // deposit  
            0xf340fa01, // lock
            0x2e1a7d4d, // unlock
        ];
        
        for selector in common_selectors {
            if self.find_function_selector(selector).is_some() {
                return true;
            }
        }
        false
    }
}
