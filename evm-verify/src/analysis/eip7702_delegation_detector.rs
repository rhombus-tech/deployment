use serde::{Serialize, Deserialize};

/// EIP-7702 Set Code Transaction Detection
/// 
/// EIP-7702 allows EOAs to temporarily delegate their code to a contract.
/// This creates new security risks:
/// 
/// 1. Malicious delegation can steal funds from EOA
/// 2. Delegation can be front-run
/// 3. No clear revocation mechanism
/// 4. Delegate contract can have vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip7702DelegationVulnerability {
    /// Critical: Delegation target not validated
    UnvalidatedDelegationTarget {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Delegate can transfer EOA assets
    DelegateAssetRisk {
        description: String,
        location: usize,
    },
    /// High: No delegation revocation
    MissingRevocation {
        description: String,
        location: usize,
    },
    /// High: Delegate contract is upgradeable
    UpgradeableDelegateRisk {
        description: String,
        location: usize,
    },
    /// Medium: No delegation expiry
    NoExpiryMechanism {
        description: String,
        location: usize,
    },
}

pub struct Eip7702DelegationDetector {
    bytecode: Vec<u8>,
}

impl Eip7702DelegationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip7702DelegationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check if this contract is designed to be a delegate
        // EIP-7702 delegates receive calls as if they're the EOA
        let is_delegate_target = self.is_delegation_target();
        
        if is_delegate_target {
            // Check if delegate has asset transfer capabilities
            let can_transfer_assets = self.can_transfer_assets();
            
            if can_transfer_assets {
                // Verify there are proper authorization checks
                let has_auth_checks = self.has_proper_authorization();
                
                if !has_auth_checks {
                    vulnerabilities.push(Eip7702DelegationVulnerability::DelegateAssetRisk {
                        description: "Delegate contract can transfer assets without proper authorization".to_string(),
                        location: 0,
                    });
                }
            }
            
            // Check if delegate is upgradeable
            let is_upgradeable = self.is_upgradeable_contract();
            
            if is_upgradeable {
                vulnerabilities.push(Eip7702DelegationVulnerability::UpgradeableDelegateRisk {
                    description: "Delegate contract is upgradeable - EOA code can change unexpectedly".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 2: Check for delegation management functions
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this is a delegation setup function
                if self.is_delegation_setup_function(i) {
                    // Verify target validation
                    let validates_target = self.validates_delegation_target(i);
                    
                    if !validates_target {
                        vulnerabilities.push(Eip7702DelegationVulnerability::UnvalidatedDelegationTarget {
                            description: format!(
                                "Delegation setup (0x{:08x}) without target validation",
                                selector
                            ),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                    
                    // Check for revocation mechanism
                    let has_revocation = self.has_revocation_function();
                    
                    if !has_revocation {
                        vulnerabilities.push(Eip7702DelegationVulnerability::MissingRevocation {
                            description: "Delegation setup without revocation mechanism".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Check for time-based delegation expiry
        let has_expiry = self.has_expiry_mechanism();
        
        if !has_expiry && is_delegate_target {
            vulnerabilities.push(Eip7702DelegationVulnerability::NoExpiryMechanism {
                description: "Delegation without time-based expiry - indefinite code control".to_string(),
                location: 0,
            });
        }
        
        // Pattern 4: Check for ORIGIN-based checks (problematic with delegation)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x32 { // ORIGIN
                // Using ORIGIN in delegate is problematic
                // It will point to the EOA, not the real originator
                let used_in_auth = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        w[0] == 0x14 && w[1] == 0x57 // EQ, JUMPI (authorization check)
                    });
                
                if used_in_auth && is_delegate_target {
                    vulnerabilities.push(Eip7702DelegationVulnerability::DelegateAssetRisk {
                        description: "Delegate uses tx.origin for auth - can be confused with delegating EOA".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 5: Check for SELFDESTRUCT in delegate
        // SELFDESTRUCT in delegate would affect the EOA
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xff { // SELFDESTRUCT
                if is_delegate_target {
                    vulnerabilities.push(Eip7702DelegationVulnerability::DelegateAssetRisk {
                        description: "SELFDESTRUCT in delegate contract - would destroy delegating EOA".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 6: Check for delegate signature verification
        // Delegates should verify that actions are authorized by the EOA owner
        if is_delegate_target {
            let has_signature_checks = self.has_signature_verification();
            
            if !has_signature_checks {
                let has_state_changing_ops = self.has_state_changing_operations();
                
                if has_state_changing_ops {
                    vulnerabilities.push(Eip7702DelegationVulnerability::UnvalidatedDelegationTarget {
                        description: "Delegate performs state changes without signature verification".to_string(),
                        location: 0,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        // Pattern 7: Check for delegate access to delegator's storage
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 || self.bytecode[i] == 0x55 { // SLOAD or SSTORE
                // In EIP-7702, delegate operates on EOA's storage
                // Check if storage access is properly controlled
                let has_access_control = self.bytecode[i.saturating_sub(20)..i]
                    .windows(5)
                    .any(|w| {
                        // Look for CALLER check before storage access
                        w[0] == 0x33 && w[2] == 0x14 // CALLER, EQ
                    });
                
                if !has_access_control && is_delegate_target {
                    // Only report if this is in a public function
                    let in_public_function = self.is_in_public_function(i);
                    
                    if in_public_function {
                        vulnerabilities.push(Eip7702DelegationVulnerability::DelegateAssetRisk {
                            description: "Delegate accesses delegator storage without authorization".to_string(),
                            location: i,
                        });
                        break; // Report once
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_delegation_target(&self) -> bool {
        // Heuristic: contracts designed as delegates typically have:
        // 1. Functions that use msg.sender (the delegating EOA)
        // 2. No constructor (since they're meant to be delegated to)
        // 3. Storage layout considerations
        
        let uses_caller = self.bytecode.iter().any(|&b| b == 0x33); // CALLER
        
        // Check for lack of constructor initialization
        let has_constructor_init = self.bytecode[..std::cmp::min(100, self.bytecode.len())]
            .windows(3)
            .any(|w| {
                w[0] == 0x60 && w[1] == 0x80 && w[2] == 0x60 // Common constructor pattern
            });
        
        uses_caller && !has_constructor_init
    }
    
    fn can_transfer_assets(&self) -> bool {
        // Check for CALL with value or token transfer patterns
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if value is non-zero (ETH transfer)
                let has_value = self.bytecode[i.saturating_sub(15)..i]
                    .windows(2)
                    .any(|w| {
                        // PUSH with non-zero value
                        (w[0] >= 0x60 && w[0] <= 0x7f) && w[1] != 0x00
                    });
                
                if has_value {
                    return true;
                }
            }
        }
        
        // Check for ERC20 transfer
        let has_erc20_transfer = self.bytecode
            .windows(4)
            .any(|w| {
                // transfer selector: 0xa9059cbb
                w[0] == 0xa9 && w[1] == 0x05 && w[2] == 0x9c && w[3] == 0xbb
            });
        
        has_erc20_transfer
    }
    
    fn has_proper_authorization(&self) -> bool {
        // Look for authorization patterns: msg.sender checks, signature verification
        let has_caller_check = self.bytecode
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w[2] == 0x14 && // EQ
                w[3] == 0x15 && // ISZERO
                w[4] == 0x57    // JUMPI
            });
        
        let has_sig_verify = self.has_signature_verification();
        
        has_caller_check || has_sig_verify
    }
    
    fn is_upgradeable_contract(&self) -> bool {
        // Check for proxy/upgrade patterns
        let has_delegate_call = self.bytecode.iter().any(|&b| b == 0xf4);
        
        // Check for upgrade function selectors
        let upgrade_selectors = [0x3659cfe6, 0x4f1ef286]; // upgradeTo, upgradeToAndCall
        
        for selector in upgrade_selectors {
            if self.find_selector(selector).is_some() {
                return true;
            }
        }
        
        has_delegate_call
    }
    
    fn is_delegation_setup_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Setup function typically stores delegate address
        let stores_address = section.iter().any(|&b| b == 0x55); // SSTORE
        let takes_address_param = section.iter().any(|&b| b == 0x35); // CALLDATALOAD
        
        stores_address && takes_address_param
    }
    
    fn validates_delegation_target(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        
        // Look for code validation (EXTCODESIZE, EXTCODEHASH)
        self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x3b || b == 0x3f)
    }
    
    fn has_revocation_function(&self) -> bool {
        // Look for function that clears delegation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                // Check if function clears storage
                let clears_storage = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        w[0] == 0x60 && w[1] == 0x00 && w[2] == 0x55 // PUSH1 0, SSTORE
                    });
                
                if clears_storage {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn has_expiry_mechanism(&self) -> bool {
        // Look for TIMESTAMP comparisons
        self.bytecode
            .windows(4)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                (w[1] == 0x10 || w[1] == 0x11) // LT or GT
            })
    }
    
    fn has_signature_verification(&self) -> bool {
        // Look for ecrecover patterns
        self.bytecode.iter().any(|&b| b == 0x01) // Might be ecrecover precompile
    }
    
    fn has_state_changing_operations(&self) -> bool {
        self.bytecode.iter().any(|&b| {
            b == 0x55 || // SSTORE
            b == 0xf1 || // CALL
            b == 0xf4    // DELEGATECALL
        })
    }
    
    fn is_in_public_function(&self, location: usize) -> bool {
        // Check if location is after a function selector check
        let start = location.saturating_sub(50);
        
        self.bytecode[start..location]
            .windows(5)
            .any(|w| {
                w[0] == 0x63 && // PUSH4 (selector)
                w[4] == 0x14    // EQ (comparison)
            })
    }
    
    fn find_selector(&self, selector: u32) -> Option<usize> {
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
}
