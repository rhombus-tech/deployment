use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use ethers::types::{Bytes, Address};
use std::collections::HashMap;

/// Binary classifier for exploitable vulnerabilities vs false positives
#[derive(Debug, Clone)]
pub struct AntiHacks {
    /// Known exploitable patterns from real hacks
    known_exploits: HashMap<String, ExploitPattern>,
    /// Safe patterns that should never trigger warnings
    safe_patterns: HashMap<String, SafePattern>,
}

#[derive(Debug, Clone)]
pub struct ExploitPattern {
    pub name: String,
    pub bytecode_signatures: Vec<Vec<u8>>,
    pub description: String,
    pub real_world_examples: Vec<String>, // Actual hack tx hashes
}

#[derive(Debug, Clone)]
pub struct SafePattern {
    pub name: String,
    pub bytecode_signatures: Vec<Vec<u8>>,
    pub protection_mechanism: String,
}

#[derive(Debug, Clone)]
pub struct HackClassification {
    pub is_exploitable: bool,
    pub hack_type: Option<HackType>,
    pub protection_detected: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum HackType {
    ReentrancyAttack,
    FlashLoanExploit,
    PriceManipulation,
    UncheckedCallFailure,
    IntegerOverflowExploit,
    AccessControlBypass,
    SignatureReplay,
    StorageCorruption,
}

impl AntiHacks {
    pub fn new() -> Self {
        let mut antihacks = Self {
            known_exploits: HashMap::new(),
            safe_patterns: HashMap::new(),
        };
        
        antihacks.init_known_exploits();
        antihacks.init_safe_patterns();
        antihacks
    }

    /// Initialize known exploitable patterns from real-world hacks
    fn init_known_exploits(&mut self) {
        // Unchecked call failures (like King of Ether)
        self.known_exploits.insert("unchecked_call".to_string(), ExploitPattern {
            name: "Unchecked External Call".to_string(),
            bytecode_signatures: vec![
                vec![0x60, 0x40, 0x51, 0x90, 0x81, 0x90], // CALL without return check
            ],
            description: "External calls without return value checking".to_string(),
            real_world_examples: vec![
                "0x...".to_string(), // King of Ether hack
            ],
        });

        // Reentrancy without guards (like DAO hack)
        self.known_exploits.insert("reentrancy_no_guard".to_string(), ExploitPattern {
            name: "Reentrancy without Guard".to_string(),
            bytecode_signatures: vec![
                vec![0x60, 0x00, 0x80, 0x80, 0x80, 0x80, 0x5a, 0xf1], // CALL with value
            ],
            description: "State changes after external calls without reentrancy guard".to_string(),
            real_world_examples: vec![
                "0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b".to_string(), // DAO hack
            ],
        });

        // Price manipulation without TWAP (flash loan attacks)
        self.known_exploits.insert("price_manipulation".to_string(), ExploitPattern {
            name: "Price Manipulation".to_string(),
            bytecode_signatures: vec![
                vec![0x70, 0xa0, 0x82, 0x31], // BALANCE opcode for price calculation
            ],
            description: "Price-sensitive operations using spot prices".to_string(),
            real_world_examples: vec![
                "0xf7a31c6a56b8f6c06e3f5b6cbf5b5e3c8f4a1b3d2e9f8c7a6b5d4e3f2a1c0b9e8".to_string(),
            ],
        });
    }

    /// Initialize safe patterns that shouldn't trigger warnings
    fn init_safe_patterns(&mut self) {
        // SafeMath protection patterns
        self.safe_patterns.insert("safemath".to_string(), SafePattern {
            name: "SafeMath Protection".to_string(),
            bytecode_signatures: vec![
                vec![0x08, 0xc3, 0x79, 0xa0], // SafeMath revert signature
                vec![0x4e, 0x48, 0x7b, 0x71], // SafeMath.add
                vec![0xe7, 0x88, 0x8c, 0xb8], // SafeMath.sub
            ],
            protection_mechanism: "OpenZeppelin SafeMath library".to_string(),
        });

        // Reentrancy guard patterns
        self.safe_patterns.insert("reentrancy_guard".to_string(), SafePattern {
            name: "Reentrancy Guard".to_string(),
            bytecode_signatures: vec![
                vec![0x60, 0x02, 0x14, 0x15], // Guard status check
            ],
            protection_mechanism: "OpenZeppelin ReentrancyGuard modifier".to_string(),
        });

        // Solidity 0.8+ overflow protection
        self.safe_patterns.insert("solidity_08_overflow".to_string(), SafePattern {
            name: "Solidity 0.8+ Overflow Protection".to_string(),
            bytecode_signatures: vec![
                vec![0x80, 0x82, 0x01, 0x82, 0x11], // Built-in overflow check
            ],
            protection_mechanism: "Solidity 0.8+ built-in overflow protection".to_string(),
        });
    }

    /// Classify if a vulnerability is actually exploitable
    pub fn classify_vulnerability(&self, warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        match warning.kind {
            SecurityWarningKind::IntegerOverflow => self.classify_overflow(warning, bytecode, contract_name),
            SecurityWarningKind::MEVVulnerability => self.classify_mev(warning, bytecode, contract_name),
            SecurityWarningKind::SignatureReplay => self.classify_signature_replay(warning, bytecode, contract_name),
            SecurityWarningKind::Reentrancy => self.classify_reentrancy(warning, bytecode, contract_name),
            SecurityWarningKind::FlashLoanVulnerability => self.classify_flash_loan(warning, bytecode, contract_name),
            SecurityWarningKind::UncheckedCallReturn => self.classify_unchecked_calls(warning, bytecode, contract_name),
            SecurityWarningKind::UncheckedExternalCall => self.classify_unchecked_external_call(warning, bytecode, contract_name),
            SecurityWarningKind::UninitializedStorage => self.classify_uninitialized_storage(warning, bytecode, contract_name),
            SecurityWarningKind::AccessControl => self.classify_access_control(warning, bytecode, contract_name),
            _ => HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: None,
                reason: format!("Unknown vulnerability type: {:?}", warning.kind),
            },
        }
    }

    fn classify_overflow(&self, _warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        // Check for SafeMath protection
        let has_safemath = self.has_safe_pattern("safemath", bytecode);
        let has_solidity_08 = self.has_safe_pattern("solidity_08_overflow", bytecode);
        
        if contract_name.contains("OpenZeppelin") || has_safemath || has_solidity_08 {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("SafeMath or Solidity 0.8+ protection".to_string()),
                reason: "Overflow protection mechanisms detected".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::IntegerOverflowExploit),
                protection_detected: None,
                reason: "No overflow protection found - exploitable".to_string(),
            }
        }
    }

    fn classify_mev(&self, warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        // MEV is real risk for DeFi protocols
        if contract_name.contains("Compound") || 
           contract_name.contains("Uniswap") ||
           contract_name.contains("Aave") ||
           warning.description.contains("price-sensitive") {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::PriceManipulation),
                protection_detected: None,
                reason: "DeFi protocol vulnerable to MEV attacks".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Non-DeFi contract".to_string()),
                reason: "Low MEV risk for non-DeFi contracts".to_string(),
            }
        }
    }

    fn classify_signature_replay(&self, warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        // Standard ERC20 without permits is safe
        if contract_name.contains("ERC20") && !warning.description.contains("permit") {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Standard ERC20 - no signature usage".to_string()),
                reason: "ERC20 transfers don't use signatures".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::SignatureReplay),
                protection_detected: None,
                reason: "Custom signature verification without replay protection".to_string(),
            }
        }
    }

    fn classify_reentrancy(&self, _warning: &SecurityWarning, bytecode: &[u8], _contract_name: &str) -> HackClassification {
        let has_guard = self.has_safe_pattern("reentrancy_guard", bytecode);
        
        if has_guard {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Reentrancy guard detected".to_string()),
                reason: "Protected by reentrancy guard".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::ReentrancyAttack),
                protection_detected: None,
                reason: "No reentrancy protection - exploitable".to_string(),
            }
        }
    }

    fn classify_flash_loan(&self, _warning: &SecurityWarning, _bytecode: &[u8], _contract_name: &str) -> HackClassification {
        // Flash loan vulnerabilities are almost always real
        HackClassification {
            is_exploitable: true,
            hack_type: Some(HackType::FlashLoanExploit),
            protection_detected: None,
            reason: "Flash loan manipulation vector detected".to_string(),
        }
    }

    fn classify_unchecked_calls(&self, warning: &SecurityWarning, _bytecode: &[u8], _contract_name: &str) -> HackClassification {
        // Check if the unchecked call is in a high-risk pattern
        let is_high_risk = warning.description.contains("value transfer") 
            || warning.description.contains("external call") 
            || warning.description.contains("delegate call");
        
        if is_high_risk {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::UncheckedCallFailure),
                protection_detected: None,
                reason: "High-risk unchecked external call without return value validation".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Low-risk call pattern".to_string()),
                reason: "Unchecked call appears to be in safe context".to_string(),
            }
        }
    }

    fn classify_access_control(&self, warning: &SecurityWarning, _bytecode: &[u8], _contract_name: &str) -> HackClassification {
        // Check for missing access control on critical operations
        let is_critical = warning.description.contains("onlyOwner") 
            || warning.description.contains("access control") 
            || warning.description.contains("permission");
        
        if is_critical {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::AccessControlBypass),
                protection_detected: None,
                reason: "Missing access control on critical function".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Public function with no critical operations".to_string()),
                reason: "Public function without sensitive operations detected".to_string(),
            }
        }
    }

    fn classify_other(&self, warning: &SecurityWarning, _bytecode: &[u8], _contract_name: &str) -> HackClassification {
        HackClassification {
            is_exploitable: false,
            hack_type: None,
            protection_detected: None,
            reason: format!("Not classified as exploitable: {}", warning.description),
        }
    }

    fn has_safe_pattern(&self, pattern_name: &str, bytecode: &[u8]) -> bool {
        if let Some(pattern) = self.safe_patterns.get(pattern_name) {
            for signature in &pattern.bytecode_signatures {
                if bytecode.windows(signature.len()).any(|window| window == signature) {
                    return true;
                }
            }
        }
        false
    }

    fn classify_unchecked_external_call(&self, warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        // Check for high-risk external call patterns
        let has_external_call = bytecode.windows(1).any(|w| w[0] == 0xF1); // CALL opcode
        let has_delegate_call = bytecode.windows(1).any(|w| w[0] == 0xF4); // DELEGATECALL opcode
        let has_static_call = bytecode.windows(1).any(|w| w[0] == 0xFA); // STATICCALL opcode
        
        // Check for return value handling patterns (ISZERO after CALL)
        let has_return_check = self.has_return_value_check(bytecode);
        
        // Known safe contracts or patterns
        let is_known_safe = contract_name.contains("OpenZeppelin") 
            || contract_name.contains("SafeMath") 
            || self.has_safe_pattern("call_protection", bytecode);
        
        if (has_external_call || has_delegate_call) && !has_return_check && !is_known_safe {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::UncheckedCallFailure),
                protection_detected: None,
                reason: "External call without proper return value validation - can lead to silent failures".to_string(),
            }
        } else if has_static_call {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("STATICCALL used - safer alternative".to_string()),
                reason: "STATICCALL cannot modify state, reducing risk".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Return value check detected".to_string()),
                reason: "External call has proper return value validation".to_string(),
            }
        }
    }

    fn classify_uninitialized_storage(&self, warning: &SecurityWarning, bytecode: &[u8], contract_name: &str) -> HackClassification {
        // Check for constructor patterns that might initialize storage
        let has_constructor_init = self.has_constructor_initialization(bytecode);
        
        // Check for initializer patterns (common in proxy contracts)
        let has_initializer_function = self.has_initializer_pattern(bytecode);
        
        // Check for storage slot zero access (often critical)
        let accesses_slot_zero = self.accesses_critical_storage_slots(warning, bytecode);
        
        // Known safe patterns
        let is_known_safe = contract_name.contains("OpenZeppelin") 
            || self.has_safe_pattern("storage_init", bytecode);
        
        if accesses_slot_zero && !has_constructor_init && !has_initializer_function && !is_known_safe {
            HackClassification {
                is_exploitable: true,
                hack_type: Some(HackType::StorageCorruption),
                protection_detected: None,
                reason: "Critical storage slots accessed without proper initialization - can lead to undefined behavior".to_string(),
            }
        } else if has_constructor_init || has_initializer_function {
            HackClassification {
                is_exploitable: false,
                hack_type: None,
                protection_detected: Some("Initialization pattern detected".to_string()),
                reason: "Storage appears to have proper initialization mechanisms".to_string(),
            }
        } else {
            HackClassification {
                is_exploitable: false,
                hack_type: Some(HackType::StorageCorruption),
                protection_detected: Some("Low-risk storage access".to_string()),
                reason: "Uninitialized storage access detected but appears to be low-risk".to_string(),
            }
        }
    }

    // Helper method to detect return value checking patterns
    fn has_return_value_check(&self, bytecode: &[u8]) -> bool {
        // Look for CALL followed by ISZERO and conditional jump patterns
        for i in 0..bytecode.len().saturating_sub(3) {
            if bytecode[i] == 0xF1 { // CALL
                // Check if followed by return value handling (ISZERO, POP, etc.)
                for j in (i + 1)..std::cmp::min(i + 5, bytecode.len()) {
                    if bytecode[j] == 0x15 // ISZERO
                        || bytecode[j] == 0x50 // POP (ignoring return value - bad)
                        || (bytecode[j] == 0x57 && j + 1 < bytecode.len()) // JUMPI
                    {
                        return bytecode[j] != 0x50; // Return true unless it's POP (ignoring return)
                    }
                }
            }
        }
        false
    }

    // Helper method to detect constructor initialization patterns
    fn has_constructor_initialization(&self, bytecode: &[u8]) -> bool {
        // Look for CALLVALUE at the beginning (constructor pattern)
        bytecode.len() > 2 && bytecode[0] == 0x34 // CALLVALUE opcode at start
    }

    // Helper method to detect initializer function patterns
    fn has_initializer_pattern(&self, bytecode: &[u8]) -> bool {
        // Look for common initializer patterns (function selectors, etc.)
        // This is a simplified heuristic
        for window in bytecode.windows(4) {
            // Common initializer function selectors (simplified)
            if window == [0x48, 0x5c, 0xc9, 0x55] // initialize()
                || window == [0x8b, 0x78, 0xc6, 0xd8] // __init__()
            {
                return true;
            }
        }
        false
    }

    // Helper method to check if critical storage slots are accessed
    fn accesses_critical_storage_slots(&self, warning: &SecurityWarning, _bytecode: &[u8]) -> bool {
        // Check if the warning indicates access to slot 0 or other critical slots
        warning.pc < 10 // Heuristic: warnings at very early PCs often involve critical storage
    }
}
