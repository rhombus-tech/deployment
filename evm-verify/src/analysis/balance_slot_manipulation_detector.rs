use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Balance Slot Direct Manipulation Detector
/// 
/// Detects vulnerabilities where token balance storage slots can be directly
/// written to create fake balances without proper transfer authorization.
/// 
/// **Attack Pattern**:
/// Attacker directly writes to balance storage slots (e.g., via delegatecall,
/// storage collision, or unprotected SSTORE) to inflate their token balance
/// without actually receiving tokens.
/// 
/// **Specific Vulnerability Patterns**:
/// 1. **Direct Balance Write**: SSTORE to balance slot without transfer validation
/// 2. **Storage Collision**: Proxy/implementation overlap allows balance writes
/// 3. **Delegatecall to Arbitrary**: DELEGATECALL allows writing to balance slots
/// 4. **Unprotected Mint**: Mint function without access control writes balances
/// 5. **Balance Overflow**: Arithmetic overflow in balance updates
/// 
/// **Detection Strategy**:
/// - Identifies direct SSTORE operations to balance-like storage slots
/// - Detects balance updates without corresponding transfer logic
/// - Flags SSTORE in public/external functions without access control
/// - Checks for delegatecall that could manipulate storage
/// - Validates balance arithmetic for overflow protection
pub struct BalanceSlotManipulationDetector {
    bytecode: Vec<u8>,
}

impl BalanceSlotManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_direct_balance_write_without_validation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Direct write to balance storage slot without proper authorization".to_string(),
                operations: Vec::new(),
                remediation: "Add strict access control before any balance storage writes".to_string(),
            });
        }

        if self.has_unprotected_balance_mint() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Mint/balance increase function lacks access control".to_string(),
                operations: Vec::new(),
                remediation: "Restrict mint functions to authorized roles only (owner, minter role)".to_string(),
            });
        }

        if self.has_delegatecall_storage_manipulation_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "DELEGATECALL to arbitrary address can manipulate balance storage".to_string(),
                operations: Vec::new(),
                remediation: "Restrict DELEGATECALL targets to trusted implementations only".to_string(),
            });
        }

        if self.has_balance_overflow_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::IntegerOverflow,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Balance arithmetic vulnerable to overflow/underflow".to_string(),
                operations: Vec::new(),
                remediation: "Use SafeMath or checked arithmetic for all balance operations".to_string(),
            });
        }

        if self.has_storage_collision_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Medium,
                pc: 0,
                description: "Storage layout may allow balance slot collision in upgradeable contracts".to_string(),
                operations: Vec::new(),
                remediation: "Use standardized storage patterns (e.g., EIP-1967) and validate storage layout".to_string(),
            });
        }

        warnings
    }

    fn has_direct_balance_write_without_validation(&self) -> bool {
        // Pattern: SSTORE to balance-like slot without proper checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let window = &self.bytecode[i.saturating_sub(35)..i];
                
                // Check if this looks like a balance update (KECCAK256 for mapping)
                let has_mapping_access = window.windows(10).any(|w| {
                    // Pattern: KECCAK256(user_address + slot) for balanceOf[user]
                    w.iter().any(|&op| op == 0x20) // KECCAK256
                });
                
                // Check for transfer validation (from/to checks)
                let has_transfer_validation = window.windows(12).any(|w| {
                    // Pattern: require(from == msg.sender || approved)
                    w.iter().any(|&op| op == 0x33) && // CALLER
                    w.iter().any(|&op| op == 0x14) && // EQ
                    w.iter().any(|&op| op == 0xfd) // REVERT if unauthorized
                });
                
                // Check for mint authorization
                let has_mint_auth = window.windows(10).any(|w| {
                    // Pattern: require(msg.sender == owner/minter)
                    w.iter().any(|&op| op == 0x33) && // CALLER
                    w.iter().any(|&op| op == 0x54) && // SLOAD (owner/minter role)
                    w.iter().any(|&op| op == 0x14) // EQ
                });
                
                // Check for balance decrease validation (burn/transfer from)
                let has_decrease_check = window.windows(8).any(|w| {
                    // Pattern: require(balance >= amount)
                    w.iter().any(|&op| op == 0x54) && // SLOAD (current balance)
                    w.iter().any(|&op| op == 0x11) && // GT (balance > amount)
                    w.iter().any(|&op| op == 0x57) // JUMPI (revert if insufficient)
                });
                
                if has_mapping_access && !has_transfer_validation && !has_mint_auth && !has_decrease_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_unprotected_balance_mint(&self) -> bool {
        // Pattern: mint() function without access control
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19]; // mint(address,uint256)
        let mint_to_selector = [0xa0, 0x71, 0x2d, 0x68]; // mintTo()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector || selector == mint_to_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for balance increase (SSTORE after ADD)
                    let has_balance_increase = window.windows(5).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ADD (increase balance)
                        w.iter().any(|&op| op == 0x55) // SSTORE (write balance)
                    });
                    
                    // Check for access control
                    let has_owner_check = window.windows(8).any(|w| {
                        // Pattern: require(msg.sender == owner)
                        w.iter().any(|&op| op == 0x33) && // CALLER
                        w.iter().any(|&op| op == 0x54) && // SLOAD (owner)
                        w.iter().any(|&op| op == 0x14) && // EQ
                        w.iter().any(|&op| op == 0xfd) // REVERT if not owner
                    });
                    
                    // Check for role-based access control
                    let has_role_check = window.windows(10).any(|w| {
                        // Pattern: require(hasRole(MINTER_ROLE, msg.sender))
                        w.iter().any(|&op| op == 0x20) && // KECCAK256 (role hash)
                        w.iter().any(|&op| op == 0x54) && // SLOAD (role mapping)
                        w.iter().any(|&op| op == 0x15) // ISZERO (check if has role)
                    });
                    
                    if has_balance_increase && !has_owner_check && !has_role_check {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_delegatecall_storage_manipulation_risk(&self) -> bool {
        // Pattern: DELEGATECALL to user-controlled address
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                let window = &self.bytecode[i.saturating_sub(25)..i];
                
                // Check if target comes from calldata or user input
                let has_dynamic_target = window.iter().any(|&op| {
                    op == 0x35 || op == 0x36 // CALLDATALOAD or CALLDATACOPY
                });
                
                // Check for implementation address from storage (upgradeable)
                let has_storage_target = window.iter().any(|&op| {
                    op == 0x54 // SLOAD (implementation address)
                });
                
                // Check for target validation
                let has_target_validation = window.windows(8).any(|w| {
                    // Pattern: require(target == trustedImplementation)
                    w.iter().any(|&op| op == 0x14) && // EQ (compare addresses)
                    w.iter().any(|&op| op == 0xfd) // REVERT if mismatch
                });
                
                // Check for implementation whitelist
                let has_whitelist = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256
                    w.iter().any(|&op| op == 0x54) && // SLOAD (whitelist)
                    w.iter().any(|&op| op == 0x15) // ISZERO (check whitelisted)
                });
                
                if (has_dynamic_target || has_storage_target) && !has_target_validation && !has_whitelist {
                    return true;
                }
            }
        }
        false
    }

    fn has_balance_overflow_risk(&self) -> bool {
        // Pattern: balance arithmetic without overflow checks
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x01 { // ADD (balance increase)
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check if result is stored (balance update)
                let has_balance_store = window.windows(5).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256 (balance slot)
                    w.iter().any(|&op| op == 0x55) // SSTORE
                });
                
                // Check for overflow protection
                let has_overflow_check = window.windows(6).any(|w| {
                    // Pattern: require(result >= operand) - overflow check
                    w.iter().any(|&op| op == 0x11) && // GT or GE
                    w.iter().any(|&op| op == 0xfd) // REVERT on overflow
                });
                
                // Check for SafeMath usage
                let has_safe_math = window.windows(5).any(|w| {
                    // Pattern: STATICCALL to SafeMath library
                    w.iter().any(|&op| op == 0xfa) // STATICCALL
                });
                
                if has_balance_store && !has_overflow_check && !has_safe_math {
                    return true;
                }
            }
            
            // Check for SUB (balance decrease) underflow
            if self.bytecode[i] == 0x03 { // SUB
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                let has_balance_store = window.windows(5).any(|w| {
                    w.iter().any(|&op| op == 0x20) && // KECCAK256
                    w.iter().any(|&op| op == 0x55) // SSTORE
                });
                
                // Check for underflow protection
                let has_underflow_check = window.windows(6).any(|w| {
                    // Pattern: require(balance >= amount)
                    w.iter().any(|&op| op == 0x11 || op == 0x10) && // GT/LT
                    w.iter().any(|&op| op == 0xfd) // REVERT on underflow
                });
                
                if has_balance_store && !has_underflow_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_storage_collision_risk(&self) -> bool {
        // Check for upgradeable proxy patterns with potential storage collision
        // Pattern: DELEGATECALL in fallback with storage usage
        
        let mut has_delegatecall = false;
        let mut has_early_storage_writes = false;
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                has_delegatecall = true;
            }
            
            // Check for SSTORE in early bytecode (potential collision)
            if i < 100 && self.bytecode[i] == 0x55 { // SSTORE in first 100 bytes
                has_early_storage_writes = true;
            }
        }
        
        // Check for lack of EIP-1967 storage pattern
        let has_eip1967_pattern = self.bytecode.windows(32).any(|w| {
            // EIP-1967 uses specific storage slots like 0x360894...
            // Look for these magic numbers in SLOAD/SSTORE operations
            w.iter().filter(|&&op| op >= 0x7f && op <= 0x7f).count() > 0 // PUSH32 (EIP-1967 slot)
        });
        
        if has_delegatecall && has_early_storage_writes && !has_eip1967_pattern {
            return true;
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_balance_manipulation() {
        let vulnerable_bytecode = vec![
            0x20, // KECCAK256 (compute balance slot)
            0x60, 0xff, 0xff, // PUSH large value
            0x55, // SSTORE (directly write balance without validation!)
        ];

        let detector = BalanceSlotManipulationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("balance")));
    }

    #[test]
    fn test_unprotected_mint() {
        let vulnerable_bytecode = vec![
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint() selector
            0x01, // ADD (increase balance)
            0x55, // SSTORE (write balance - no access control!)
        ];

        let detector = BalanceSlotManipulationDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| 
            w.description.contains("Mint") || 
            w.description.contains("access control")
        ));
    }
}
