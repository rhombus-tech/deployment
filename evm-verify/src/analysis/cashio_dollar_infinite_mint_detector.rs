use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Cashio Dollar Infinite Mint Detector
/// 
/// Detects cross-VM account validation bypass vulnerabilities that enable
/// infinite minting of stablecoins or wrapped tokens.
/// 
/// **Historical Exploit**: Cashio Dollar ($52M, March 2022)
/// 
/// **Attack Pattern**:
/// Cashio used Solana's "arrow" accounts for validation. Attacker:
/// 1. Created fake collateral account that passed arrow validation
/// 2. Arrow account pointed to attacker-controlled data
/// 3. Minted unlimited CASH tokens against fake collateral
/// 4. Drained $52M before detection
/// 
/// **Core Vulnerability**: Account validation bypass through:
/// - Missing account ownership checks
/// - Insufficient account data validation
/// - Cross-program invocation (CPI) validation gaps
/// - Fake account creation not detected
/// 
/// **Detection Strategy**:
/// - Identifies mint functions without proper account validation
/// - Detects missing ownership/authority checks on collateral accounts
/// - Flags insufficient account discriminator validation
/// - Checks for CPI guard bypasses
/// - Validates mint authority verification
pub struct CashioDollarInfiniteMintDetector {
    bytecode: Vec<u8>,
}

impl CashioDollarInfiniteMintDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_mint_without_collateral_validation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Token minting without proper collateral account validation - Cashio vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Validate collateral account ownership, discriminator, and data integrity before minting".to_string(),
            });
        }

        if self.has_missing_account_ownership_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Missing account ownership verification - enables fake account attacks".to_string(),
                operations: Vec::new(),
                remediation: "Verify account owner matches expected program before trusting account data".to_string(),
            });
        }

        if self.has_insufficient_account_discriminator_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Account discriminator not validated - allows wrong account type substitution".to_string(),
                operations: Vec::new(),
                remediation: "Validate account discriminator matches expected type before reading data".to_string(),
            });
        }

        if self.has_cpi_guard_bypass() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Cross-program invocation guards can be bypassed".to_string(),
                operations: Vec::new(),
                remediation: "Implement CPI guard checks to prevent unauthorized cross-program calls".to_string(),
            });
        }

        if self.has_mint_authority_validation_gap() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Mint authority verification insufficient or missing".to_string(),
                operations: Vec::new(),
                remediation: "Strictly validate mint authority ownership and signature before minting".to_string(),
            });
        }

        warnings
    }

    fn has_mint_without_collateral_validation(&self) -> bool {
        // Pattern: mint() function without comprehensive collateral checks
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19]; // mint(address,uint256)
        let mint_to = [0xa0, 0x71, 0x2d, 0x68]; // mintTo()
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector || selector == mint_to {
                    let window = &self.bytecode[i..i+60.min(self.bytecode.len())];
                    
                    // Check for mint operation
                    let has_mint_call = window.windows(5).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ADD (increase supply)
                        w.iter().any(|&op| op == 0x55) // SSTORE (store new balance)
                    });
                    
                    // Check for collateral account validation
                    let has_collateral_check = window.windows(15).any(|w| {
                        // Pattern: SLOAD collateral -> verify balance/ownership
                        w.iter().any(|&op| op == 0x54) && // SLOAD (collateral data)
                        w.iter().any(|&op| op == 0x14) && // EQ (ownership check)
                        w.iter().any(|&op| op == 0xfd) // REVERT if invalid
                    });
                    
                    // Check for collateral value verification
                    let has_value_check = window.windows(10).any(|w| {
                        // Pattern: collateral value >= mint amount
                        w.iter().any(|&op| op == 0x11 || op == 0x10) && // GT/LT
                        w.iter().any(|&op| op == 0xfd) // REVERT
                    });
                    
                    // Check for account discriminator validation
                    let has_discriminator = window.windows(8).any(|w| {
                        // First 8 bytes of account should match expected type
                        w.iter().filter(|&&op| op == 0x35).count() >= 2 && // CALLDATALOAD (read discriminator)
                        w.iter().any(|&op| op == 0x14) // EQ (compare discriminator)
                    });
                    
                    if has_mint_call && !has_collateral_check && !has_value_check && !has_discriminator {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_account_ownership_check(&self) -> bool {
        // Check if account data is read without verifying account owner
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for STATICCALL or CALL to read account data
            if self.bytecode[i] == 0xfa || self.bytecode[i] == 0xf1 {
                let window = &self.bytecode[i.saturating_sub(30)..i+10.min(self.bytecode.len())];
                
                // Check if account data is being read
                let reads_account_data = window.iter().any(|&op| {
                    op == 0x35 || op == 0x36 // CALLDATALOAD or CALLDATACOPY
                });
                
                // Check for owner verification before reading
                let verifies_owner = window.windows(10).any(|w| {
                    // Pattern: account.owner == expectedProgram
                    w.iter().any(|&op| op == 0x35) && // CALLDATALOAD (owner field)
                    w.iter().any(|&op| op == 0x14) && // EQ (compare to expected)
                    w.iter().any(|&op| op == 0xfd) // REVERT if mismatch
                });
                
                // Check for program ID validation
                let validates_program_id = window.windows(6).any(|w| {
                    w.iter().filter(|&&op| op == 0x14).count() >= 2 // Multiple equality checks
                });
                
                if reads_account_data && !verifies_owner && !validates_program_id {
                    return true;
                }
            }
        }
        false
    }

    fn has_insufficient_account_discriminator_check(&self) -> bool {
        // Pattern: Using account data without discriminator validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (reading account data)
                let window = &self.bytecode[i..i+35.min(self.bytecode.len())];
                
                // Check if data is used in calculations
                let uses_account_data = window.iter().any(|&op| {
                    op == 0x02 || op == 0x04 // MUL or DIV (using the data)
                });
                
                // Check for discriminator validation (first 8 bytes)
                let checks_discriminator = window.windows(12).any(|w| {
                    // Pattern: first 8 bytes == expected discriminator
                    w.iter().filter(|&&op| op == 0x60).count() >= 1 && // PUSH (expected discriminator)
                    w.iter().any(|&op| op == 0x14) && // EQ
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if wrong type
                });
                
                // Check for type tag validation
                let checks_type_tag = window.windows(6).any(|w| {
                    w.iter().filter(|&&op| op == 0x14).count() >= 2 // Multiple type checks
                });
                
                if uses_account_data && !checks_discriminator && !checks_type_tag {
                    return true;
                }
            }
        }
        false
    }

    fn has_cpi_guard_bypass(&self) -> bool {
        // Check for cross-program/cross-contract calls without guards
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 { // CALL or DELEGATECALL
                let window = &self.bytecode[i.saturating_sub(25)..i];
                
                // Check if target is dynamic (cross-program)
                let has_dynamic_target = window.iter().any(|&op| {
                    op == 0x35 || op == 0x54 // CALLDATALOAD or SLOAD (target address)
                });
                
                // Check for CPI guard (reentrancy or auth check)
                let has_cpi_guard = window.windows(8).any(|w| {
                    // Pattern: SLOAD(cpiGuard) -> ISZERO -> require
                    w.iter().any(|&op| op == 0x54) && // SLOAD
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if guard set
                });
                
                // Check for caller authorization
                let has_caller_auth = window.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x33) && // CALLER
                    w.iter().any(|&op| op == 0x14) // EQ (check authorized)
                });
                
                if has_dynamic_target && !has_cpi_guard && !has_caller_auth {
                    return true;
                }
            }
        }
        false
    }

    fn has_mint_authority_validation_gap(&self) -> bool {
        // Pattern: mint authority not strictly validated
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19];
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Check for mint operation
                    let has_mint = window.contains(&0x55); // SSTORE (update balance)
                    
                    // Check for authority signature verification
                    let verifies_signature = window.windows(10).any(|w| {
                        w.iter().any(|&op| op == 0x01) && // ecrecover
                        w.iter().any(|&op| op == 0x14) // EQ (verify recovered address)
                    });
                    
                    // Check for authority ownership verification
                    let verifies_ownership = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x54) && // SLOAD (mint authority)
                        w.iter().any(|&op| op == 0x33) && // CALLER
                        w.iter().any(|&op| op == 0x14) // EQ (check match)
                    });
                    
                    // Check for multi-sig requirement
                    let requires_multisig = window.windows(12).any(|w| {
                        w.iter().filter(|&&op| op == 0x01).count() >= 2 // Multiple ecrecover
                    });
                    
                    if has_mint && !verifies_signature && !verifies_ownership && !requires_multisig {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cashio_infinite_mint() {
        let vulnerable_bytecode = vec![
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint()
            0x35, // CALLDATALOAD (fake collateral account)
            0x01, // ADD (increase supply)
            0x55, // SSTORE (mint - no collateral validation!)
        ];

        let detector = CashioDollarInfiniteMintDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("collateral")));
    }

    #[test]
    fn test_missing_account_ownership() {
        let vulnerable_bytecode = vec![
            0xfa, // STATICCALL (read account data)
            0x35, // CALLDATALOAD (use data without owner check!)
            0x02, // MUL (calculate with unvalidated data)
        ];

        let detector = CashioDollarInfiniteMintDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| w.description.contains("ownership")));
    }
}
