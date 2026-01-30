use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// BXH/Iron Bank Specific Pattern Detector
/// 
/// Detects vulnerabilities specific to BXH (BXH Exchange) and Iron Bank exploits
/// involving flash loan + lending protocol manipulation.
/// 
/// **Historical Exploits**: 
/// - BXH ($139M, 2021) - Admin key compromise + price oracle manipulation
/// - Iron Bank ($30M+, multiple incidents) - Cream Finance fork vulnerabilities
/// 
/// **Attack Patterns**:
/// 1. Price oracle manipulation through illiquid markets
/// 2. Collateral factor exploitation in isolated lending pools
/// 3. Cross-asset borrowing with manipulated collateral prices
/// 4. Flash loan attacks on undercollateralized positions
/// 
/// **Detection Strategy**:
/// - Identifies isolated lending pool patterns
/// - Detects oracle price usage without manipulation resistance
/// - Flags collateral factor calculations without safety checks
/// - Checks for flash loan + borrow patterns
pub struct BxhIronBankSpecificDetector {
    bytecode: Vec<u8>,
}

impl BxhIronBankSpecificDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_isolated_pool_oracle_manipulation() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Isolated lending pool uses manipulable price oracle - BXH/Iron Bank pattern".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracle or add liquidity validation checks".to_string(),
            });
        }

        if self.has_unsafe_collateral_factor() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Collateral factor calculation without safety bounds checking".to_string(),
                operations: Vec::new(),
                remediation: "Add bounds validation for collateral factor calculations".to_string(),
            });
        }

        if self.has_flash_loan_borrow_pattern() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::FlashLoanAttackVector,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Flash loan + borrow pattern detected - Iron Bank vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Implement flash loan protection and same-block borrow restrictions".to_string(),
            });
        }

        warnings
    }

    fn has_isolated_pool_oracle_manipulation(&self) -> bool {
        // Pattern: getPrice() call without TWAP or liquidity check
        let get_price_selector = [0x41, 0x97, 0x6e, 0x09]; // getPrice()
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == get_price_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for liquidity validation
                    let has_liquidity_check = window.iter().any(|&op| {
                        op == 0x11 || op == 0x10 // GT or LT (liquidity threshold)
                    });
                    
                    // Check for TWAP
                    let has_twap = window.iter().any(|&op| {
                        op == 0x42 || op == 0x54 // TIMESTAMP or SLOAD (observations)
                    });
                    
                    if !has_liquidity_check && !has_twap {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_unsafe_collateral_factor(&self) -> bool {
        // Pattern: collateralFactor calculation without bounds
        // Typically: borrowed * collateralFactor / price
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 { // MUL (collateral calculation)
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Look for DIV (price division)
                if window.contains(&0x04) {
                    // Check for bounds validation (GT/LT)
                    let has_bounds = window.iter().any(|&op| {
                        op == 0x10 || op == 0x11 || op == 0xfd // LT, GT, or REVERT
                    });
                    
                    if !has_bounds {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_flash_loan_borrow_pattern(&self) -> bool {
        // Pattern: flash loan callback -> borrow() call
        let flash_loan_callback = [0x23, 0xe3, 0x0c, 0x8b]; // onFlashLoan
        let borrow_selector = [0xc5, 0xea, 0xbe, 0xec]; // borrow()
        
        let mut has_flash_callback = false;
        let mut has_borrow = false;
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == flash_loan_callback {
                    has_flash_callback = true;
                    
                    // Check next 50 bytes for borrow call
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    for j in 0..window.len().saturating_sub(5) {
                        if window[j] == 0x63 && window[j+1..j+5] == borrow_selector {
                            has_borrow = true;
                            break;
                        }
                    }
                }
            }
        }
        
        has_flash_callback && has_borrow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bxh_iron_bank_vulnerability() {
        let vulnerable_bytecode = vec![
            0x63, 0x41, 0x97, 0x6e, 0x09, // getPrice()
            0xfa, // STATICCALL (no TWAP check)
            0x02, // MUL (collateral calc)
            0x04, // DIV (no bounds!)
            0x55, // SSTORE
        ];

        let detector = BxhIronBankSpecificDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
