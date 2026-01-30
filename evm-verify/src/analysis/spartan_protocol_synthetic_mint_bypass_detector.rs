use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Spartan Protocol Synthetic Mint Bypass Detector
/// 
/// Detects vulnerabilities in synthetic asset protocols where minting
/// restrictions can be bypassed through flash loan manipulation.
/// 
/// **Historical Exploit**: Spartan Protocol ($30M, May 2021)
/// **Attack Pattern**:
/// 1. Flash loan to inflate pool liquidity
/// 2. Manipulate synth pricing calculation
/// 3. Mint excessive synthetic assets at manipulated rate
/// 4. Drain underlying collateral
/// 
/// **Detection Strategy**:
/// - Identifies synthetic minting without proper collateralization checks
/// - Detects flash loan + mint patterns
/// - Flags price oracle manipulation in minting logic
/// - Checks for missing time delays or caps
pub struct SpartanProtocolSyntheticMintBypassDetector {
    bytecode: Vec<u8>,
}

impl SpartanProtocolSyntheticMintBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_unchecked_synthetic_minting() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Synthetic asset minting without collateralization checks - Spartan vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add collateralization ratio checks before minting synthetic assets".to_string(),
            });
        }

        if self.has_flash_loan_mint_pattern() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::FlashLoanAttackVector,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Flash loan can manipulate synthetic asset minting".to_string(),
                operations: Vec::new(),
                remediation: "Implement flash loan protection and same-block mint restrictions".to_string(),
            });
        }

        if self.has_manipulable_synth_pricing() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Synthetic pricing uses manipulable oracle data".to_string(),
                operations: Vec::new(),
                remediation: "Use TWAP oracle for synthetic asset pricing".to_string(),
            });
        }

        warnings
    }

    fn has_unchecked_synthetic_minting(&self) -> bool {
        // mint() selector: 0x40c10f19
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == mint_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for collateral validation (GT/LT comparison)
                    let has_collateral_check = window.iter().any(|&op| {
                        op == 0x10 || op == 0x11 // LT or GT
                    });
                    
                    // Check for SSTORE (minting)
                    let has_mint = window.contains(&0x55);
                    
                    if has_mint && !has_collateral_check {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_flash_loan_mint_pattern(&self) -> bool {
        // Pattern: flash loan callback -> pool manipulation -> mint
        let flash_callback = [0x23, 0xe3, 0x0c, 0x8b];
        let mint_selector = [0x40, 0xc1, 0x0f, 0x19];
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == flash_callback {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Look for mint call in callback
                    let has_mint = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == mint_selector
                    });
                    
                    if has_mint {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_manipulable_synth_pricing(&self) -> bool {
        // Pattern: balanceOf -> DIV (price calc) -> mint
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x31 { // BALANCE
                let window = &self.bytecode[i..i+25.min(self.bytecode.len())];
                
                // Check for price calculation
                let has_price_calc = window.iter().any(|&op| op == 0x04); // DIV
                
                // Check for mint
                let has_mint = window.contains(&0x55); // SSTORE
                
                // Check for TWAP/time delay
                let has_twap = window.iter().any(|&op| op == 0x42); // TIMESTAMP
                
                if has_price_calc && has_mint && !has_twap {
                    return true;
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
    fn test_spartan_synthetic_bypass() {
        let vulnerable_bytecode = vec![
            0x63, 0x23, 0xe3, 0x0c, 0x8b, // flash loan callback
            0x31, // BALANCE
            0x04, // DIV (price calc)
            0x63, 0x40, 0xc1, 0x0f, 0x19, // mint()
            0x55, // SSTORE
        ];

        let detector = SpartanProtocolSyntheticMintBypassDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
