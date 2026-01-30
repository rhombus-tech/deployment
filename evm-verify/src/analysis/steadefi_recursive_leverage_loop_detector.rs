use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Steadefi Recursive Leverage Loop Detector
/// 
/// Detects vulnerabilities in leveraged yield farming where recursive
/// borrowing loops can create excessive leverage and liquidation risks.
/// 
/// **Attack Patterns**:
/// 1. Deposit collateral -> Borrow -> Re-deposit as collateral (loop)
/// 2. Excessive leverage multiplication through recursion
/// 3. Liquidation cascade when position unwound
/// 4. Oracle manipulation affecting leveraged positions
/// 
/// **Detection Strategy**:
/// - Identifies recursive borrow/deposit patterns
/// - Detects missing leverage limits
/// - Flags unsafe liquidation thresholds
/// - Checks for cascading liquidation risks
pub struct SteadefiRecursiveLeverageLoopDetector {
    bytecode: Vec<u8>,
}

impl SteadefiRecursiveLeverageLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_recursive_borrow_deposit_loop() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Recursive leverage loop without maximum iteration limit - Steadefi pattern".to_string(),
                operations: Vec::new(),
                remediation: "Add maximum iteration limit for recursive borrow-deposit loops".to_string(),
            });
        }

        if self.has_excessive_leverage_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Leverage multiplication lacks safety bounds".to_string(),
                operations: Vec::new(),
                remediation: "Implement maximum leverage ratio limits".to_string(),
            });
        }

        if self.has_cascading_liquidation_vulnerability() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Position unwinding can trigger liquidation cascade".to_string(),
                operations: Vec::new(),
                remediation: "Add circuit breakers and gradual unwinding mechanisms".to_string(),
            });
        }

        warnings
    }

    fn has_recursive_borrow_deposit_loop(&self) -> bool {
        // Pattern: borrow() -> deposit() -> JUMP (loop back)
        let borrow_selector = [0xc5, 0xea, 0xbe, 0xec]; // borrow()
        let deposit_selector = [0xb6, 0xb5, 0x5f, 0x25]; // deposit()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == borrow_selector {
                    let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                    
                    // Look for deposit after borrow
                    let has_deposit = window.windows(5).any(|w| {
                        w[0] == 0x63 && w[1..5] == deposit_selector
                    });
                    
                    // Look for loop (JUMP/JUMPI back)
                    let has_loop = window.iter().any(|&op| {
                        op == 0x56 || op == 0x57 // JUMP or JUMPI
                    });
                    
                    // Check for iteration counter/limit
                    let has_counter = window.windows(3).any(|w| {
                        w[0] == 0x54 && // SLOAD (counter)
                        w[1] == 0x01 && // ADD (increment)
                        w[2] == 0x55    // SSTORE (update)
                    });
                    
                    if has_deposit && has_loop && !has_counter {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_excessive_leverage_risk(&self) -> bool {
        // Pattern: leverage calculation without max bound
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 { // MUL (leverage multiplier)
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Check if result used in borrow calculation
                let has_borrow_calc = window.iter().any(|&op| {
                    op == 0x04 // DIV (collateral ratio)
                });
                
                // Check for maximum leverage check
                let has_max_check = window.iter().any(|&op| {
                    op == 0x11 || op == 0xfd // GT or REVERT
                });
                
                if has_borrow_calc && !has_max_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_cascading_liquidation_vulnerability(&self) -> bool {
        // Pattern: liquidation without health factor validation
        let liquidate_selector = [0x96, 0xcd, 0x43, 0x59]; // liquidate()
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == liquidate_selector {
                    let window = &self.bytecode[i..i+30.min(self.bytecode.len())];
                    
                    // Check for health factor calculation
                    let has_health_check = window.iter().any(|&op| {
                        op == 0x04 // DIV (health factor = collateral/debt)
                    });
                    
                    // Check for cascade prevention (liquidation size limit)
                    let has_size_limit = window.iter().any(|&op| {
                        op == 0x10 || op == 0x11 // LT or GT
                    });
                    
                    if has_health_check && !has_size_limit {
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
    fn test_steadefi_recursive_leverage() {
        let vulnerable_bytecode = vec![
            0x63, 0xc5, 0xea, 0xbe, 0xec, // borrow()
            0x63, 0xb6, 0xb5, 0x5f, 0x25, // deposit()
            0x57, // JUMPI (loop back, no counter!)
            0x02, // MUL (leverage)
        ];

        let detector = SteadefiRecursiveLeverageLoopDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty());
    }
}
