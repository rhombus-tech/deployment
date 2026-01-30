/// Vault Fee Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct VaultFeeManipulationDetector {
    bytecode: Vec<u8>,
}

impl VaultFeeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Vault fee manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.check_fee_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_fee_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for fee calculation that can be manipulated via share inflation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // deposit, withdraw, performanceFee, managementFee selectors
            if matches!(self.bytecode[pos+1], 0xb6 | 0x2e | 0x3c | 0xf8 | 0x47) {
                let mut has_fee_calc = false;
                let mut has_timestamp_check = false;
                let mut has_share_inflation_protection = false;
                
                if pos + 50 < self.bytecode.len() {
                    // Check for fee calculation (MUL + DIV pattern)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 && j + 4 < self.bytecode.len() { // MUL
                            if self.bytecode[j + 2] == 0x04 { // DIV
                                has_fee_calc = true;
                            }
                        }
                    }
                    
                    // Check for timestamp-based fee accrual
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            has_timestamp_check = true;
                        }
                    }
                    
                    // Check for minimum shares protection (GT check before fee calc)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_share_inflation_protection = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if calculates fees without inflation protection
                return has_fee_calc && (!has_timestamp_check || !has_share_inflation_protection);
            }
        }
        false
    }
}
