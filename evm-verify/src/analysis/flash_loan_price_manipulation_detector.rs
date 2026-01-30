/// Flash Loan Price Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct FlashLoanPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl FlashLoanPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Flash loan price manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_flash_loan_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_flash_loan_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for price calculation based on spot reserves without TWAP
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getReserves, balanceOf used for pricing
            if matches!(self.bytecode[pos+1], 0x0c | 0x70 | 0x90) {
                let mut has_spot_price_calc = false;
                let mut has_twap_protection = false;
                let mut has_flash_loan_check = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for division after reserve reads (spot price calculation)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV
                            has_spot_price_calc = true;
                            break;
                        }
                    }
                    
                    // Check for TWAP (multiple timestamp checks and cumulative price)
                    let mut timestamp_count = 0;
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            timestamp_count += 1;
                        }
                        
                        // Check for reentrancy lock (flash loan protection)
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 3] == 0x15 && self.bytecode[j + 5] == 0x57 { // ISZERO + REVERT
                                has_flash_loan_check = true;
                            }
                        }
                    }
                    
                    if timestamp_count >= 2 {
                        has_twap_protection = true;
                    }
                }
                
                // Vulnerable if uses spot price without TWAP or flash loan protection
                return has_spot_price_calc && !has_twap_protection && !has_flash_loan_check;
            }
        }
        false
    }
}
