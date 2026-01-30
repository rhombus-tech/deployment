/// Insurance Fund Drain Detector
use crate::bytecode::SecurityFinding;

pub struct InsuranceFundDrainDetector {
    bytecode: Vec<u8>,
}

impl InsuranceFundDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Insurance fund drain vulnerability at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_insurance_drain(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_insurance_drain(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for insurance fund withdrawal without proper authorization and limits
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // withdrawInsurance, claimInsurance, liquidateWithInsurance selectors
            if matches!(self.bytecode[pos+1], 0x2c | 0x51 | 0x8e | 0xbd) {
                let mut has_governance_check = false;
                let mut has_withdrawal_limit = false;
                let mut has_deficit_validation = false;
                let mut has_timelock = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for governance/admin authorization
                    for j in (pos + 5)..(pos + 25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 8 < self.bytecode.len() { // CALLER
                            if self.bytecode[j + 3] == 0x54 && self.bytecode[j + 5] == 0x14 { // SLOAD + EQ
                                has_governance_check = true;
                            }
                        }
                    }
                    
                    // Check for withdrawal limit (percentage or absolute cap)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_withdrawal_limit = true;
                            }
                        }
                    }
                    
                    // Check for actual deficit validation (comparing losses to insurance)
                    let mut balance_reads = 0;
                    let mut comparisons = 0;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            balance_reads += 1;
                        }
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                            comparisons += 1;
                        }
                    }
                    if balance_reads >= 2 && comparisons >= 1 {
                        has_deficit_validation = true;
                    }
                    
                    // Check for timelock (TIMESTAMP comparison)
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) &&
                               matches!(self.bytecode[j + 5], 0x57 | 0xfd) {
                                has_timelock = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if missing critical protections
                return !has_governance_check || !has_withdrawal_limit || !has_deficit_validation || !has_timelock;
            }
        }
        false
    }
}
