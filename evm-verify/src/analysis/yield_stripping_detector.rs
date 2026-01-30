/// Yield Stripping Detector
use crate::bytecode::SecurityFinding;

pub struct YieldStrippingDetector {
    bytecode: Vec<u8>,
}

impl YieldStrippingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Yield stripping vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_yield_stripping(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_yield_stripping(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for yield token separation without fair split
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // split, separate, claimYield selectors
            if matches!(self.bytecode[pos+1], 0x42 | 0x7f | 0xa9 | 0xcc) {
                let mut has_yield_calculation = false;
                let mut has_proportional_split = false;
                let mut has_timestamp_validation = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for yield calculation (MUL + DIV)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 && j + 4 < self.bytecode.len() { // MUL
                            if self.bytecode[j + 2] == 0x04 { // DIV
                                has_yield_calculation = true;
                            }
                        }
                    }
                    
                    // Check for proportional split (multiple balance reads + divisions)
                    let mut balance_reads = 0;
                    let mut divisions = 0;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            balance_reads += 1;
                        }
                        if self.bytecode[j] == 0x04 { // DIV
                            divisions += 1;
                        }
                    }
                    if balance_reads >= 2 && divisions >= 2 {
                        has_proportional_split = true;
                    }
                    
                    // Check for timestamp-based accrual
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 2] == 0x03 { // SUB (time difference)
                                has_timestamp_validation = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if separates yield without proper proportional distribution
                return has_yield_calculation && (!has_proportional_split || !has_timestamp_validation);
            }
        }
        false
    }
}
