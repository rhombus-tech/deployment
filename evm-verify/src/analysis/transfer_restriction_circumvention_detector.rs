/// Transfer Restriction Circumvention Detector
use crate::bytecode::SecurityFinding;

pub struct TransferRestrictionCircumventionDetector {
    bytecode: Vec<u8>,
}

impl TransferRestrictionCircumventionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Transfer restriction circumvention at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_restriction_circumvention(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_restriction_circumvention(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for transfer restrictions that can be circumvented
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // transfer, transferFrom, approve selectors
            if matches!(self.bytecode[pos+1], 0xa9 | 0x23 | 0x09) {
                let mut enforces_transfer_restrictions = false;
                let mut validates_all_transfer_paths = false;
                let mut prevents_multicall_bypass = false;
                let mut checks_flash_loan_context = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for transfer restriction enforcement
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to restriction module
                            enforces_transfer_restrictions = true;
                        }
                    }
                    
                    // Check if all transfer paths validated (not just direct transfers)
                    let mut validation_points = 0;
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD (checking restrictions)
                            validation_points += 1;
                        }
                    }
                    if validation_points >= 2 {
                        validates_all_transfer_paths = true;
                    }
                    
                    // Check for multicall/batch operation prevention
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            // Should track transfer count per transaction
                            if self.bytecode[j + 5] == 0x01 { // ADD (incrementing)
                                prevents_multicall_bypass = true;
                            }
                        }
                    }
                    
                    // Check for flash loan context detection
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x31 && j + 6 < self.bytecode.len() { // BALANCE
                            // Should detect temporary balance changes
                            checks_flash_loan_context = true;
                        }
                    }
                }
                
                // Vulnerable if restrictions can be circumvented via:
                // 1. Restrictions not enforced
                // 2. Alternative transfer paths not validated
                // 3. Multicall/batch bypass possible
                // 4. Flash loan bypass possible
                return !enforces_transfer_restrictions || !validates_all_transfer_paths || !prevents_multicall_bypass || !checks_flash_loan_context;
            }
        }
        false
    }
}
