/// EIP-6780 SELFDESTRUCT Behavior Change Detector  
use crate::bytecode::SecurityFinding;

pub struct Eip6780SelfdestructChangeDetector {
    bytecode: Vec<u8>,
}

impl Eip6780SelfdestructChangeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("EIP-6780 SELFDESTRUCT behavior change issue at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_selfdestruct_issue(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_selfdestruct_issue(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for SELFDESTRUCT (0xff) with old assumptions
        if self.bytecode[pos] == 0xff {
            let mut checks_same_transaction = false;
            let mut has_balance_transfer = false;
            let mut expects_code_removal = false;
            
            // Look for patterns indicating old SELFDESTRUCT assumptions
            let start = pos.saturating_sub(35);
            if pos > 0 && start < self.bytecode.len() {
                for j in start..pos {
                    // Check if code checks BALANCE before SELFDESTRUCT
                    if self.bytecode[j] == 0x47 { // SELFBALANCE
                        has_balance_transfer = true;
                    }
                    
                    // Check if code tries to verify contract still exists
                    if self.bytecode[j] == 0x3b { // EXTCODESIZE
                        expects_code_removal = true;
                    }
                    
                    // Check if code validates same-transaction creation
                    if self.bytecode[j] == 0x43 { // NUMBER
                        checks_same_transaction = true;
                    }
                }
            }
            
            // Look ahead for problematic patterns
            if pos + 35 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 35).min(self.bytecode.len()) {
                    // Check if code after SELFDESTRUCT expects contract to be gone
                    if self.bytecode[j] == 0x3b { // EXTCODESIZE check after
                        expects_code_removal = true;
                    }
                }
            }
            
            // Vulnerable if:
            // 1. Uses SELFDESTRUCT without checking same-transaction creation
            // 2. Expects code to be removed (EIP-6780: only removes in same tx as creation)
            // 3. Relies on balance transfer without proper validation
            return expects_code_removal || (has_balance_transfer && !checks_same_transaction);
        }
        false
    }
}
