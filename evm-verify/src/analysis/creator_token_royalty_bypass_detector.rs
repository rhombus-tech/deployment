/// Creator Token Royalty Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct CreatorTokenRoyaltyBypassDetector {
    bytecode: Vec<u8>,
}

impl CreatorTokenRoyaltyBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Creator token royalty bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.check_royalty_bypass(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_royalty_bypass(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for transfer functions that bypass royalty enforcement
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // transfer, transferFrom, safeTransferFrom selectors
            if matches!(self.bytecode[pos+1], 0xa9 | 0x23 | 0x42) {
                let mut has_royalty_call = false;
                let mut has_royalty_validation = false;
                let mut enforces_eip2981 = false;
                let mut checks_operator_filter = false;
                
                if pos + 75 < self.bytecode.len() {
                    // Check for EIP-2981 royaltyInfo call
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa && j + 6 < self.bytecode.len() { // STATICCALL
                            // Check for royaltyInfo selector (0x2a55205a)
                            if j > 10 && self.bytecode[j-10] == 0x60 && self.bytecode[j-9] == 0x2a {
                                enforces_eip2981 = true;
                                has_royalty_call = true;
                            }
                        }
                    }
                    
                    // Check for operator filter registry check (OpenSea)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to filter registry
                            checks_operator_filter = true;
                        }
                    }
                    
                    // Check for royalty payment validation
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 && j + 3 < self.bytecode.len() { // CALL (payment)
                            if self.bytecode[j + 2] == 0x50 { // POP (checking return)
                                has_royalty_validation = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if transfer doesn't enforce royalties properly
                // Attacks: direct transfers, batch transfers, atomic swaps bypassing royalty
                return !has_royalty_call || !has_royalty_validation || (!enforces_eip2981 && !checks_operator_filter);
            }
        }
        false
    }
}
