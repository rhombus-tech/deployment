/// NFT Approval Hijack Detector
use crate::bytecode::SecurityFinding;

pub struct NftApprovalHijackDetector {
    bytecode: Vec<u8>,
}

impl NftApprovalHijackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("NFT approval hijacking vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_approval_hijack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_approval_hijack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for approve() (0x095ea7b3) or setApprovalForAll() (0xa22cb465)
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 { // PUSH4
            let is_approve = self.bytecode[pos+1] == 0x09 && self.bytecode[pos+2] == 0x5e && 
                           self.bytecode[pos+3] == 0xa7 && self.bytecode[pos+4] == 0xb3;
            let is_approval_for_all = self.bytecode[pos+1] == 0xa2 && self.bytecode[pos+2] == 0x2c && 
                                     self.bytecode[pos+3] == 0xb4 && self.bytecode[pos+4] == 0x65;
            
            if is_approve || is_approval_for_all {
                // Check if there's ownership verification before approval
                if pos > 25 {
                    let mut has_owner_check = false;
                    for j in pos.saturating_sub(25)..pos {
                        // Check for ownerOf call or CALLER comparison
                        if self.bytecode[j] == 0x63 {
                            if j + 4 < self.bytecode.len() {
                                if self.bytecode[j+1] == 0x63 && self.bytecode[j+2] == 0x52 && 
                                   self.bytecode[j+3] == 0x21 && self.bytecode[j+4] == 0x1e {
                                    has_owner_check = true;
                                    break;
                                }
                            }
                        }
                        if self.bytecode[j] == 0x33 { // CALLER check
                            has_owner_check = true;
                            break;
                        }
                    }
                    return !has_owner_check;
                }
            }
        }
        false
    }
}
