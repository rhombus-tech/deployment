/// NFT Royalty Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct NftRoyaltyBypassDetector {
    bytecode: Vec<u8>,
}

impl NftRoyaltyBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("NFT royalty bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_royalty_enforcement(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_royalty_enforcement(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for transferFrom without royalty check (ERC721: 0x23b872dd, ERC1155: 0xf242432a)
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            let is_transfer = (self.bytecode[pos+1] == 0x23 && self.bytecode[pos+2] == 0xb8) ||
                             (self.bytecode[pos+1] == 0xf2 && self.bytecode[pos+2] == 0x42);
            
            if is_transfer {
                // Check if royaltyInfo is called (ERC2981: 0x2a55205a)
                if pos + 60 < self.bytecode.len() {
                    let mut has_royalty_check = false;
                    for j in pos.saturating_sub(40)..(pos + 60).min(self.bytecode.len()) {
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            if self.bytecode[j+1] == 0x2a && self.bytecode[j+2] == 0x55 &&
                               self.bytecode[j+3] == 0x20 && self.bytecode[j+4] == 0x5a {
                                has_royalty_check = true;
                                break;
                            }
                        }
                    }
                    return !has_royalty_check;
                }
            }
        }
        false
    }
}
