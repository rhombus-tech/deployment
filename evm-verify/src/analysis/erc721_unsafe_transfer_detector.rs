/// ERC721 Unsafe Transfer Detector
use crate::bytecode::SecurityFinding;

pub struct Erc721UnsafeTransferDetector {
    bytecode: Vec<u8>,
}

impl Erc721UnsafeTransferDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("ERC721 unsafe transfer to contract at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_unsafe_transfer(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_unsafe_transfer(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // transferFrom: 0x23b872dd, safeTransferFrom: 0x42842e0e
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if self.bytecode[pos+1] == 0x23 && self.bytecode[pos+2] == 0xb8 {
                // Check if recipient is contract without onERC721Received check
                if pos + 40 < self.bytecode.len() {
                    let mut has_receiver_check = false;
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            // onERC721Received: 0x150b7a02
                            if self.bytecode[j+1] == 0x15 && self.bytecode[j+2] == 0x0b {
                                has_receiver_check = true;
                                break;
                            }
                        }
                    }
                    return !has_receiver_check;
                }
            }
        }
        false
    }
}
