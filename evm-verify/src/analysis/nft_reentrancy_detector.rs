/// NFT Reentrancy Detector
/// Detects reentrancy vulnerabilities in NFT transfer callbacks
use crate::bytecode::SecurityFinding;

pub struct NftReentrancyDetector {
    bytecode: Vec<u8>,
}

impl NftReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_nft_reentrancy() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "NFT reentrancy at PC {}. ERC721/ERC1155 receiver callback before state update allows reentrant attacks",
                    location
                ),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn has_nft_reentrancy(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // onERC721Received: 0x150b7a02, onERC1155Received: 0xf23a6e61
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let sel = u32::from_be_bytes([self.bytecode[i+1],self.bytecode[i+2],self.bytecode[i+3],self.bytecode[i+4]]);
                if sel == 0x150b7a02 || sel == 0xf23a6e61 {
                    if self.has_external_call_before_sstore(i) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_external_call_before_sstore(&self, pos: usize) -> bool {
        let end = (pos + 100).min(self.bytecode.len());
        let mut found_call = false;
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { found_call = true; }
            if found_call && self.bytecode[i] == 0x55 { return true; }
        }
        false
    }
}
