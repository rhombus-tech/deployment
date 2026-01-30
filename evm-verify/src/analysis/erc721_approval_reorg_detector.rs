/// ERC721 Approval Reorg Detector
/// Detects race condition in ERC721 approvals during chain reorganizations
use crate::bytecode::SecurityFinding;

pub struct Erc721ApprovalReorgDetector {
    bytecode: Vec<u8>,
}

impl Erc721ApprovalReorgDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_unsafe_approval() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "ERC721 approval reorg vulnerability at PC {}. Approval changes without block confirmation checks vulnerable to chain reorganization attacks",
                    location
                ),
                pc: location,
                confidence: 0.82,
            });
        }

        findings
    }

    fn has_unsafe_approval(&self) -> Option<usize> {
        // Look for approve selector: 0x095ea7b3
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1], self.bytecode[i + 2],
                    self.bytecode[i + 3], self.bytecode[i + 4],
                ]);
                
                if selector == 0x095ea7b3 {
                    let has_block_check = self.has_block_confirmation_check(i);
                    if !has_block_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_block_confirmation_check(&self, pos: usize) -> bool {
        let end = (pos + 100).min(self.bytecode.len());
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x43 { // NUMBER (block number check)
                return true;
            }
        }
        false
    }
}
