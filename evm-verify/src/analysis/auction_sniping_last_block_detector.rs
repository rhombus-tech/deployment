use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct AuctionSnipingLastBlockDetector;

impl AuctionSnipingLastBlockDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if bytecode[i] == 0x42 {
                if self.has_auction_end_logic(bytecode, i) && self.lacks_commit_reveal(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Auction sniping vulnerability: timestamp-based auction end without commit-reveal scheme allows last-block sniping".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }
            i += 1;
        }

        findings
    }

    fn has_auction_end_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_finalization = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 => has_comparison = true,
                    0x55 => has_finalization = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_finalization
    }

    fn lacks_commit_reveal(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        for offset in 1..window {
            if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x20 {
                return false;
            }
        }
        true
    }
}
