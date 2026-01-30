/// Chainlink Round Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct ChainlinkRoundManipulationDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkRoundManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Chainlink round manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.check_round_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_round_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for latestRoundData usage without round completeness check
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // latestRoundData selector: 0xfeaf968c
            if self.bytecode[pos+1] == 0xfe && self.bytecode[pos+2] == 0xaf {
                let mut has_round_id_check = false;
                let mut has_answered_in_round_check = false;
                
                if pos + 40 < self.bytecode.len() {
                    // Look for roundId == answeredInRound check
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        // EQ comparison between two return values
                        if self.bytecode[j] == 0x14 { // EQ
                            if j + 5 < self.bytecode.len() {
                                // Check if followed by REVERT on inequality
                                if matches!(self.bytecode[j + 3], 0x57 | 0xfd) {
                                    has_round_id_check = true;
                                }
                            }
                        }
                        // Check for answeredInRound > 0
                        if self.bytecode[j] == 0x11 && j > 3 { // GT
                            if self.bytecode[j-2] == 0x60 && self.bytecode[j-1] == 0x00 {
                                has_answered_in_round_check = true;
                            }
                        }
                    }
                }
                return !has_round_id_check || !has_answered_in_round_check;
            }
        }
        false
    }
}
