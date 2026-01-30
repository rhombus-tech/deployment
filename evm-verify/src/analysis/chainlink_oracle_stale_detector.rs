/// Chainlink Oracle Stale Data Detector
use crate::bytecode::SecurityFinding;

pub struct ChainlinkOracleStaleDetector { bytecode: Vec<u8> }
impl ChainlinkOracleStaleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        self.detect_vulnerability().map(|loc| vec![SecurityFinding {
            severity: crate::bytecode::SecuritySeverity::High,
            description: format!("Chainlink stale price data usage at PC {}", loc),
            pc: loc, confidence: 0.86,
        }]).unwrap_or_default()
    }
    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if self.bytecode[i+1] == 0x50 && self.bytecode[i+2] == 0xd2 { // latestRoundData
                    let mut checks_timestamp = false;
                    for j in (i+5)..(i+40).min(self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { checks_timestamp = true; break; }
                    }
                    if !checks_timestamp { return Some(i); }
                }
            }
        }
        None
    }
}
