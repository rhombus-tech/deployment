/// Orderbook Spoofing Detector
use crate::bytecode::SecurityFinding;
pub struct OrderbookSpoofingDetector { bytecode: Vec<u8> }
impl OrderbookSpoofingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_instant_cancel() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Order placement/cancellation lacks time delay, spoofing possible at PC {}", pc),
                pc, confidence: 0.82
            });
        }
        findings
    }
    fn detect_instant_cancel(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xac | 0xbd) {
                    let mut has_delay = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { has_delay = true; }
                    }
                    if !has_delay { return Some(i); }
                }
            }
        }
        None
    }
}
