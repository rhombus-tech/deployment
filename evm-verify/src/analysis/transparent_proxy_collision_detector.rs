/// Transparent Proxy Collision Detector
use crate::bytecode::SecurityFinding;

pub struct TransparentProxyCollisionDetector {
    bytecode: Vec<u8>,
}

impl TransparentProxyCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        self.detect_vulnerability().map(|loc| vec![SecurityFinding {
            severity: crate::bytecode::SecuritySeverity::Critical,
            description: format!("Transparent proxy storage collision at PC {}", loc),
            pc: loc,
            confidence: 0.90,
        }]).unwrap_or_default()
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x36 && i + 30 < self.bytecode.len() { // CALLDATASIZE
                if self.bytecode.get(i+15..i+25)?.contains(&0xf4) { // DELEGATECALL
                    let mut has_admin_check = false;
                    for j in i..i.saturating_add(30).min(self.bytecode.len()) {
                        if self.bytecode.get(j)? == &0x33 { has_admin_check = true; break; }
                    }
                    if !has_admin_check { return Some(i); }
                }
            }
        }
        None
    }
}
