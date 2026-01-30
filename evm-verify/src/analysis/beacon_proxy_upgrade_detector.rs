/// Beacon Proxy Upgrade Detector
use crate::bytecode::SecurityFinding;

pub struct BeaconProxyUpgradeDetector {
    bytecode: Vec<u8>,
}

impl BeaconProxyUpgradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        self.detect_vulnerability().map(|loc| vec![SecurityFinding {
            severity: crate::bytecode::SecuritySeverity::High,
            description: format!("Beacon proxy unauthorized upgrade at PC {}", loc),
            pc: loc, confidence: 0.88,
        }]).unwrap_or_default()
    }
    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 && i > 20 { // SSTORE
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0xfa { // STATICCALL (beacon)
                        let mut has_auth = false;
                        for k in j..i { if self.bytecode[k] == 0x33 { has_auth = true; break; } }
                        if !has_auth { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
