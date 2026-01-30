/// UUPS Uninitialized Detector
use crate::bytecode::SecurityFinding;

pub struct UupsUninitializedDetector {
    bytecode: Vec<u8>,
}

impl UupsUninitializedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        self.detect_vulnerability().map(|loc| vec![SecurityFinding {
            severity: crate::bytecode::SecuritySeverity::Critical,
            description: format!("UUPS uninitialized implementation at PC {}", loc),
            pc: loc,
            confidence: 0.91,
        }]).unwrap_or_default()
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf4 && i > 15 {
                let mut has_init_check = false;
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x54 { has_init_check = true; break; }
                }
                if !has_init_check { return Some(i); }
            }
        }
        None
    }
}
