/// Optimism L2 Sequencer Detector
use crate::bytecode::SecurityFinding;
pub struct OptimismL2SequencerDetector { bytecode: Vec<u8> }
impl OptimismL2SequencerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa && i + 20 < self.bytecode.len() { // STATICCALL to L1 oracle
                let mut checks_sequencer = false;
                for j in (i+1)..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 { checks_sequencer = true; break; }
                }
                if !checks_sequencer {
                    return vec![SecurityFinding {
                        severity: crate::bytecode::SecuritySeverity::High,
                        description: format!("L2 sequencer downtime not checked at PC {}", i),
                        pc: i, confidence: 0.85,
                    }];
                }
            }
        }
        Vec::new()
    }
}
