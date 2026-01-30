use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArbitrumSequencerInboxVulnerability {
    SequencerBypass { description: String, location: usize, confidence: f32 },
    DelayedInboxExploit { description: String, location: usize, confidence: f32 },
    BatchSubmissionManipulation { description: String, location: usize, confidence: f32 },
}

pub struct ArbitrumSequencerInboxDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumSequencerInboxDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ArbitrumSequencerInboxVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.validates_sequencer() && !self.checks_delay_period() {
            vulnerabilities.push(ArbitrumSequencerInboxVulnerability::SequencerBypass {
                description: "Sequencer validation without delay period - forced inclusion bypass".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.processes_delayed_messages() && !self.validates_batch_hash() {
            vulnerabilities.push(ArbitrumSequencerInboxVulnerability::DelayedInboxExploit {
                description: "Delayed message processing without batch validation - message reordering".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.submits_batch() && !self.verifies_batch_signature() {
            vulnerabilities.push(ArbitrumSequencerInboxVulnerability::BatchSubmissionManipulation {
                description: "Batch submission without signature verification - unauthorized batch".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn validates_sequencer(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        eq_count > 2 && caller_count > 0
    }
    
    fn checks_delay_period(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && sload_count > 3 && gt_count > 1
    }
    
    fn processes_delayed_messages(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sload_count > 4 && sstore_count > 3
    }
    
    fn validates_batch_hash(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 1 && eq_count > 3
    }
    
    fn submits_batch(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 3 && log_count > 1
    }
    
    fn verifies_batch_signature(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        staticcall_count > 1 && iszero_count > 2
    }
}
