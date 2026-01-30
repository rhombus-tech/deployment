use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SequencerLivenessAssumptionVulnerability {
    UnhandledSequencerFailure { description: String, location: usize, confidence: f32 },
    MissingForcedInclusionPath { description: String, location: usize, confidence: f32 },
    LivenessDeadlock { description: String, location: usize, confidence: f32 },
}

pub struct SequencerLivenessAssumptionDetector {
    bytecode: Vec<u8>,
}

impl SequencerLivenessAssumptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SequencerLivenessAssumptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.assumes_sequencer_liveness() && !self.has_fallback_mechanism() {
            vulnerabilities.push(SequencerLivenessAssumptionVulnerability::UnhandledSequencerFailure {
                description: "Assumes L2 sequencer liveness without fallback - service disruption risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.has_time_dependent_logic() && !self.has_forced_inclusion() {
            vulnerabilities.push(SequencerLivenessAssumptionVulnerability::MissingForcedInclusionPath {
                description: "Time-dependent logic without forced inclusion path - censorship risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_sequencer_dependency() && self.has_state_locks() {
            vulnerabilities.push(SequencerLivenessAssumptionVulnerability::LivenessDeadlock {
                description: "Sequencer dependency with state locks - deadlock risk on sequencer failure".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn assumes_sequencer_liveness(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let blocknumber_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        (timestamp_count + blocknumber_count) > 3
    }
    
    fn has_fallback_mechanism(&self) -> bool {
        let try_catch = self.bytecode.windows(3).any(|w| w == [0xFA, 0x3D, 0x57]);
        try_catch
    }
    
    fn has_time_dependent_logic(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        timestamp_count > 2 && sub_count > 3
    }
    
    fn has_forced_inclusion(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        call_count > 2 && staticcall_count > 2
    }
    
    fn has_sequencer_dependency(&self) -> bool {
        let extcodesize_count = self.bytecode.iter().filter(|&&b| b == 0x3B).count();
        extcodesize_count > 1
    }
    
    fn has_state_locks(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 3 && sstore_count > 2 && iszero_count > 3
    }
}
