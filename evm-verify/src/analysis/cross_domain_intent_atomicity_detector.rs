use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossDomainIntentAtomicityVulnerability {
    PartialIntentExecution { description: String, location: usize, confidence: f32 },
    CrossChainAtomicityBreak { description: String, location: usize, confidence: f32 },
    IntentReplayRisk { description: String, location: usize, confidence: f32 },
}

pub struct CrossDomainIntentAtomicityDetector {
    bytecode: Vec<u8>,
}

impl CrossDomainIntentAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossDomainIntentAtomicityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.executes_intents() && !self.ensures_atomicity() {
            vulnerabilities.push(CrossDomainIntentAtomicityVulnerability::PartialIntentExecution {
                description: "Intent execution without atomicity guarantee - partial fill risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.handles_cross_chain_intents() && !self.validates_chain_consistency() {
            vulnerabilities.push(CrossDomainIntentAtomicityVulnerability::CrossChainAtomicityBreak {
                description: "Cross-chain intent without consistency validation - atomicity break".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.processes_signed_intents() && !self.prevents_replay() {
            vulnerabilities.push(CrossDomainIntentAtomicityVulnerability::IntentReplayRisk {
                description: "Signed intent processing without replay protection - double execution risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn executes_intents(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 3 && sstore_count > 4
    }
    
    fn ensures_atomicity(&self) -> bool {
        // Revert on failure pattern
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        iszero_count > 3 && jumpi_count > 4 && revert_count > 1
    }
    
    fn handles_cross_chain_intents(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let chainid_count = self.bytecode.iter().filter(|&&b| b == 0x46).count();
        call_count > 2 && staticcall_count > 2 && chainid_count > 0
    }
    
    fn validates_chain_consistency(&self) -> bool {
        let chainid_count = self.bytecode.iter().filter(|&&b| b == 0x46).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        chainid_count > 0 && eq_count > 2 && jumpi_count > 3
    }
    
    fn processes_signed_intents(&self) -> bool {
        // Signature verification (ecrecover or similar)
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        staticcall_count > 1 && sha3_count > 1
    }
    
    fn prevents_replay(&self) -> bool {
        // Nonce or used flag tracking
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 4 && sstore_count > 3 && iszero_count > 2
    }
}
