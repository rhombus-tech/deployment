use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc2612PermitFrontrunVulnerability {
    NoNonceCancellation { description: String, location: usize, confidence: f32 },
    PermitReplayable { description: String, location: usize },
    DeadlineTooLong { description: String, location: usize },
    NonceNotIncremented { description: String, location: usize },
}

pub struct Erc2612PermitFrontrunDetector {
    bytecode: Vec<u8>,
}

impl Erc2612PermitFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc2612PermitFrontrunVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_permit_function(i) {
                if !self.has_nonce_cancellation_function() {
                    vulnerabilities.push(Erc2612PermitFrontrunVulnerability::NoNonceCancellation {
                        description: "ERC-2612 permit without nonce cancellation - frontrun vulnerable".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if !self.increments_nonce(i, i + 150) {
                    vulnerabilities.push(Erc2612PermitFrontrunVulnerability::NonceNotIncremented {
                        description: "Permit doesn't increment nonce - replay attack possible".to_string(),
                        location: i,
                    });
                }
                
                if !self.validates_deadline(i, i + 150) {
                    vulnerabilities.push(Erc2612PermitFrontrunVulnerability::DeadlineTooLong {
                        description: "Permit deadline not properly validated".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_permit_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // permit() selector: 0xd505accf
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0xd5, 0x05, 0xac, 0xcf])
    }
    
    fn has_nonce_cancellation_function(&self) -> bool {
        // Look for invalidateNonce or cancelPermit functions
        // Common selectors for nonce cancellation
        let cancel_selectors = [
            [0x30, 0x5f, 0x3e, 0x65], // Example: cancelPermit
            [0x7e, 0xcb, 0xe8, 0x91], // Example: invalidateNonce
        ];
        
        cancel_selectors.iter().any(|sel| {
            self.bytecode.windows(4).any(|w| w == sel)
        })
    }
    
    fn increments_nonce(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Nonce increment pattern: SLOAD, ADD 1, SSTORE
        let mut has_sload = false;
        let mut has_add = false;
        let mut has_sstore = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if has_sload && self.bytecode[i] == 0x01 { has_add = true; }
            if has_add && self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        
        has_sload && has_add && has_sstore
    }
    
    fn validates_deadline(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Deadline validation: block.timestamp <= deadline
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let has_comparison = self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11);
        
        has_timestamp && has_comparison
    }
}
