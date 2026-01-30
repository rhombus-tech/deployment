/// Dynamic NFT Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct DynamicNftManipulationDetector {
    bytecode: Vec<u8>,
}

impl DynamicNftManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Dynamic NFT manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_metadata_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_metadata_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for tokenURI or metadata update without proper access control
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // tokenURI, setTokenURI, updateMetadata selectors
            if matches!(self.bytecode[pos+1], 0xc8 | 0x16 | 0x2e | 0x75) {
                let mut has_owner_check = false;
                let mut has_timelock = false;
                let mut has_metadata_validation = false;
                let mut checks_token_existence = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for owner/authorized modifier
                    for j in (pos + 5)..(pos + 25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 8 < self.bytecode.len() { // CALLER
                            if self.bytecode[j + 3] == 0x54 && self.bytecode[j + 5] == 0x14 { // SLOAD + EQ
                                has_owner_check = true;
                            }
                        }
                    }
                    
                    // Check for timelock on metadata changes
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) {
                                has_timelock = true;
                            }
                        }
                    }
                    
                    // Check for metadata format validation (checking string length/format)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_metadata_validation = true;
                            }
                        }
                    }
                    
                    // Check if validates token exists
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 4 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 2] == 0x15 { // ISZERO
                                checks_token_existence = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if metadata can be changed without proper controls
                return !has_owner_check || (!has_timelock && !has_metadata_validation) || !checks_token_existence;
            }
        }
        false
    }
}
