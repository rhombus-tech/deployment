/// Rental NFT Theft Detector
use crate::bytecode::SecurityFinding;

pub struct RentalNftTheftDetector {
    bytecode: Vec<u8>,
}

impl RentalNftTheftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Rental NFT theft vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_rental_theft(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_rental_theft(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for rental return without proper ownership validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // returnRental, endRental, claimRental selectors
            if matches!(self.bytecode[pos+1], 0x3d | 0x6e | 0x91 | 0xc5) {
                let mut has_ownership_check = false;
                let mut has_expiry_check = false;
                let mut has_approval_revocation = false;
                let mut checks_original_owner = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for ownership validation (comparing caller to original owner)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 8 < self.bytecode.len() { // CALLER
                            if self.bytecode[j + 3] == 0x54 && self.bytecode[j + 5] == 0x14 { // SLOAD + EQ
                                has_ownership_check = true;
                            }
                        }
                    }
                    
                    // Check for expiry time validation
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) &&
                               matches!(self.bytecode[j + 5], 0x57 | 0xfd) {
                                has_expiry_check = true;
                            }
                        }
                    }
                    
                    // Check for approval revocation (setApprovalForAll call)
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            // setApprovalForAll selector check
                            if self.bytecode[j + 1] == 0xa2 {
                                has_approval_revocation = true;
                            }
                        }
                    }
                    
                    // Check if it reads original owner from storage
                    let mut owner_reads = 0;
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            owner_reads += 1;
                        }
                    }
                    if owner_reads >= 2 {
                        checks_original_owner = true;
                    }
                }
                
                // Vulnerable if missing critical checks for rental returns
                return !has_ownership_check || !has_expiry_check || !has_approval_revocation || !checks_original_owner;
            }
        }
        false
    }
}
