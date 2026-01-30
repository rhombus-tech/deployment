/// Token Bound Account (ERC-6551) Drain Detector
use crate::bytecode::SecurityFinding;

pub struct TokenBoundAccountDrainDetector {
    bytecode: Vec<u8>,
}

impl TokenBoundAccountDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Token Bound Account drain vulnerability at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_tba_drain(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_tba_drain(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for TBA execution without proper NFT ownership validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // execute, executeCall, executeBatch (ERC-6551 TBA) selectors
            if matches!(self.bytecode[pos+1], 0x51 | 0x61 | 0xb6 | 0xc5) {
                let mut has_nft_owner_check = false;
                let mut has_registry_validation = false;
                let mut has_call_validation = false;
                let mut checks_token_ownership = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for NFT ownership validation (calling ownerOf on NFT contract)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            // ownerOf selector (0x6352211e)
                            if self.bytecode[j + 1] == 0x63 {
                                has_nft_owner_check = true;
                            }
                        }
                    }
                    
                    // Check for registry validation (verifying account creation via registry)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            has_registry_validation = true;
                        }
                    }
                    
                    // Check for target call validation (checking calldata and target address)
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 && j + 3 < self.bytecode.len() { // EQ
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_call_validation = true;
                            }
                        }
                    }
                    
                    // Check if it reads token contract and tokenId
                    let mut external_reads = 0;
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            external_reads += 1;
                        }
                    }
                    if external_reads >= 2 {
                        checks_token_ownership = true;
                    }
                }
                
                // Vulnerable if executes calls without validating NFT ownership
                return !has_nft_owner_check || !has_registry_validation || !has_call_validation || !checks_token_ownership;
            }
        }
        false
    }
}
