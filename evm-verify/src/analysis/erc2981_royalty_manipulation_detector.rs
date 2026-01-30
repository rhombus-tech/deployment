pub struct Erc2981RoyaltyManipulationDetector {
    bytecode: Vec<u8>,
}

impl Erc2981RoyaltyManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_royalty_bypass() {
            findings.push("ERC2981: Royalty payments can be bypassed".to_string());
        }

        if self.has_mutable_royalty_info() {
            findings.push("ERC2981: Royalty info can be manipulated after minting".to_string());
        }

        if self.has_excessive_royalty_percentage() {
            findings.push("ERC2981: Excessive royalty percentage (>10%) detected".to_string());
        }

        findings
    }

    fn has_royalty_bypass(&self) -> bool {
        let royalty_patterns = [b"royaltyInfo", b"ERC2981"];
        let has_royalty = royalty_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_royalty {
            let transfer_patterns = [b"transfer", b"safeTransfer"];
            let has_transfer = transfer_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_transfer {
                // Check if royaltyInfo is called before transfer
                return true; // Simplified check - in reality would need control flow analysis
            }
        }
        
        false
    }

    fn has_mutable_royalty_info(&self) -> bool {
        let royalty_set_patterns = [b"setRoyalty", b"updateRoyalty", b"setDefaultRoyalty"];
        let has_setter = royalty_set_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_setter {
            // Check for proper access control
            let access_patterns = [b"onlyOwner", b"onlyAdmin", b"AccessControl"];
            let has_access_control = access_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_access_control;
        }
        
        false
    }

    fn has_excessive_royalty_percentage(&self) -> bool {
        let has_royalty = self.bytecode.windows(11).any(|w| w == b"royaltyInfo");
        
        if has_royalty {
            // Look for percentage calculations (10000 basis points = 100%)
            // Check for values > 1000 (10%)
            for i in 0..self.bytecode.len().saturating_sub(3) {
                if self.bytecode[i] == 0x61 { // PUSH2
                    let value = ((self.bytecode[i+1] as u16) << 8) | (self.bytecode[i+2] as u16);
                    if value > 1000 && value <= 10000 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
