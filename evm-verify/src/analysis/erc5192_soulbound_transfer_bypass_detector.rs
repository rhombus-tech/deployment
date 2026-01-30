pub struct Erc5192SoulboundTransferBypassDetector {
    bytecode: Vec<u8>,
}

impl Erc5192SoulboundTransferBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_transfer_bypass() {
            findings.push("ERC5192: Soulbound transfer restriction can be bypassed".to_string());
        }

        if self.has_inconsistent_locked_state() {
            findings.push("ERC5192: Locked state inconsistent with transfer functions".to_string());
        }

        if self.has_approval_bypass() {
            findings.push("ERC5192: Approval mechanisms bypass soulbound restrictions".to_string());
        }

        findings
    }

    fn has_transfer_bypass(&self) -> bool {
        let soulbound_patterns = [b"locked", b"Locked", b"ERC5192"];
        let has_soulbound = soulbound_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_soulbound {
            let transfer_patterns = [b"transfer", b"safeTransfer", b"transferFrom"];
            let has_transfer = transfer_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_transfer {
                // Check if locked() is checked before transfers
                let has_locked_check = self.bytecode.windows(6).any(|w| w == b"locked");
                
                // Look for REVERT after locked check
                let mut has_revert_after_locked = false;
                for i in 0..self.bytecode.len().saturating_sub(10) {
                    if self.bytecode[i..].windows(6).any(|w| w == b"locked") {
                        if self.bytecode[i..i+10].iter().any(|&b| b == 0xfd) { // REVERT
                            has_revert_after_locked = true;
                            break;
                        }
                    }
                }
                
                return !has_revert_after_locked;
            }
        }
        
        false
    }

    fn has_inconsistent_locked_state(&self) -> bool {
        let has_locked_func = self.bytecode.windows(6).any(|w| w == b"locked");
        let has_transfer = self.bytecode.windows(8).any(|w| w == b"transfer");
        
        if has_locked_func && has_transfer {
            // Check if locked() always returns true
            // Look for constant true returns
            for i in 0..self.bytecode.len().saturating_sub(2) {
                if self.bytecode[i] == 0x60 && self.bytecode[i+1] == 0x01 { // PUSH1 1 (true)
                    return false; // Has locked = true constant
                }
            }
            return true; // No constant true found
        }
        
        false
    }

    fn has_approval_bypass(&self) -> bool {
        let approval_patterns = [b"approve", b"setApprovalForAll"];
        let has_approval = approval_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_approval {
            let has_locked = self.bytecode.windows(6).any(|w| w == b"locked");
            
            if has_locked {
                // Approvals should be blocked when locked
                return true; // Simplified - would need flow analysis
            }
        }
        
        false
    }
}
