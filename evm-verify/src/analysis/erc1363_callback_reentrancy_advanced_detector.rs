pub struct Erc1363CallbackReentrancyAdvancedDetector {
    bytecode: Vec<u8>,
}

impl Erc1363CallbackReentrancyAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_callback_reentrancy() {
            findings.push("ERC1363: Callback reentrancy vulnerability in ERC1363 operations".to_string());
        }

        if self.has_unsafe_callback_handling() {
            findings.push("ERC1363: Unsafe callback handling without state checks".to_string());
        }

        if self.has_callback_gas_griefing() {
            findings.push("ERC1363: Callback operations vulnerable to gas griefing".to_string());
        }

        findings
    }

    fn has_callback_reentrancy(&self) -> bool {
        let erc1363_patterns = [b"transferAndCall", b"transferFromAndCall", b"approveAndCall"];
        let has_erc1363 = erc1363_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_erc1363 {
            let callback_patterns = [b"onTransferReceived", b"onApprovalReceived"];
            let has_callback = callback_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            if has_callback {
                let has_guard = self.bytecode.windows(10).any(|w| w == b"nonReentra" || w == b"ReentrancyG");
                return !has_guard;
            }
        }
        
        false
    }

    fn has_unsafe_callback_handling(&self) -> bool {
        let callback_patterns = [b"onTransferReceived", b"onApprovalReceived"];
        let has_callback = callback_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_callback {
            // Check for state updates after external calls
            let mut call_positions = Vec::new();
            let mut sstore_positions = Vec::new();
            
            for (i, &byte) in self.bytecode.iter().enumerate() {
                if byte == 0xf1 || byte == 0xf4 { // CALL, DELEGATECALL
                    call_positions.push(i);
                } else if byte == 0x55 { // SSTORE
                    sstore_positions.push(i);
                }
            }
            
            // Check if SSTORE happens after CALL
            for &call_pos in &call_positions {
                if sstore_positions.iter().any(|&sstore_pos| sstore_pos > call_pos) {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_callback_gas_griefing(&self) -> bool {
        let callback_patterns = [b"onTransferReceived", b"onApprovalReceived"];
        let has_callback = callback_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_callback {
            // Check for GAS opcode usage (explicit gas forwarding)
            let has_gas_control = self.bytecode.iter().any(|&b| b == 0x5a); // GAS
            
            return !has_gas_control;
        }
        
        false
    }
}
