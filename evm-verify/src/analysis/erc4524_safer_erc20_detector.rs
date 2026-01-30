use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc4524SaferErc20Vulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc4524SaferErc20Detector {
    bytecode: Vec<u8>,
}

impl Erc4524SaferErc20Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4524SaferErc20Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-4524 extends ERC-20 with safe transfer semantics
        // Detect missing receiver validation
        if let Some(location) = self.has_missing_receiver_validation() {
            vulnerabilities.push(Erc4524SaferErc20Vulnerability {
                vulnerability_type: "ERC-4524 Missing Receiver Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Safe transfer without onERC20Received callback verification. Tokens could be sent to contracts unable to handle them, resulting in locked funds. Implement receiver interface check.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect callback reentrancy
        if let Some(location) = self.has_callback_reentrancy() {
            vulnerabilities.push(Erc4524SaferErc20Vulnerability {
                vulnerability_type: "ERC-4524 Receiver Callback Reentrancy".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "onERC20Received callback invoked before state finalization. Malicious receivers can reenter and exploit intermediate state. Use checks-effects-interactions pattern.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect gas limit bypass
        if let Some(location) = self.has_gas_limit_bypass() {
            vulnerabilities.push(Erc4524SaferErc20Vulnerability {
                vulnerability_type: "ERC-4524 Callback Gas Limit Bypass".to_string(),
                location,
                severity: "Medium".to_string(),
                description: "Receiver callback without gas limit. Malicious receivers can consume all gas causing DoS. Limit callback gas to reasonable amount (e.g., 50000).".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_missing_receiver_validation(&self) -> Option<usize> {
        // Pattern: CALL (transfer) without prior EXTCODESIZE check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for balance update (SSTORE)
            if self.bytecode[i] == 0x55 { // SSTORE (balance change)
                // Check if receiver is a contract (EXTCODESIZE check)
                let mut has_code_size_check = false;
                
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x3b { // EXTCODESIZE
                        has_code_size_check = true;
                        break;
                    }
                }
                
                // If it's a contract, should have callback
                if has_code_size_check {
                    // Look for CALL to onERC20Received
                    let mut has_callback = false;
                    for j in i+1..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xfa { // CALL or STATICCALL
                            has_callback = true;
                            break;
                        }
                    }
                    if !has_callback {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_callback_reentrancy(&self) -> Option<usize> {
        // Pattern: CALL (callback) before final SSTORE (state update)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 { // CALL (onERC20Received callback)
                // Check if there's SSTORE after the CALL
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE after callback
                        // This is vulnerable - state updated after external call
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_gas_limit_bypass(&self) -> Option<usize> {
        // Pattern: CALL without explicit gas parameter (uses all available gas)
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL
                // Check if gas parameter is set (PUSH with reasonable value before CALL)
                let mut has_gas_limit = false;
                
                for j in i.saturating_sub(15)..i {
                    // Look for PUSH operations with specific gas values
                    if self.bytecode[j] >= 0x60 && self.bytecode[j] <= 0x7f { // PUSH1-PUSH32
                        // Check if the pushed value looks like a gas limit
                        if j + 1 < self.bytecode.len() {
                            let value = self.bytecode[j + 1] as u32;
                            // Reasonable gas limits are typically 10000-100000
                            if value > 0 && value < 200 { // In practice, this would be larger
                                has_gas_limit = true;
                            }
                        }
                    }
                    // Or GAS opcode (using remaining gas)
                    if self.bytecode[j] == 0x5a { // GAS
                        // Using all remaining gas - check if it's limited
                        for k in j+1..(j+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 || self.bytecode[k] == 0x04 { // SUB or DIV
                                has_gas_limit = true;
                            }
                        }
                    }
                }
                
                if !has_gas_limit {
                    // Verify this looks like a callback (not a simple transfer)
                    for j in i.saturating_sub(10)..i {
                        if self.bytecode[j] == 0x3b { // EXTCODESIZE (checking if contract)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
