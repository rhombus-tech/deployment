use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc20TransferReturnUncheckedVulnerability {
    TransferReturnIgnored { description: String, location: usize, confidence: f32 },
    TransferFromReturnIgnored { description: String, location: usize, confidence: f32 },
    NoSafeTransferWrapper { description: String, location: usize },
}

pub struct Erc20TransferReturnUncheckedDetector {
    bytecode: Vec<u8>,
}

impl Erc20TransferReturnUncheckedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc20TransferReturnUncheckedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // ERC20 transfer(): 0xa9059cbb
        // ERC20 transferFrom(): 0x23b872dd
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb];
        let transfer_from_selector = [0x23, 0xb8, 0x72, 0xdd];
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Check for CALL/STATICCALL to external contract with transfer selector
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA { // CALL or STATICCALL
                // Look back for selector
                if self.has_transfer_selector_before(i, transfer_selector) {
                    if !self.checks_return_value_after(i) {
                        vulnerabilities.push(Erc20TransferReturnUncheckedVulnerability::TransferReturnIgnored {
                            description: "ERC20 transfer() return value not checked - USDT/BNB will fail silently".to_string(),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                }
                
                if self.has_transfer_selector_before(i, transfer_from_selector) {
                    if !self.checks_return_value_after(i) {
                        vulnerabilities.push(Erc20TransferReturnUncheckedVulnerability::TransferFromReturnIgnored {
                            description: "ERC20 transferFrom() return value not checked - silent failure possible".to_string(),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_transfer_selector_before(&self, call_location: usize, selector: [u8; 4]) -> bool {
        let start = call_location.saturating_sub(40);
        
        self.bytecode[start..call_location]
            .windows(4)
            .any(|w| w == selector)
    }
    
    fn checks_return_value_after(&self, call_location: usize) -> bool {
        let end = (call_location + 20).min(self.bytecode.len());
        
        // Pattern after CALL: ISZERO ISZERO (double negation to check true)
        // Or: ISZERO JUMPI (revert if false)
        let has_iszero = self.bytecode[call_location..end].iter().any(|&b| b == 0x15);
        let has_revert = self.bytecode[call_location..end].iter().any(|&b| b == 0xFD);
        
        // Should have at least one check
        has_iszero && has_revert
    }
}
