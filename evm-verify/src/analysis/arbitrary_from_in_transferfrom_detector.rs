/// Arbitrary From in TransferFrom Detector
/// Detects ERC20 transferFrom where 'from' parameter can be manipulated
/// Vulnerable pattern: transferFrom without proper validation of 'from' address

use crate::bytecode::SecurityFinding;

pub struct ArbitraryFromInTransferFromDetector {
    bytecode: Vec<u8>,
}

impl ArbitraryFromInTransferFromDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_arbitrary_from_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Arbitrary 'from' in transferFrom at PC {}. Attacker can specify any address as 'from' parameter to steal tokens without validation",
                    location
                ),
                pc: location,
                confidence: 0.90,
            });
        }

        findings
    }

    fn has_arbitrary_from_vulnerability(&self) -> Option<usize> {
        // Look for transferFrom function selector: 0x23b872dd
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() { // PUSH4
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // transferFrom selector
                if selector == 0x23b872dd {
                    // Check if 'from' parameter is validated
                    // Should have: CALLDATALOAD for 'from', CALLER comparison, or allowance check
                    let has_from_validation = self.has_from_validation_after(i);
                    let has_allowance_check = self.has_allowance_check_after(i);
                    
                    if !has_from_validation && !has_allowance_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_from_validation_after(&self, selector_pos: usize) -> bool {
        let end = (selector_pos + 150).min(self.bytecode.len());
        
        // Look for: CALLDATALOAD (get 'from'), CALLER (get msg.sender), EQ (compare)
        for i in selector_pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check for CALLER comparison nearby
                for j in (i + 1)..(i + 20).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x33 { // CALLER
                        // Look for EQ comparison
                        for k in (j + 1)..(j + 10).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0x14 { // EQ
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn has_allowance_check_after(&self, selector_pos: usize) -> bool {
        let end = (selector_pos + 200).min(self.bytecode.len());
        
        // Look for allowance storage read: SLOAD with mapping pattern
        // Pattern: 'from' address + mapping slot calculation
        for i in selector_pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if preceded by KECCAK256 (mapping key calculation)
                if i > 0 && i.saturating_sub(30) < self.bytecode.len() {
                    for j in i.saturating_sub(30)..i {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x20 { // KECCAK256
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}
