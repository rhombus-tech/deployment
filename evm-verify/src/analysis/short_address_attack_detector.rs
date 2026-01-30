/// Short Address Attack Detector
/// Detects ERC20 token padding exploit where shortened addresses cause value inflation
/// Vulnerable pattern: Missing input length validation in transfer functions

use crate::bytecode::SecurityFinding;

pub struct ShortAddressAttackDetector {
    bytecode: Vec<u8>,
}

impl ShortAddressAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Check ERC20 transfer/transferFrom functions for missing calldatasize check
        if let Some(location) = self.has_transfer_without_length_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Short address attack vulnerability at PC {}. Transfer function lacks calldata length validation, allowing value inflation through address padding",
                    location
                ),
                pc: location,
                confidence: 0.85,
            });
        }

        findings
    }

    fn has_transfer_without_length_check(&self) -> Option<usize> {
        // Pattern: Look for CALLDATALOAD without prior CALLDATASIZE check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for transfer function selector patterns (0xa9059cbb = transfer, 0x23b872dd = transferFrom)
            if i + 4 < self.bytecode.len() {
                if self.bytecode[i] == 0x63 { // PUSH4
                    let selector = u32::from_be_bytes([
                        self.bytecode[i + 1],
                        self.bytecode[i + 2],
                        self.bytecode[i + 3],
                        self.bytecode[i + 4],
                    ]);
                    
                    // Check if it's transfer or transferFrom
                    if selector == 0xa9059cbb || selector == 0x23b872dd {
                        // Look ahead for CALLDATALOAD without CALLDATASIZE check
                        let has_calldataload = self.has_calldataload_in_range(i, i + 100);
                        let has_calldatasize_check = self.has_calldatasize_check_in_range(i, i + 100);
                        
                        if has_calldataload && !has_calldatasize_check {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_calldataload_in_range(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                return true;
            }
        }
        false
    }

    fn has_calldatasize_check_in_range(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x36 { // CALLDATASIZE
                // Check if followed by comparison (LT, GT, EQ)
                if i + 1 < self.bytecode.len() {
                    let next = self.bytecode[i + 1];
                    if next == 0x10 || next == 0x11 || next == 0x14 { // LT, GT, EQ
                        return true;
                    }
                }
            }
        }
        false
    }
}
