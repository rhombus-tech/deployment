/// Function Selector Clash Detector
/// Detects when functions have identical 4-byte selectors which can lead to exploits
/// Vulnerable pattern: Multiple functions with same first 4 bytes of keccak256(signature)

use crate::bytecode::SecurityFinding;

pub struct FunctionSelectorClashDetector {
    bytecode: Vec<u8>,
}

impl FunctionSelectorClashDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Extract all function selectors from JUMPDEST patterns
        let selectors = self.extract_function_selectors();
        
        // Check for duplicate selectors
        if let Some(location) = self.has_selector_collision(&selectors) {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Function selector clash detected at PC {}. Multiple functions share the same 4-byte selector, allowing attacker to call wrong function",
                    location
                ),
                pc: location,
                confidence: 0.90,
            });
        }

        findings
    }

    fn extract_function_selectors(&self) -> Vec<(usize, u32)> {
        let mut selectors = Vec::new();
        
        // Pattern: PUSH4 <selector> EQ PUSH2 <jumpdest> JUMPI
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x63 { // PUSH4 (function selector)
                if i + 5 < self.bytecode.len() {
                    // Extract 4-byte selector
                    let selector = u32::from_be_bytes([
                        self.bytecode[i + 1],
                        self.bytecode[i + 2],
                        self.bytecode[i + 3],
                        self.bytecode[i + 4],
                    ]);
                    
                    // Verify it's followed by EQ (0x14) - function dispatch pattern
                    if i + 5 < self.bytecode.len() && self.bytecode[i + 5] == 0x14 {
                        selectors.push((i, selector));
                    }
                }
            }
        }
        
        selectors
    }

    fn has_selector_collision(&self, selectors: &[(usize, u32)]) -> Option<usize> {
        // Check for duplicate selectors
        for i in 0..selectors.len() {
            for j in (i + 1)..selectors.len() {
                if selectors[i].1 == selectors[j].1 {
                    // Found collision
                    return Some(selectors[i].0);
                }
            }
        }
        None
    }
}
