use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Uniswap V4 Hook State Poisoning Detector
/// 
/// Detects vulnerabilities where malicious hooks can poison pool state through
/// callback manipulation, affecting subsequent swaps or liquidity operations.
pub struct UniswapV4HookStatePoisoningDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookStatePoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_hook_storage_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Hook modifies storage during callback that affects pool state. Can poison liquidity calculations or fee accumulation for subsequent operations.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_cross_callback_state_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Hook maintains state across multiple callbacks that can be manipulated to grief other users or extract value.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        if self.has_unprotected_hook_storage() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Hook storage can be manipulated without proper access control, allowing state poisoning attacks.".to_string(),
                pc: 0,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_hook_storage_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        
        // Hook callback selectors
        let callbacks = [
            [0x1c, 0xb7, 0xb9, 0xf7], // beforeSwap
            [0x3c, 0x6a, 0x5c, 0x54], // afterSwap
            [0x8f, 0x0c, 0xb5, 0xe3], // beforeModifyPosition
            [0x7d, 0x5f, 0x4e, 0x2a], // afterModifyPosition
        ];

        for selector in &callbacks {
            for i in 0..bytecode.len().saturating_sub(40) {
                if i + 4 <= bytecode.len() && &bytecode[i..i+4] == selector {
                    // Check for SSTORE in callback (modifying storage)
                    for j in i..std::cmp::min(i+35, bytecode.len()) {
                        if bytecode[j] == 0x55 { // SSTORE
                            // Verify not just temporary/local state
                            // Check for slot calculation (indicating persistent state)
                            let mut has_slot_calc = false;
                            for k in j.saturating_sub(10)..j {
                                if bytecode[k] == 0x20 || // SHA3
                                   bytecode[k] == 0x01 || // ADD (slot offset)
                                   bytecode[k] == 0x02 {  // MUL (slot calculation)
                                    has_slot_calc = true;
                                    break;
                                }
                            }
                            
                            if has_slot_calc {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_cross_callback_state_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut callback_storage_access = Vec::new();

        for i in 0..bytecode.len().saturating_sub(20) {
            // Detect storage access (SLOAD/SSTORE) in callbacks
            if bytecode[i] == 0x54 || bytecode[i] == 0x55 { // SLOAD or SSTORE
                // Check if in a callback function
                for j in i.saturating_sub(30)..i {
                    // Look for callback selector comparison
                    if bytecode[j] == 0x14 { // EQ (function selector match)
                        callback_storage_access.push(i);
                        break;
                    }
                }
            }
        }

        // If multiple storage accesses across callbacks, state can be poisoned
        if callback_storage_access.len() >= 3 {
            return Some(callback_storage_access[0]);
        }

        None
    }

    fn has_unprotected_hook_storage(&self) -> bool {
        // This would require more complex analysis of access patterns
        // Simplified check for now
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_state_poisoning() {
        let bytecode = vec![
            0x1c, 0xb7, 0xb9, 0xf7, // beforeSwap selector
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (calculate storage slot)
            0x60, 0xFF, // PUSH1 255 (malicious value)
            0x55, // SSTORE (poison state)
            0xF3, // RETURN
        ];

        let detector = UniswapV4HookStatePoisoningDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("State Poisoning")));
    }
}
