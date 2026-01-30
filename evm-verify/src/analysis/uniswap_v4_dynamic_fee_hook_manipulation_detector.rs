use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Uniswap V4 Dynamic Fee Hook Manipulation Detector
/// 
/// Detects vulnerabilities in Uniswap V4 hooks that manipulate swap fees dynamically.
/// Malicious hooks can front-run transactions to extract MEV or drain liquidity.
/// 
/// Real Risk: Uniswap V4 hooks can modify fees before/after swaps, enabling sophisticated attacks
pub struct UniswapV4DynamicFeeHookManipulationDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4DynamicFeeHookManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // CRITICAL FIX: Only analyze if contract implements Uniswap V4 hooks
        if !self.is_uniswap_v4_hook() {
            return findings; // Empty - not a Uniswap V4 hook contract
        }

        // Pattern 1: beforeSwap hook with fee manipulation
        if let Some(pc) = self.detect_before_swap_fee_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Hook contract can manipulate swap fees in beforeSwap callback. Malicious hook can extract MEV by adjusting fees based on swap parameters.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        // Pattern 2: Unchecked fee bounds in hook
        if let Some(pc) = self.detect_unbounded_fee_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Hook modifies fees without proper bounds checking. Fees can be set arbitrarily high to grief swappers or extract excessive value.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        // Pattern 3: Fee manipulation based on external state
        if self.has_external_state_fee_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Hook fee calculation depends on external contract state. Fee can be manipulated via oracle manipulation or flash loans.".to_string(),
                pc: 0,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_before_swap_fee_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        // beforeSwap function selector: 0x1cb7b9f7 (first 4 bytes)
        let before_swap_selector = [0x1c, 0xb7, 0xb9, 0xf7];

        for i in 0..bytecode.len().saturating_sub(50) {
            // Look for beforeSwap selector
            if i + 4 <= bytecode.len() && 
               bytecode[i..i+4] == before_swap_selector {
                
                // Check if fee is modified in this function
                // Pattern: Load fee, modify it, return modified value
                for j in i..std::cmp::min(i+45, bytecode.len().saturating_sub(5)) {
                    // Fee modification pattern: arithmetic operations on fee value
                    if (bytecode[j] == 0x01 || // ADD
                        bytecode[j] == 0x02 || // MUL
                        bytecode[j] == 0x03 || // SUB
                        bytecode[j] == 0x04 || // DIV
                        bytecode[j] == 0x05) { // SDIV
                        
                        // Check if followed by RETURN (returning modified fee)
                        for k in j..std::cmp::min(j+10, bytecode.len()) {
                            if bytecode[k] == 0xF3 { // RETURN
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_unbounded_fee_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(30) {
            // Look for fee modification without bounds checking
            // Pattern: Modify fee value without GT/LT comparison
            
            if bytecode[i] == 0x01 || bytecode[i] == 0x02 { // ADD or MUL
                let mut has_bounds_check = false;
                
                // Check preceding 20 bytes for bounds checking
                let start = i.saturating_sub(20);
                for j in start..i {
                    if bytecode[j] == 0x10 || // LT
                       bytecode[j] == 0x11 || // GT
                       bytecode[j] == 0x12 || // SLT
                       bytecode[j] == 0x13 {  // SGT
                        has_bounds_check = true;
                        break;
                    }
                }

                // Check following 10 bytes for REVERT (validation)
                let mut has_validation = false;
                for j in i..std::cmp::min(i+10, bytecode.len()) {
                    if bytecode[j] == 0xFD { // REVERT
                        has_validation = true;
                        break;
                    }
                }

                // Unbounded if no checks found
                if !has_bounds_check && !has_validation {
                    // Verify this is in a function that returns (likely hook callback)
                    for j in i..std::cmp::min(i+20, bytecode.len()) {
                        if bytecode[j] == 0xF3 { // RETURN
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }

    fn has_external_state_fee_manipulation(&self) -> bool {
        let bytecode = &self.bytecode;
        let mut has_external_call = false;
        let mut has_fee_modification = false;

        for i in 0..bytecode.len().saturating_sub(20) {
            // Check for external calls (STATICCALL to read external state)
            if bytecode[i] == 0xFA { // STATICCALL
                has_external_call = true;
            }

            // Check for fee modification after external call
            if has_external_call && 
               (bytecode[i] == 0x01 || // ADD
                bytecode[i] == 0x02 || // MUL
                bytecode[i] == 0x03 || // SUB
                bytecode[i] == 0x04) { // DIV
                
                // Check if this leads to a return value
                for j in i..std::cmp::min(i+15, bytecode.len()) {
                    if bytecode[j] == 0xF3 { // RETURN
                        has_fee_modification = true;
                        break;
                    }
                }
            }

            if has_external_call && has_fee_modification {
                return true;
            }
        }

        false
    }

    /// Check if contract implements Uniswap V4 hook interface
    fn is_uniswap_v4_hook(&self) -> bool {
        let bytecode = &self.bytecode;
        
        let hook_selectors = [
            [0x6d, 0x9f, 0x6d, 0x7d], // beforeInitialize
            [0x5c, 0x6f, 0x0b, 0x9e], // afterInitialize
            [0x4a, 0x4f, 0xbe, 0xec], // beforeModifyPosition
            [0x8c, 0x5b, 0x83, 0x85], // afterModifyPosition
            [0x5c, 0x0d, 0x5e, 0x53], // beforeSwap
            [0xf5, 0xe7, 0xb2, 0x10], // afterSwap
            [0x47, 0xa7, 0xd1, 0x07], // beforeDonate
            [0xc8, 0xe7, 0xa3, 0x3f], // afterDonate
        ];
        
        let mut found_hooks = 0;
        for selector in &hook_selectors {
            if bytecode.windows(4).take(500).any(|w| w == selector) {
                found_hooks += 1;
            }
        }
        
        found_hooks >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_before_swap_fee_manipulation() {
        // Simulated Uniswap V4 hook with beforeSwap fee manipulation
        let bytecode = vec![
            // beforeSwap selector
            0x1c, 0xb7, 0xb9, 0xf7,
            // Load swap parameters
            0x60, 0x04, // PUSH1 4
            0x35, // CALLDATALOAD
            // Manipulate fee (multiply by 2)
            0x60, 0x02, // PUSH1 2
            0x02, // MUL
            // Return modified fee
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3, // RETURN
        ];

        let detector = UniswapV4DynamicFeeHookManipulationDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect fee manipulation in beforeSwap");
        assert!(findings.iter().any(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_unbounded_fee_manipulation() {
        // Fee manipulation without bounds checking
        let bytecode = vec![
            0x60, 0x64, // PUSH1 100 (fee)
            0x60, 0x0A, // PUSH1 10
            0x02, // MUL (multiply without checking result)
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3, // RETURN (no bounds validation)
        ];

        let detector = UniswapV4DynamicFeeHookManipulationDetector::new(bytecode);
        let findings = detector.detect();

        assert!(!findings.is_empty(), "Should detect unbounded fee manipulation");
    }

    #[test]
    fn test_safe_fee_with_bounds() {
        // Safe fee manipulation with bounds checking
        let bytecode = vec![
            0x60, 0x64, // PUSH1 100
            0x60, 0x0A, // PUSH1 10
            0x02, // MUL
            // Bounds check
            0x61, 0x03, 0xE8, // PUSH2 1000 (max fee)
            0x10, // LT (check if result < max)
            0x60, 0x20, // PUSH1 32
            0x57, // JUMPI (revert if too high)
            0xFD, // REVERT
            0x5B, // JUMPDEST
            0xF3, // RETURN
        ];

        let detector = UniswapV4DynamicFeeHookManipulationDetector::new(bytecode);
        let findings = detector.detect();

        assert!(findings.is_empty() || findings.iter().all(|f| f.severity != "CRITICAL"));
    }
}
