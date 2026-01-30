use crate::bytecode::opcodes::*;

pub struct LiquidationBotGriefingDetector {
    bytecode: Vec<u8>,
}

impl LiquidationBotGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_liquidation_pattern()
            && (self.has_griefing_revert() || self.has_frontrun_blocking())
    }

    fn has_liquidation_pattern(&self) -> bool {
        // Look for external call to liquidation function
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == CALL {
                // Check for liquidation-related function selectors nearby
                // Common: liquidate, seize, etc.
                if self.has_liquidation_selector_before(i) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_griefing_revert(&self) -> bool {
        // Look for intentional reverts after state checks
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            // Pattern: Check health factor -> Revert to block others
            if self.bytecode[i] == SLOAD {
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    // Conditional revert based on loaded value
                    if self.bytecode[j] == GT || self.bytecode[j] == LT {
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j+1] == ISZERO && self.bytecode[j+3] == REVERT {
                                return true;
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_frontrun_blocking(&self) -> bool {
        // Look for gas price checks to block competing bots
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == GASPRICE {
                // Check for comparison followed by revert
                for j in i+1..i.min(self.bytecode.len()).min(i+10) {
                    if (self.bytecode[j] == LT || self.bytecode[j] == GT) {
                        // Followed by conditional revert
                        if j + 3 < self.bytecode.len() && self.bytecode[j+2] == REVERT {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_liquidation_selector_before(&self, call_pos: usize) -> bool {
        if call_pos < 10 { return false; }

        for i in (call_pos.saturating_sub(10))..call_pos {
            if self.bytecode[i] == PUSH4 {
                // Check if next 4 bytes look like function selector
                if i + 4 < call_pos {
                    // Common liquidation selectors start with specific patterns
                    let selector_start = self.bytecode.get(i + 1);
                    if let Some(&first_byte) = selector_start {
                        // Many liquidation functions start with 0x96, 0xae, 0x5c
                        if first_byte == 0x96 || first_byte == 0xae || first_byte == 0x5c {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liquidation_griefing_detection() {
        let bytecode = vec![
            PUSH4, 0x96, 0x01, 0x02, 0x03, // Liquidation selector
            GASPRICE,                       // Check gas price
            PUSH1, 0x64,
            LT,                             // Compare
            PUSH1, 0x08,
            JUMPI,                          
            REVERT,                         // Block competitors
            JUMPDEST,
            CALL,                           // Execute liquidation
        ];
        let detector = LiquidationBotGriefingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_liquidation() {
        let bytecode = vec![
            PUSH4, 0x96, 0x01, 0x02, 0x03,
            CALL,
        ];
        let detector = LiquidationBotGriefingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
