use crate::bytecode::opcodes::*;

pub struct PriceImpactManipulationDetector {
    bytecode: Vec<u8>,
}

impl PriceImpactManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_large_trade_pattern()
            && self.has_price_impact_exploitation()
            && !self.has_price_impact_limits()
    }

    fn has_large_trade_pattern(&self) -> bool {
        // Large value operations
        self.has_large_push_values() && self.has_swap_operations()
    }

    fn has_large_push_values(&self) -> bool {
        // PUSH16+ operations indicating large amounts
        self.bytecode.iter()
            .any(|&op| matches!(op, PUSH16 | PUSH20 | PUSH32))
    }

    fn has_swap_operations(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                if self.is_swap_selector(&self.bytecode[i+1..]) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn is_swap_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        bytes[0] == 0x02 || bytes[0] == 0x12 || bytes[0] == 0x38
    }

    fn has_price_impact_exploitation(&self) -> bool {
        // Trade -> Check price impact -> Additional trade
        self.has_sequential_trades_with_checks()
    }

    fn has_sequential_trades_with_checks(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            if self.is_swap_at(i) {
                // Look for balance/reserve check
                for j in i+5..i.min(self.bytecode.len()).min(i+20) {
                    if self.bytecode[j] == BALANCE || self.bytecode[j] == STATICCALL {
                        // Followed by another swap
                        for k in j+1..j.min(self.bytecode.len()).min(j+20) {
                            if self.is_swap_at(k) {
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

    fn is_swap_at(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_swap_selector(&self.bytecode[pos+1..])
    }

    fn has_price_impact_limits(&self) -> bool {
        // Checks limiting price impact
        self.has_max_price_impact_check() || self.has_reserve_ratio_check()
    }

    fn has_max_price_impact_check(&self) -> bool {
        // Price comparison before trade
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            // Price calculation (MUL/DIV)
            if self.bytecode[i] == MUL || self.bytecode[i] == DIV {
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    // Comparison
                    if matches!(self.bytecode[j], LT | GT) {
                        // Followed by REVERT if exceeded
                        for k in j+1..j.min(self.bytecode.len()).min(j+8) {
                            if self.bytecode[k] == REVERT {
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

    fn has_reserve_ratio_check(&self) -> bool {
        // Reserve balance checks preventing large impact
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == BALANCE {
                // Comparison to limit trade size relative to reserves
                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if matches!(self.bytecode[j], LT | GT) {
                        // Followed by conditional REVERT
                        if self.has_revert_after(j) {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_revert_after(&self, pos: usize) -> bool {
        for i in pos+1..pos.min(self.bytecode.len()).min(pos+10) {
            if self.bytecode[i] == REVERT {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_impact_manipulation() {
        let bytecode = vec![
            PUSH32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Large amount
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,     // swap
            CALL,
            BALANCE,                            // Check impact
            PUSH4, 0x12, 0x8a, 0xcb, 0x08,     // Another swap
            CALL,
        ];
        let detector = PriceImpactManipulationDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_trading() {
        let bytecode = vec![
            BALANCE,                            // Check reserves
            LT,                                 // Compare trade size
            ISZERO, PUSH1, 0x08, JUMPI,
            REVERT,                             // Revert if too large
            JUMPDEST,
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,
            CALL,
        ];
        let detector = PriceImpactManipulationDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
