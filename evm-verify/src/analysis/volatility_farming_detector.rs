use crate::bytecode::opcodes::*;

pub struct VolatilityFarmingDetector {
    bytecode: Vec<u8>,
}

impl VolatilityFarmingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_volatility_farming_pattern()
            && self.has_price_manipulation()
            && self.has_option_settlement()
    }

    fn has_volatility_farming_pattern(&self) -> bool {
        // Repeated buy/sell to create volatility
        self.has_rapid_trading() && self.has_price_checks()
    }

    fn has_rapid_trading(&self) -> bool {
        // Multiple swap operations in sequence
        let mut swap_count = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // swap selectors
                if self.is_swap_selector(&self.bytecode[i+1..i+4]) {
                    swap_count += 1;
                }
            }
            i += 1;
        }

        swap_count >= 4
    }

    fn is_swap_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        // Common swap selectors: 0x022c0d9f, 0x128acb08, 0x38ed1739
        bytes[0] == 0x02 || bytes[0] == 0x12 || bytes[0] == 0x38
    }

    fn has_price_checks(&self) -> bool {
        // Checking price/reserves between trades
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.is_swap_selector_at(i) {
                // Look for balance/price check after swap
                for j in i+5..i.min(self.bytecode.len()).min(i+18) {
                    if self.bytecode[j] == BALANCE || self.bytecode[j] == STATICCALL {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_swap_selector_at(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_swap_selector(&self.bytecode[pos+1..pos+4])
    }

    fn has_price_manipulation(&self) -> bool {
        // Large trades in opposite directions
        self.has_bidirectional_trades() && self.has_large_amounts()
    }

    fn has_bidirectional_trades(&self) -> bool {
        // Swaps in both directions (A->B then B->A)
        let swap_count = self.bytecode.windows(4)
            .filter(|w| w[0] == PUSH4 && self.is_swap_selector(&w[1..]))
            .count();
        
        swap_count >= 2
    }

    fn has_large_amounts(&self) -> bool {
        // PUSH operations with large values
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if matches!(opcode, PUSH16 | PUSH20 | PUSH32) {
                return true;
            }
        }
        false
    }

    fn has_option_settlement(&self) -> bool {
        // Settlement/claim after volatility farming
        self.has_claim_pattern() || self.has_settlement_pattern()
    }

    fn has_claim_pattern(&self) -> bool {
        // claim() function calls
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // claim selector: 0x4e71d92d
                if self.bytecode[i+1] == 0x4e && self.bytecode[i+2] == 0x71 {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_settlement_pattern(&self) -> bool {
        // settle() or execute() selectors
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // settle: 0x2e95b6c8, execute: 0x61461954
                if (self.bytecode[i+1] == 0x2e && self.bytecode[i+2] == 0x95)
                    || (self.bytecode[i+1] == 0x61 && self.bytecode[i+2] == 0x46) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volatility_farming() {
        let bytecode = vec![
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,     // swap A->B
            PUSH32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Large amount
            CALL,
            BALANCE,                            // Check price
            PUSH4, 0x12, 0x8a, 0xcb, 0x08,     // swap B->A
            CALL,
            PUSH4, 0x38, 0xed, 0x17, 0x39,     // swap A->B again
            CALL,
            PUSH4, 0x4e, 0x71, 0xd9, 0x2d,     // claim rewards
            CALL,
        ];
        let detector = VolatilityFarmingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_trading() {
        let bytecode = vec![
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,
            CALL,
        ];
        let detector = VolatilityFarmingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
