use crate::bytecode::opcodes::*;

pub struct ImpermanentLossAmplificationDetector {
    bytecode: Vec<u8>,
}

impl ImpermanentLossAmplificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_liquidity_provision()
            && self.has_price_manipulation_vulnerability()
            && self.has_withdrawal_exploitation()
    }

    fn has_liquidity_provision(&self) -> bool {
        // addLiquidity or mint functions
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // addLiquidity: 0xe8e33700, mint: 0x40c10f19
                if (self.bytecode[i+1] == 0xe8 && self.bytecode[i+2] == 0xe3)
                    || (self.bytecode[i+1] == 0x40 && self.bytecode[i+2] == 0xc1) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_price_manipulation_vulnerability(&self) -> bool {
        // Large swaps affecting price before withdrawal
        self.has_large_swap_before_withdrawal()
    }

    fn has_large_swap_before_withdrawal(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            // Large amount swap
            if self.is_large_push(i) {
                // Followed by swap
                for j in i+1..i.min(self.bytecode.len()).min(i+20) {
                    if self.is_swap_selector_at(j) {
                        // Followed by withdrawal
                        for k in j+5..j.min(self.bytecode.len()).min(j+20) {
                            if self.is_remove_liquidity_at(k) {
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

    fn is_large_push(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        matches!(self.bytecode[pos], PUSH16 | PUSH20 | PUSH32)
    }

    fn is_swap_selector_at(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_swap_selector(&self.bytecode[pos+1..])
    }

    fn is_swap_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        // swap selectors
        bytes[0] == 0x02 || bytes[0] == 0x12 || bytes[0] == 0x38
    }

    fn is_remove_liquidity_at(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_remove_liquidity_selector(&self.bytecode[pos+1..])
    }

    fn is_remove_liquidity_selector(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 2 { return false; }
        // removeLiquidity: 0xbaa2abde, burn: 0x42966c68
        (bytes[0] == 0xba && bytes[1] == 0xa2) || (bytes[0] == 0x42 && bytes[1] == 0x96)
    }

    fn has_withdrawal_exploitation(&self) -> bool {
        // Withdraw at manipulated price
        self.has_remove_liquidity() && !self.has_slippage_protection()
    }

    fn has_remove_liquidity(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                if self.is_remove_liquidity_selector(&self.bytecode[i+1..]) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_slippage_protection(&self) -> bool {
        // minAmount parameters or checks
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.is_remove_liquidity_selector_at(i) {
                // Check for amount validation after
                for j in i+5..i.min(self.bytecode.len()).min(i+12) {
                    if matches!(self.bytecode[j], LT | GT) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_remove_liquidity_selector_at(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.is_remove_liquidity_selector(&self.bytecode[pos+1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impermanent_loss_amplification() {
        let bytecode = vec![
            PUSH4, 0xe8, 0xe3, 0x37, 0x00,     // addLiquidity
            CALL,
            PUSH32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Large swap
            PUSH4, 0x02, 0x2c, 0x0d, 0x9f,     // swap
            CALL,
            PUSH4, 0xba, 0xa2, 0xab, 0xde,     // removeLiquidity (no slippage check)
            CALL,
        ];
        let detector = ImpermanentLossAmplificationDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_liquidity() {
        let bytecode = vec![
            PUSH4, 0xba, 0xa2, 0xab, 0xde,     // removeLiquidity
            LT,                                 // Slippage check
            CALL,
        ];
        let detector = ImpermanentLossAmplificationDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
