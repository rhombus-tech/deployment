use crate::bytecode::opcodes::*;

pub struct YieldAggregatorStrategyManipulationDetector {
    bytecode: Vec<u8>,
}

impl YieldAggregatorStrategyManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_yield_strategy_pattern()
            && (self.has_share_price_manipulation() || self.has_withdrawal_exploitation())
    }

    fn has_yield_strategy_pattern(&self) -> bool {
        // Yield aggregator: deposit/withdraw + share calculations
        self.has_deposit_withdraw() && self.has_share_calculation()
    }

    fn has_deposit_withdraw(&self) -> bool {
        // deposit/withdraw function selectors
        let mut has_deposit = false;
        let mut has_withdraw = false;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+4];
                // deposit: 0xb6b55f25, withdraw: 0x2e1a7d4d
                if selector[0] == 0xb6 && selector[1] == 0xb5 {
                    has_deposit = true;
                }
                if selector[0] == 0x2e && selector[1] == 0x1a {
                    has_withdraw = true;
                }
            }
            i += 1;
        }

        has_deposit && has_withdraw
    }

    fn has_share_calculation(&self) -> bool {
        // Division operations for share price calculation
        let div_count = self.bytecode.iter()
            .filter(|&&op| op == DIV || op == SDIV)
            .count();
        
        div_count >= 2
    }

    fn has_share_price_manipulation(&self) -> bool {
        // Share price depends on total assets which can be manipulated
        self.has_donation_pattern() && self.has_share_minting()
    }

    fn has_donation_pattern(&self) -> bool {
        // Direct transfer affecting totalAssets without minting shares
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            // Balance check without corresponding share update
            if self.bytecode[i] == BALANCE || self.bytecode[i] == SELFBALANCE {
                let mut has_div_after = false;
                let mut has_sstore_after = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.bytecode[j] == DIV {
                        has_div_after = true;
                    }
                    if self.bytecode[j] == SSTORE {
                        has_sstore_after = true;
                    }
                }

                // Balance used in calculation but no storage update = donation attack vector
                if has_div_after && !has_sstore_after {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_share_minting(&self) -> bool {
        // Mint shares based on manipulated share price
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == DIV {
                // Division (calculating shares) followed by state change
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == SSTORE {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_withdrawal_exploitation(&self) -> bool {
        // Withdraw more than fair share through manipulation
        self.has_withdrawal_calculation() && self.has_rounding_exploitation()
    }

    fn has_withdrawal_calculation(&self) -> bool {
        // MUL then DIV pattern (calculating withdrawal amount)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == MUL {
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if self.bytecode[j] == DIV {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_rounding_exploitation(&self) -> bool {
        // Multiple division operations creating rounding opportunities
        let mut div_positions = Vec::new();
        
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == DIV || opcode == SDIV {
                div_positions.push(i);
            }
        }

        // Multiple divisions close together = rounding exploitation risk
        if div_positions.len() >= 2 {
            for i in 0..div_positions.len()-1 {
                if div_positions[i+1] - div_positions[i] < 20 {
                    return true;
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
    fn test_yield_strategy_manipulation() {
        let bytecode = vec![
            PUSH4, 0xb6, 0xb5, 0xf2, 0x5,      // deposit
            BALANCE,                            // Check balance (totalAssets)
            DIV,                                // Calculate share price
            MUL, DIV,                           // Calculate shares (rounding)
            PUSH4, 0x2e, 0x1a, 0x7d, 0x4d,     // withdraw
            MUL, DIV,                           // Calculate withdrawal
        ];
        let detector = YieldAggregatorStrategyManipulationDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_yield_aggregator() {
        let bytecode = vec![
            PUSH4, 0xb6, 0xb5, 0xf2, 0x5,      // deposit
            SLOAD,                              // Load totalAssets from storage
            DIV,                                // Calculate share price
            SSTORE,                             // Update shares
        ];
        let detector = YieldAggregatorStrategyManipulationDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
