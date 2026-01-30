use crate::bytecode::opcodes::*;

pub struct WalletDrainerPatternDetector {
    bytecode: Vec<u8>,
}

impl WalletDrainerPatternDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_drainer_pattern()
            && self.has_multiple_token_extraction()
            && !self.has_legitimate_withdrawal_pattern()
    }

    fn has_drainer_pattern(&self) -> bool {
        // Sequential balance checks followed by transfers
        self.has_balance_enumeration() && self.has_sweeping_pattern()
    }

    fn has_balance_enumeration(&self) -> bool {
        // Multiple balanceOf or BALANCE calls
        let balance_count = self.count_balance_checks();
        balance_count >= 3
    }

    fn count_balance_checks(&self) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < self.bytecode.len() {
            // BALANCE opcode
            if self.bytecode[i] == BALANCE {
                count += 1;
            }
            // balanceOf selector (0x70a08231)
            if i + 4 < self.bytecode.len() && self.bytecode[i] == PUSH4 {
                if self.bytecode[i+1] == 0x70 && self.bytecode[i+2] == 0xa0 {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn has_sweeping_pattern(&self) -> bool {
        // Balance check followed by transfer of full amount
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.is_balance_check(i) {
                // Look for transfer using the balance value
                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.is_transfer_call(j) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_balance_check(&self, pos: usize) -> bool {
        if self.bytecode[pos] == BALANCE {
            return true;
        }
        // balanceOf selector
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == PUSH4 {
            return self.bytecode[pos+1] == 0x70 && self.bytecode[pos+2] == 0xa0;
        }
        false
    }

    fn is_transfer_call(&self, pos: usize) -> bool {
        if pos + 4 >= self.bytecode.len() || self.bytecode[pos] != PUSH4 {
            return false;
        }
        // transfer selector (0xa9059cbb) or transferFrom (0x23b872dd)
        (self.bytecode[pos+1] == 0xa9 && self.bytecode[pos+2] == 0x05)
            || (self.bytecode[pos+1] == 0x23 && self.bytecode[pos+2] == 0xb8)
    }

    fn has_multiple_token_extraction(&self) -> bool {
        // Loop through multiple tokens
        self.has_loop_with_transfers() || self.has_multiple_transfer_calls()
    }

    fn has_loop_with_transfers(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == JUMPDEST {
                let mut has_transfer = false;
                let mut has_jump_back = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.is_transfer_call(j) {
                        has_transfer = true;
                    }
                    if self.bytecode[j] == JUMP || self.bytecode[j] == JUMPI {
                        has_jump_back = true;
                    }
                }

                if has_transfer && has_jump_back {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_multiple_transfer_calls(&self) -> bool {
        self.bytecode.windows(4)
            .filter(|w| w[0] == PUSH4 && ((w[1] == 0xa9 && w[2] == 0x05) || (w[1] == 0x23 && w[2] == 0xb8)))
            .count() >= 5
    }

    fn has_legitimate_withdrawal_pattern(&self) -> bool {
        // Legitimate contracts have access control
        self.has_owner_check() || self.has_withdrawal_limit()
    }

    fn has_owner_check(&self) -> bool {
        // CALLER comparison before transfers
        let mut has_caller = false;
        let mut has_comparison = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == CALLER {
                has_caller = true;
            }
            if has_caller && (opcode == EQ || opcode == ISZERO) {
                has_comparison = true;
            }
        }

        has_caller && has_comparison
    }

    fn has_withdrawal_limit(&self) -> bool {
        // Amount checks before transfers
        self.bytecode.windows(3).any(|w| {
            (w[0] == LT || w[0] == GT) && (w[1] == ISZERO || w[2] == ISZERO)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_drainer_detection() {
        let bytecode = vec![
            JUMPDEST,                          // Loop start
            PUSH4, 0x70, 0xa0, 0x82, 0x31,    // balanceOf
            STATICCALL,
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,    // transfer
            CALL,
            PUSH1, 0x00,
            JUMPI,                             // Loop back
        ];
        let detector = WalletDrainerPatternDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_legitimate_withdrawal() {
        let bytecode = vec![
            CALLER, EQ,                        // Owner check
            PUSH4, 0xa9, 0x05, 0x9c, 0xbb,    // transfer
            CALL,
        ];
        let detector = WalletDrainerPatternDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
