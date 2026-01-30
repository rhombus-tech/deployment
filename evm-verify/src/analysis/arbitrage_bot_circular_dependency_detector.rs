use crate::bytecode::opcodes::*;

pub struct ArbitrageBotCircularDependencyDetector {
    bytecode: Vec<u8>,
}

impl ArbitrageBotCircularDependencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_circular_call_pattern()
            && self.has_price_dependency()
            && self.has_profit_extraction()
    }

    fn has_circular_call_pattern(&self) -> bool {
        // Look for multiple sequential CALLs indicating circular trading
        let mut call_positions = Vec::new();
        
        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == CALL {
                call_positions.push(i);
            }
        }

        // Circular arbitrage typically requires 3+ calls
        call_positions.len() >= 3
    }

    fn has_price_dependency(&self) -> bool {
        // Look for RETURNDATASIZE/RETURNDATACOPY after CALLs (reading prices)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == CALL {
                // Check for return data processing
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == RETURNDATASIZE || self.bytecode[j] == RETURNDATACOPY {
                        // Followed by arithmetic (price calculation)
                        if self.has_arithmetic_after(j) {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_profit_extraction(&self) -> bool {
        // Look for balance comparison before and after circular calls
        let mut balance_checks = 0;
        
        for &opcode in &self.bytecode {
            if opcode == BALANCE || opcode == SELFBALANCE {
                balance_checks += 1;
            }
        }

        // At least 2 balance checks (before and after)
        balance_checks >= 2
    }

    fn has_arithmetic_after(&self, pos: usize) -> bool {
        for i in pos+1..pos.min(self.bytecode.len()).min(pos+10) {
            if self.is_arithmetic_op(self.bytecode[i]) {
                return true;
            }
        }
        false
    }

    fn is_arithmetic_op(&self, opcode: u8) -> bool {
        matches!(opcode, ADD | MUL | SUB | DIV | SDIV | MOD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_arbitrage_detection() {
        let bytecode = vec![
            SELFBALANCE,        // Check initial balance
            CALL,               // DEX 1
            RETURNDATACOPY,     // Get amount
            MUL,                // Calculate
            CALL,               // DEX 2
            RETURNDATACOPY,     // Get amount
            DIV,                // Calculate
            CALL,               // DEX 3
            RETURNDATACOPY,     // Get amount
            BALANCE,            // Check final balance
            SUB,                // Calculate profit
        ];
        let detector = ArbitrageBotCircularDependencyDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_simple_trade() {
        let bytecode = vec![CALL, RETURNDATACOPY];
        let detector = ArbitrageBotCircularDependencyDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
