use crate::bytecode::opcodes::*;

pub struct GeneralizedFrontrunningBotDetector {
    bytecode: Vec<u8>,
}

impl GeneralizedFrontrunningBotDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_mempool_monitoring()
            && self.has_transaction_replication()
            && self.has_gas_price_manipulation()
    }

    fn has_mempool_monitoring(&self) -> bool {
        // Look for off-chain data reading patterns
        // EVENT logs used to signal off-chain bots
        let log_count = self.bytecode.iter()
            .filter(|&&op| matches!(op, LOG0 | LOG1 | LOG2 | LOG3 | LOG4))
            .count();

        log_count >= 2 // Multiple events = monitoring signals
    }

    fn has_transaction_replication(&self) -> bool {
        // Look for CALLDATACOPY (copying tx data) + CALL (replicating)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == CALLDATACOPY {
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == CALL || self.bytecode[j] == DELEGATECALL {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_gas_price_manipulation(&self) -> bool {
        // Look for GASPRICE checks with arithmetic manipulation
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == GASPRICE {
                // Check for arithmetic operations after
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.is_arithmetic_op(self.bytecode[j]) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_arithmetic_op(&self, opcode: u8) -> bool {
        matches!(opcode, ADD | MUL | SUB | DIV)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frontrunning_bot_detection() {
        let bytecode = vec![
            LOG1,               // Monitoring signal
            LOG2,               // Another signal
            CALLDATACOPY,       // Copy target tx
            GASPRICE,           // Check gas
            ADD,                // Increase gas price
            CALL,               // Execute frontrun
        ];
        let detector = GeneralizedFrontrunningBotDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_contract() {
        let bytecode = vec![PUSH1, 0x01, CALL];
        let detector = GeneralizedFrontrunningBotDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
