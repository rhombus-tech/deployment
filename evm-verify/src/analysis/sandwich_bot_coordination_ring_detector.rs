use crate::bytecode::opcodes::*;

pub struct SandwichBotCoordinationRingDetector {
    bytecode: Vec<u8>,
}

impl SandwichBotCoordinationRingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_coordination_signaling()
            && self.has_profit_distribution()
            && self.has_multi_party_pattern()
    }

    fn has_coordination_signaling(&self) -> bool {
        // Look for event emissions or storage writes used for coordination
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            // LOG operations for off-chain coordination
            if self.is_log_opcode(self.bytecode[i]) {
                // Check if followed by CALL (profit distribution)
                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.bytecode[j] == CALL || self.bytecode[j] == DELEGATECALL {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_profit_distribution(&self) -> bool {
        // Look for multiple sequential CALLs with value transfers
        let mut i = 0;
        let mut call_count = 0;
        
        while i < self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == CALL {
                // Check for CALLVALUE or value in stack before CALL
                if self.has_value_before(i) {
                    call_count += 1;
                    if call_count >= 3 {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_multi_party_pattern(&self) -> bool {
        // Look for address loading patterns indicating multiple participants
        let mut address_loads = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(5) {
            // SLOAD followed by address masking
            if self.bytecode[i] == SLOAD {
                if i + 3 < self.bytecode.len() {
                    // Check for address extraction (AND with address mask)
                    if self.bytecode[i+1] == PUSH20 || self.bytecode[i+2] == AND {
                        address_loads += 1;
                    }
                }
            }
            i += 1;
        }

        address_loads >= 3 // Multiple addresses = coordination ring
    }

    fn has_value_before(&self, call_pos: usize) -> bool {
        if call_pos < 5 { return false; }
        
        for i in (call_pos.saturating_sub(10))..call_pos {
            if self.bytecode[i] == CALLVALUE {
                return true;
            }
            if self.is_push_opcode(self.bytecode[i]) && i + 2 < call_pos {
                // Large value push
                let push_size = (self.bytecode[i] - PUSH1 + 1) as usize;
                if push_size >= 8 { // Large value suggesting ETH transfer
                    return true;
                }
            }
        }
        false
    }

    fn is_log_opcode(&self, opcode: u8) -> bool {
        matches!(opcode, LOG0 | LOG1 | LOG2 | LOG3 | LOG4)
    }

    fn is_push_opcode(&self, opcode: u8) -> bool {
        (PUSH1..=PUSH32).contains(&opcode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordination_ring_detection() {
        let bytecode = vec![
            LOG1,           // Coordination signal
            SLOAD, AND,     // Load address 1
            CALL,           // Transfer to member 1
            SLOAD, AND,     // Load address 2
            CALL,           // Transfer to member 2
            SLOAD, AND,     // Load address 3
            CALL,           // Transfer to member 3
        ];
        let detector = SandwichBotCoordinationRingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_single_bot_no_coordination() {
        let bytecode = vec![PUSH1, 0x01, CALL];
        let detector = SandwichBotCoordinationRingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
