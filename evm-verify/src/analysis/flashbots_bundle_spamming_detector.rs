use crate::bytecode::opcodes::*;

pub struct FlashbotsBundleSpammingDetector {
    bytecode: Vec<u8>,
}

impl FlashbotsBundleSpammingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_bundle_construction()
            && self.has_spam_indicators()
            && self.has_low_value_transactions()
    }

    fn has_bundle_construction(&self) -> bool {
        // Look for multiple transaction submissions in sequence
        let mut i = 0;
        let mut create_count = 0;

        while i < self.bytecode.len() {
            // CREATE/CREATE2 for deploying temporary contracts
            if self.bytecode[i] == CREATE || self.bytecode[i] == CREATE2 {
                create_count += 1;
            }
            i += 1;
        }

        create_count >= 2 // Multiple creates suggest bundle construction
    }

    fn has_spam_indicators(&self) -> bool {
        // Look for repetitive patterns with minimal variation
        self.has_loop_with_external_calls() || self.has_repetitive_selectors()
    }

    fn has_loop_with_external_calls(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            // JUMPDEST (loop start)
            if self.bytecode[i] == JUMPDEST {
                let mut has_call = false;
                let mut has_jump_back = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.bytecode[j] == CALL {
                        has_call = true;
                    }
                    if self.bytecode[j] == JUMP || self.bytecode[j] == JUMPI {
                        has_jump_back = true;
                    }
                }

                if has_call && has_jump_back {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_repetitive_selectors(&self) -> bool {
        // Count PUSH4 (function selectors)
        let selector_count = self.bytecode.iter()
            .filter(|&&op| op == PUSH4)
            .count();

        // Many selectors with similar patterns = spam
        selector_count >= 5
    }

    fn has_low_value_transactions(&self) -> bool {
        // Look for minimal ETH value transfers
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == PUSH1 {
                // Small value (< 0xFF = 1 byte)
                if i + 1 < self.bytecode.len() {
                    let value = self.bytecode[i + 1];
                    if value <= 0x10 { // Very small value
                        // Followed by CALL
                        for j in i+2..i.min(self.bytecode.len()).min(i+8) {
                            if self.bytecode[j] == CALL {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_spamming_detection() {
        let bytecode = vec![
            CREATE,             // Deploy contract 1
            CREATE2,            // Deploy contract 2
            JUMPDEST,           // Loop start
            PUSH4, 0x01, 0x02, 0x03, 0x04, // Selector 1
            PUSH1, 0x01,        // Minimal value
            CALL,               // Spam tx 1
            PUSH4, 0x05, 0x06, 0x07, 0x08, // Selector 2
            PUSH1, 0x01,        // Minimal value
            CALL,               // Spam tx 2
            PUSH1, 0x00,
            JUMPI,              // Loop back
        ];
        let detector = FlashbotsBundleSpammingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_normal_bundle() {
        let bytecode = vec![CREATE, CALL];
        let detector = FlashbotsBundleSpammingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
