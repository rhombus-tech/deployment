use crate::bytecode::opcodes::*;

pub struct RainbowKitConnectionSpoofingDetector {
    bytecode: Vec<u8>,
}

impl RainbowKitConnectionSpoofingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_connection_verification()
            && (self.has_weak_verification() || self.has_replay_vulnerability())
    }

    fn has_connection_verification(&self) -> bool {
        // Signature or proof verification
        self.has_signature_check() || self.has_message_verification()
    }

    fn has_signature_check(&self) -> bool {
        // ECRECOVER usage
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == PUSH1 && i + 1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 {
                    for j in i+2..i.min(self.bytecode.len()).min(i+8) {
                        if self.bytecode[j] == STATICCALL {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_message_verification(&self) -> bool {
        // KECCAK256 for message hashing
        self.bytecode.iter().any(|&op| op == KECCAK256)
    }

    fn has_weak_verification(&self) -> bool {
        // Missing chain ID or insufficient checks
        !self.has_chain_id_check() || self.has_insufficient_validation()
    }

    fn has_chain_id_check(&self) -> bool {
        // CHAINID opcode usage
        self.bytecode.iter().any(|&op| op == CHAINID)
    }

    fn has_insufficient_validation(&self) -> bool {
        // Signature verification without additional context
        let has_sig = self.has_signature_check();
        let has_nonce = self.has_nonce_check();
        let has_timestamp = self.has_timestamp_check();

        has_sig && !has_nonce && !has_timestamp
    }

    fn has_nonce_check(&self) -> bool {
        // Nonce storage operations
        let mut has_sload = false;
        let mut has_sstore = false;

        for &opcode in &self.bytecode {
            if opcode == SLOAD { has_sload = true; }
            if opcode == SSTORE { has_sstore = true; }
        }

        has_sload && has_sstore
    }

    fn has_timestamp_check(&self) -> bool {
        // TIMESTAMP with comparison
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == TIMESTAMP {
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if matches!(self.bytecode[j], LT | GT) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_replay_vulnerability(&self) -> bool {
        // Signature reuse possible
        self.has_signature_check() && !self.has_replay_protection()
    }

    fn has_replay_protection(&self) -> bool {
        // Nonce or message hash storage
        self.has_nonce_check() || self.has_message_hash_storage()
    }

    fn has_message_hash_storage(&self) -> bool {
        // KECCAK256 followed by SSTORE
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == KECCAK256 {
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == SSTORE {
                        return true;
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
    fn test_connection_spoofing() {
        let bytecode = vec![
            KECCAK256,              // Hash message
            PUSH1, 0x01,            // ECRECOVER
            STATICCALL,             // Verify signature (no nonce, no chain ID)
        ];
        let detector = RainbowKitConnectionSpoofingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_secure_connection() {
        let bytecode = vec![
            CHAINID,                // Include chain ID
            KECCAK256,
            PUSH1, 0x01, STATICCALL, // Verify signature
            SLOAD, ADD, SSTORE,     // Nonce tracking
        ];
        let detector = RainbowKitConnectionSpoofingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
