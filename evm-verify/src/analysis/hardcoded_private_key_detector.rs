pub struct HardcodedPrivateKeyDetector {
    bytecode: Vec<u8>,
}

impl HardcodedPrivateKeyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_private_key_pattern() {
            findings.push("Hardcoded key: Private key pattern detected in bytecode".to_string());
        }

        if self.has_mnemonic_phrase() {
            findings.push("Hardcoded key: Mnemonic phrase found in contract".to_string());
        }

        if self.has_signing_key_constant() {
            findings.push("Hardcoded key: Signing key constant detected".to_string());
        }

        findings
    }

    fn has_private_key_pattern(&self) -> bool {
        // Check for 32-byte sequences that look like private keys (PUSH32 with high entropy)
        for i in 0..self.bytecode.len().saturating_sub(33) {
            if self.bytecode[i] == 0x7f { // PUSH32
                let key_bytes = &self.bytecode[i+1..i+33];
                
                // Check if it's not all zeros or all 0xff (common padding)
                let not_padding = key_bytes.iter().any(|&b| b != 0x00 && b != 0xff);
                
                // Check for high entropy (potential key material)
                if not_padding && self.has_high_entropy(key_bytes) {
                    // Check if it's used with signing operations nearby
                    if self.check_signing_context(i) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_mnemonic_phrase(&self) -> bool {
        // Check for BIP39 mnemonic words in bytecode
        let common_mnemonic_words = [
            b"abandon", b"ability", b"able", b"about", b"above",
            b"absent", b"absorb", b"abstract", b"absurd", b"abuse",
            b"access", b"accident", b"account", b"accuse", b"achieve",
        ];
        
        let mut word_count = 0;
        for word in &common_mnemonic_words {
            if self.bytecode.windows(word.len()).any(|w| w == *word) {
                word_count += 1;
                if word_count >= 3 { // Multiple mnemonic words found
                    return true;
                }
            }
        }
        false
    }

    fn has_signing_key_constant(&self) -> bool {
        // Check for ECDSA secp256k1 curve constants (could indicate embedded key ops)
        let secp256k1_order = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        ];
        
        // Check for the curve order constant
        if self.bytecode.windows(secp256k1_order.len()).any(|w| w == secp256k1_order.as_slice()) {
            return true;
        }
        
        // Check for hardcoded signatures (65 bytes: r + s + v)
        for i in 0..self.bytecode.len().saturating_sub(66) {
            if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x41 { // PUSH1 65
                return true; // Likely hardcoded signature
            }
        }
        
        false
    }
    
    fn has_high_entropy(&self, data: &[u8]) -> bool {
        // Simple entropy check: count unique bytes
        let mut seen = [false; 256];
        let mut unique_count = 0;
        
        for &byte in data {
            if !seen[byte as usize] {
                seen[byte as usize] = true;
                unique_count += 1;
            }
        }
        
        // High entropy if > 50% unique bytes
        unique_count > data.len() / 2
    }
    
    fn check_signing_context(&self, pos: usize) -> bool {
        // Check for ECRECOVER (0x01) or signing-related opcodes nearby
        let search_range = 20;
        let start = pos.saturating_sub(search_range);
        let end = (pos + search_range).min(self.bytecode.len());
        
        for i in start..end {
            // Check for STATICCALL/CALL to precompile 0x01 (ECRECOVER)
            if self.bytecode[i] == 0xfa || self.bytecode[i] == 0xf1 { // STATICCALL or CALL
                return true;
            }
        }
        false
    }
}
