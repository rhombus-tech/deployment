use crate::bytecode::opcodes::*;

pub struct UnicodeHomoglyphAttackDetector {
    bytecode: Vec<u8>,
}

impl UnicodeHomoglyphAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_string_operations()
            && (self.has_unicode_comparison() || self.has_homoglyph_vulnerability())
    }

    fn has_string_operations(&self) -> bool {
        // CALLDATALOAD or memory operations
        self.bytecode.iter()
            .any(|&op| op == CALLDATALOAD || op == MLOAD || op == MSTORE)
    }

    fn has_unicode_comparison(&self) -> bool {
        // String comparison without normalization
        self.has_byte_comparison() && !self.has_normalization()
    }

    fn has_byte_comparison(&self) -> bool {
        // BYTE operations with EQ (byte-level comparison)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == BYTE {
                for j in i+1..i.min(self.bytecode.len()).min(i+4) {
                    if self.bytecode[j] == EQ {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_normalization(&self) -> bool {
        // Unicode normalization would require external call
        let mut has_byte_ops = false;
        let mut has_complex_processing = false;

        for &opcode in &self.bytecode {
            if opcode == BYTE { has_byte_ops = true; }
            // Complex processing indicated by many operations
            if matches!(opcode, AND | OR | XOR) && has_byte_ops {
                has_complex_processing = true;
            }
        }

        // If processing strings and has complex operations, might have normalization
        has_byte_ops && has_complex_processing && self.has_multiple_byte_operations()
    }

    fn has_multiple_byte_operations(&self) -> bool {
        let byte_count = self.bytecode.iter()
            .filter(|&&op| op == BYTE)
            .count();
        
        byte_count >= 5
    }

    fn has_homoglyph_vulnerability(&self) -> bool {
        // Simple string matching without proper validation
        self.has_simple_string_check() && !self.has_whitelist_validation()
    }

    fn has_simple_string_check(&self) -> bool {
        // KECCAK256 for string hashing (common pattern)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == CALLDATALOAD || self.bytecode[i] == MLOAD {
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == KECCAK256 {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_whitelist_validation(&self) -> bool {
        // Multiple EQ checks suggesting whitelist
        let eq_count = self.bytecode.iter()
            .filter(|&&op| op == EQ)
            .count();
        
        eq_count >= 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homoglyph_vulnerability() {
        let bytecode = vec![
            CALLDATALOAD,           // Load string
            BYTE, EQ,               // Simple byte comparison
            KECCAK256,              // Hash without normalization
        ];
        let detector = UnicodeHomoglyphAttackDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_string_handling() {
        let bytecode = vec![
            CALLDATALOAD,
            BYTE, AND, OR, XOR,     // Complex processing
            BYTE, BYTE, BYTE, BYTE, BYTE, // Multiple byte ops (normalization)
            EQ, EQ, EQ, EQ, EQ,     // Whitelist validation
        ];
        let detector = UnicodeHomoglyphAttackDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
