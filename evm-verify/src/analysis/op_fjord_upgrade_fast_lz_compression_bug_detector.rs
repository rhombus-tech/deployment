use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct OpFjordUpgradeFastLzCompressionBugDetector {
    bytecode: Vec<u8>,
}

impl OpFjordUpgradeFastLzCompressionBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_fast_lz_decompression_bomb() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Maliciously compressed data can trigger decompression bombs causing DoS or state corruption in Fjord upgrade.".to_string(),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_compression_ratio_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Compression ratios can be manipulated to bypass gas accounting or cause unexpected state expansion.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_fast_lz_decompression_bomb(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (compressed data)
                let mut has_length_check = false;
                let mut has_decompress = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x02 { // MUL (expansion ratio)
                        has_length_check = true;
                    }
                    if bytecode[j] == 0x39 && has_length_check { // CODECOPY (decompress)
                        has_decompress = true;
                    }
                }

                if has_length_check && has_decompress {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_compression_ratio_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x36 { // CALLDATASIZE
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (compression ratio)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x5A { // GAS (gas calculation)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
