use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct RedstoneModularOracleSignatureBypassDetector {
    bytecode: Vec<u8>,
}

impl RedstoneModularOracleSignatureBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_signature_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "RedStone oracle signatures can be bypassed allowing injection of malicious price data.".to_string(),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_signer_threshold_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Multi-signature threshold can be manipulated to reduce security requirements.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_signature_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (oracle data)
                let mut has_sig_verify = false;
                let mut has_data_use = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ECRECOVER precompile address
                        has_sig_verify = true;
                    }
                    if bytecode[j] == 0x55 && !has_sig_verify { // SSTORE without verification
                        has_data_use = true;
                    }
                }

                if has_data_use && !has_sig_verify {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_signer_threshold_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (threshold)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x10 { // LT (compare signatures)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x57 { // JUMPI (bypass with low threshold)
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
