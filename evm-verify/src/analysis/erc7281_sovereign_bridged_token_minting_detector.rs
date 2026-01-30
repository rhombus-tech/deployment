use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Erc7281SovereignBridgedTokenMintingDetector {
    bytecode: Vec<u8>,
}

impl Erc7281SovereignBridgedTokenMintingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_unauthorized_minting() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Bridged tokens can be minted without proper cross-chain verification, allowing unauthorized token creation.".to_string(),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_bridge_message_replay() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Cross-chain mint/burn messages can be replayed causing double-spending.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_unauthorized_minting(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (bridge message)
                let mut has_signature_check = false;
                let mut has_mint = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0xFA { // STATICCALL (verify signature)
                        has_signature_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_signature_check { // SSTORE (mint without check)
                        has_mint = true;
                    }
                }

                if has_mint && !has_signature_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_bridge_message_replay(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x20 { // SHA3 (message hash)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE (process message)
                        let mut has_nonce_check = false;
                        for k in i..j {
                            if bytecode[k] == 0x54 { // SLOAD (check nonce)
                                has_nonce_check = true;
                                break;
                            }
                        }
                        if !has_nonce_check {
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }
}
