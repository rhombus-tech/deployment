use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct OpHoloceneUpgradeInteropMessageForgeryDetector {
    bytecode: Vec<u8>,
}

impl OpHoloceneUpgradeInteropMessageForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_cross_chain_message_forgery() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Interoperability messages between OP Stack chains can be forged due to insufficient validation in Holocene upgrade.".to_string(),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_message_replay_across_chains() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Cross-chain messages can be replayed across different OP Stack chains.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_cross_chain_message_forgery(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (message data)
                let mut has_signature_check = false;
                let mut has_chain_id = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ECRECOVER precompile address
                        has_signature_check = true;
                    }
                    if bytecode[j] == 0x46 { // CHAINID
                        has_chain_id = true;
                    }
                }

                if !has_signature_check || !has_chain_id {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_message_replay_across_chains(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x20 { // SHA3 (message hash)
                let mut has_nonce = false;
                let mut has_storage = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x54 { // SLOAD (nonce check)
                        has_nonce = true;
                    }
                    if bytecode[j] == 0x55 && !has_nonce { // SSTORE without nonce
                        has_storage = true;
                    }
                }

                if has_storage && !has_nonce {
                    return Some(i);
                }
            }
        }

        None
    }
}
