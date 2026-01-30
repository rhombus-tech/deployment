use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Erc7683CrossChainIntentSettlementAtomicityDetector {
    bytecode: Vec<u8>,
}

impl Erc7683CrossChainIntentSettlementAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_non_atomic_settlement() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Cross-chain intent settlement lacks atomicity allowing partial fills or settlement failures to strand funds.".to_string(),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_filler_griefing() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Intent fillers can be griefed through strategic order cancellation or settlement manipulation.".to_string(),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_non_atomic_settlement(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x55 { // SSTORE (update intent state)
                let mut has_cross_chain_call = false;
                let mut has_second_update = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (cross-chain message)
                        has_cross_chain_call = true;
                    }
                    if bytecode[j] == 0x55 && has_cross_chain_call { // SSTORE (settlement)
                        has_second_update = true;
                    }
                }

                if has_cross_chain_call && has_second_update {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_filler_griefing(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (intent status)
                let mut has_cancellation = false;
                let mut has_filler_loss = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x57 { // JUMPI (cancel path)
                        has_cancellation = true;
                    }
                    if bytecode[j] == 0xF1 && has_cancellation { // CALL (no compensation)
                        has_filler_loss = true;
                    }
                }

                if has_cancellation && has_filler_loss {
                    return Some(i);
                }
            }
        }

        None
    }
}
