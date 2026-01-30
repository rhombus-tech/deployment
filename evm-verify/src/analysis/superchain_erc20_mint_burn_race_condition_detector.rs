use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SuperchainErc20MintBurnRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl SuperchainErc20MintBurnRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_mint_burn_race_condition() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Cross-chain mint and burn operations can race causing total supply inconsistencies across chains.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_cross_chain_balance_desync() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Token balances can desynchronize across Superchain due to failed message delivery or reorg.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_mint_burn_race_condition(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x54 { // SLOAD (total supply)
                let mut has_mint = false;
                let mut has_burn = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (mint)
                        has_mint = true;
                    }
                    if bytecode[j] == 0x03 { // SUB (burn)
                        has_burn = true;
                    }
                    if has_mint && has_burn {
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE (update)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_cross_chain_balance_desync(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF1 { // CALL (cross-chain message)
                let mut has_balance_update = false;
                let mut lacks_confirmation = true;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE (balance update)
                        has_balance_update = true;
                    }
                    if bytecode[j] == 0x54 { // SLOAD (check confirmation)
                        lacks_confirmation = false;
                    }
                }

                if has_balance_update && lacks_confirmation {
                    return Some(i);
                }
            }
        }

        None
    }
}
