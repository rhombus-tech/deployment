/// Gas Sponsorship Exploit Detector (Enhanced AA)
/// Deep paymaster exploitation beyond basic AA validation
/// Critical for: Biconomy, Alchemy Gas Manager, Paymaster protocols

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasSponsorshipVulnerability {
    pub vulnerability_type: GasSponsorshipIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasSponsorshipIssueType {
    PaymasterGasGriefing,          // Drain paymaster via gas griefing
    SponsoredTransactionReplay,    // Replay sponsored transactions
    PaymasterFundsDraining,        // Drain paymaster balance
    GasEstimationManipulation,     // Manipulate gas estimation
    ConditionalSponsorshipBypass,  // Bypass sponsorship conditions
    UnboundedGasConsumption,       // No gas limit on sponsored ops
}

pub struct GasSponsorshipDetector {
    bytecode: Vec<u8>,
}

impl GasSponsorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GasSponsorshipVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_paymaster_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_gas_griefing());
        vulnerabilities.extend(self.detect_funds_draining());

        vulnerabilities
    }

    fn detect_gas_griefing(&self) -> Vec<GasSponsorshipVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: validatePaymasterUserOp without gas limit
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let validate = [0x0a, 0x34, 0x69, 0x7f]; // validatePaymasterUserOp
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &validate {
                if !self.has_gas_limit_check(i) {
                    vulnerabilities.push(GasSponsorshipVulnerability {
                        vulnerability_type: GasSponsorshipIssueType::UnboundedGasConsumption,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "Paymaster sponsors unbounded gas consumption".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker submits UserOp with maxGasLimit\n\
                            2. Paymaster sponsors without checking limit\n\
                            3. UserOp consumes massive gas\n\
                            4. Paymaster pays excessive fees\n\
                            5. Repeat to drain paymaster\n\n\
                            Fix: require(gasLimit <= MAX_SPONSORED_GAS)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_funds_draining(&self) -> Vec<GasSponsorshipVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Paymaster balance transfer without validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 && // CALL (transfer)
               self.is_in_paymaster_context(i) {
                if !self.has_balance_check(i) {
                    vulnerabilities.push(GasSponsorshipVulnerability {
                        vulnerability_type: GasSponsorshipIssueType::PaymasterFundsDraining,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: "Paymaster funds transferable without adequate validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Paymaster holds ETH for gas sponsorship\n\
                            2. Attacker crafts UserOp to trigger payout\n\
                            3. Validation insufficient\n\
                            4. Paymaster sends ETH to attacker\n\
                            5. Drain entire paymaster balance\n\n\
                            Fix: Strict validation of all fund transfers",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_paymaster_contract(&self) -> bool {
        let validate = [0x0a, 0x34, 0x69, 0x7f]; // validatePaymasterUserOp
        self.bytecode.windows(4).any(|w| w == validate)
    }

    fn has_gas_limit_check(&self, pos: usize) -> bool {
        // Look for gas comparison
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }

    fn is_in_paymaster_context(&self, pos: usize) -> bool {
        let validate = [0x0a, 0x34, 0x69, 0x7f];
        for i in pos.saturating_sub(100)..pos {
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &validate {
                return true;
            }
        }
        false
    }

    fn has_balance_check(&self, pos: usize) -> bool {
        // Look for BALANCE opcode check
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x31 { // BALANCE
                return true;
            }
        }
        false
    }
}
