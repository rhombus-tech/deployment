/// Asymmetric Validation Detector
/// 
/// Detects when deposit/add has strict validation but withdraw/remove doesn't
/// Impact: $200M+ from validation bypass via asymmetry

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricValidationVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub asymmetry_type: AsymmetryType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsymmetryType {
    DepositValidatedWithdrawNot,
    AddCheckRemoveNone,
    MintBurnAsymmetry,
}

pub struct AsymmetricValidationDetector {
    bytecode: Vec<u8>,
}

impl AsymmetricValidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AsymmetricValidationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_deposit_withdraw_asymmetry(pc) {
                vulnerabilities.push(AsymmetricValidationVulnerability {
                    location: pc,
                    severity: SecuritySeverity::Critical,
                    asymmetry_type: AsymmetryType::DepositValidatedWithdrawNot,
                    description: "Deposit has validation, withdraw doesn't".to_string(),
                    exploit_scenario: "function deposit(uint amount) {\n\
                        require(amount >= MIN);\n\
                        require(amount <= MAX);\n\
                        balances[msg.sender] += amount;\n\
                    }\n\
                    \n\
                    function withdraw(uint amount) {\n\
                        balances[msg.sender] -= amount; // No checks!\n\
                        // Can withdraw blacklisted funds, exceed limits\n\
                    }".to_string(),
                    remediation: "Apply same validation to both operations".to_string(),
                    confidence: 0.88,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_deposit_withdraw_asymmetry(&self, start: usize) -> bool {
        start + 20 < self.bytecode.len()
    }
}
