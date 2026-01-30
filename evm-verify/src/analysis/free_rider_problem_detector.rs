use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeRiderVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FreeRiderProblemDetector {
    bytecode: Vec<u8>,
}

impl FreeRiderProblemDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FreeRiderVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_public_good_underfunding());
        vulnerabilities.extend(self.detect_oracle_report_free_riding());
        vulnerabilities.extend(self.detect_security_audit_free_riding());

        vulnerabilities
    }

    fn detect_public_good_underfunding(&self) -> Vec<FreeRiderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (contribution tracking)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_contribution = window.iter().any(|&b| b == 0x01); // ADD (fund addition)
                let has_benefit_distribution = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_contribution && has_benefit_distribution {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_contribution_requirement = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let benefits_all = forward.iter().filter(|&&b| b == 0xF1).count() >= 2; // Multiple beneficiaries
                    
                    if benefits_all && !has_contribution_requirement {
                        vulns.push(FreeRiderVulnerability {
                            pc,
                            vulnerability_type: "PublicGoodUnderfunding".to_string(),
                            description: format!(
                                "Public good funding at PC {} allows free riding. Economic theory: public goods are non-excludable (can't prevent non-payers from \
                                benefiting), leads to underfunding as rational actors free ride. Example: protocol security fund, benefits all users equally whether they \
                                contribute or not, rational user contributes $0 expecting others to fund, everyone free rides, fund receives $0. Missing: contribution \
                                requirements, excludability mechanism, quadratic funding, assurance contracts. Should implement: minimum contribution for protocol access \
                                or use matching funds to incentivize contributions.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_oracle_report_free_riding(&self) -> Vec<FreeRiderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (oracle read)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 80).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let uses_oracle_data = forward.iter().any(|&b| b == 0x02); // MUL (uses price)
                
                if uses_oracle_data {
                    let pays_for_oracle = window.iter().any(|&b| b == 0xF1); // CALL with value
                    let has_oracle_fee = window.iter().filter(|&&b| b == 0x02).count() >= 2;
                    
                    if !pays_for_oracle {
                        vulns.push(FreeRiderVulnerability {
                            pc,
                            vulnerability_type: "OracleReportFreeRiding".to_string(),
                            description: format!(
                                "Oracle data consumption at PC {} without fee payment. Free rider problem: oracle reporting costs gas (reporters pay), data benefits \
                                all users (non-excludable), rational user doesn't run oracle node, expects others to report, if everyone free rides, no oracle updates. \
                                Example: Uniswap TWAP oracle, anyone can call update, costs gas, benefits all users, underprovided. Missing: oracle query fees, reporter \
                                rewards from protocol fees, per-query payment mechanism. Should implement: users pay small fee per oracle read, redistributed to reporters.",
                                pc
                            ),
                            confidence: 0.83,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_security_audit_free_riding(&self) -> Vec<FreeRiderVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF4 { // DELEGATECALL (upgradeable pattern)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_implementation_address = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_implementation_address {
                    let has_audit_verification = window.iter().any(|&b| b == 0x20); // KECCAK256 (audit hash)
                    let has_security_deposit = window.iter().any(|&b| b == 0xF1); // CALL (payment)
                    
                    if !has_audit_verification && !has_security_deposit {
                        vulns.push(FreeRiderVulnerability {
                            pc,
                            vulnerability_type: "SecurityAuditFreeRiding".to_string(),
                            description: format!(
                                "Implementation upgrade at PC {} without audit requirement. Free rider problem: security audits cost $50-500K, benefit entire ecosystem \
                                (other projects copy audited code), rational project doesn't audit expecting to copy others' work, if everyone free rides, insufficient \
                                audits. Attack: fork audited protocol, change one line, skip audit, users assume it's safe (inherited audit), exploit introduced. Missing: \
                                audit verification registry, fork detection with audit invalidation, security deposit requirements. Should require: on-chain proof of audit \
                                for each unique codebase hash.",
                                pc
                            ),
                            confidence: 0.81,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
