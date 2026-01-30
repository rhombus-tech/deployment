use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilecoinVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FilecoinDealSlashingManipulationDetector {
    bytecode: Vec<u8>,
}

impl FilecoinDealSlashingManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FilecoinVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_deal_activation());
        vulnerabilities.extend(self.detect_slashing_condition_bypass());
        vulnerabilities.extend(self.detect_storage_provider_collusion());

        vulnerabilities
    }

    fn detect_unchecked_deal_activation(&self) -> Vec<FilecoinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call followed by state change without validation
            if matches!(opcode, 0xF1 | 0xFA) {
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut has_validation = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 40 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                        break;
                    }
                    
                    // Check for validation (EQ, ISZERO, comparison ops)
                    if matches!(check_op, 0x14 | 0x15 | 0x10 | 0x11) {
                        has_validation = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !has_validation {
                    vulns.push(FilecoinVulnerability {
                        pc,
                        vulnerability_type: "UncheckedDealActivation".to_string(),
                        description: format!(
                            "Filecoin deal activation at PC {} without verification of deal state. \
                            Missing checks for: deal activation status, sector commitment, proof-of-spacetime, \
                            and collateral requirements. Attacker can claim deal is active when storage provider \
                            hasn't committed resources or is already slashed.",
                            pc
                        ),
                        confidence: 0.89,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_slashing_condition_bypass(&self) -> Vec<FilecoinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Timestamp operations that might be used for slashing window checks
            if opcode == 0x42 { // TIMESTAMP
                let mut check_pc = pc + 1;
                let mut has_comparison = false;
                let mut has_revert = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 30 {
                    let check_op = self.bytecode[check_pc];
                    
                    if matches!(check_op, 0x10 | 0x11 | 0x12 | 0x13) { // LT, GT, SLT, SGT
                        has_comparison = true;
                    }
                    
                    if matches!(check_op, 0xFD | 0xFE) { // REVERT, INVALID
                        has_revert = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if has_comparison && !has_revert {
                    vulns.push(FilecoinVulnerability {
                        pc,
                        vulnerability_type: "SlashingConditionBypass".to_string(),
                        description: format!(
                            "Slashing window check at PC {} without enforcement. \
                            Storage provider fault detection windows can be bypassed. Missing proper \
                            validation of: sector fault reporting deadlines, WindowPoSt submission timing, \
                            and consensus fault penalties. Providers can avoid slashing by manipulating timing.",
                            pc
                        ),
                        confidence: 0.84,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_storage_provider_collusion(&self) -> Vec<FilecoinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut external_calls = 0;
        let mut unique_checks = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) {
                external_calls += 1;
            }
            
            // Look for address uniqueness checks (XOR, EQ comparisons)
            if opcode == 0x18 { // XOR (used for comparing addresses)
                unique_checks += 1;
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If multiple external calls but no uniqueness validation
        if external_calls >= 2 && unique_checks == 0 {
            vulns.push(FilecoinVulnerability {
                pc: 0,
                vulnerability_type: "StorageProviderCollusion".to_string(),
                description: format!(
                    "Contract makes {} storage provider calls without uniqueness validation. \
                    Missing checks for: distinct storage provider IDs, separate ownership verification, \
                    and collusion resistance. Attackers can use multiple controlled providers to \
                    fake redundancy, manipulate deal pricing, or coordinate sector failures.",
                    external_calls
                ),
                confidence: 0.81,
            });
        }

        vulns
    }
}
