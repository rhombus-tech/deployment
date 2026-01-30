use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiaVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SiaHostCollusionAttackDetector {
    bytecode: Vec<u8>,
}

impl SiaHostCollusionAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SiaVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_insufficient_host_diversity());
        vulnerabilities.extend(self.detect_collateral_manipulation());
        vulnerabilities.extend(self.detect_proof_of_storage_collusion());

        vulnerabilities
    }

    fn detect_insufficient_host_diversity(&self) -> Vec<SiaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut host_selections = 0;
        let mut diversity_checks = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External calls to Sia hosts
            if matches!(opcode, 0xF1 | 0xFA) {
                host_selections += 1;
            }
            
            // Address comparison/uniqueness checks
            if opcode == 0x14 { // EQ (comparing addresses)
                let start = if pc > 10 { pc - 10 } else { 0 };
                if self.bytecode[start..pc].iter().any(|&b| b == 0x33) { // CALLER
                    diversity_checks += 1;
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If selecting multiple hosts without diversity enforcement
        if host_selections >= 2 && diversity_checks == 0 {
            vulns.push(SiaVulnerability {
                pc: 0,
                vulnerability_type: "InsufficientHostDiversity".to_string(),
                description: format!(
                    "Contract selects {} Sia storage hosts without diversity enforcement. \
                    Vulnerable to: host collusion to withhold data, coordinated data loss, \
                    simultaneous host failures affecting redundancy. Missing validations: \
                    geographic distribution, ownership diversity, network topology separation. \
                    Colluding hosts can coordinate to fail proof-of-storage or hold data ransom.",
                    host_selections
                ),
                confidence: 0.83,
            });
        }

        vulns
    }

    fn detect_collateral_manipulation(&self) -> Vec<SiaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for collateral validation logic
            if opcode == 0x10 || opcode == 0x11 { // LT, GT (comparing collateral amounts)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if comparing against storage contract value
                let has_value_comparison = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_value_comparison {
                    // Check for minimum collateral enforcement
                    let window_end = (pc + 30).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_revert = forward_window.iter().any(|&b| b == 0xFD); // REVERT
                    
                    // Check for collateral-to-storage ratio validation
                    let has_ratio_check = window.iter().any(|&b| matches!(b, 0x04 | 0x05)); // DIV, SDIV
                    
                    if !has_revert || !has_ratio_check {
                        vulns.push(SiaVulnerability {
                            pc,
                            vulnerability_type: "CollateralManipulation".to_string(),
                            description: format!(
                                "Sia collateral validation at PC {} insufficient for host accountability. \
                                Missing enforcement of: minimum collateral-to-storage ratio, collateral lock period, \
                                slashing conditions for data loss. Malicious hosts can: post minimal collateral, \
                                profit from storage payments while risking little, coordinate to delete data with \
                                acceptable losses, avoid economic penalties for poor service.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_proof_of_storage_collusion(&self) -> Vec<SiaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for proof verification (KECCAK256 for Merkle proofs)
            if opcode == 0x20 {
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for proof validation
                let has_eq_check = window.iter().any(|&b| b == 0x14);
                
                if has_eq_check {
                    // Check for multiple independent proofs (redundancy)
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Count external calls (should verify proofs from multiple hosts)
                    let call_count = pre_window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count();
                    
                    // Check for proof freshness (timestamp validation)
                    let has_timestamp = pre_window.iter().any(|&b| b == 0x42);
                    
                    if call_count < 2 || !has_timestamp {
                        vulns.push(SiaVulnerability {
                            pc,
                            vulnerability_type: "ProofOfStorageCollusion".to_string(),
                            description: format!(
                                "Sia proof-of-storage verification at PC {} vulnerable to host collusion. \
                                Accepting proofs from {} host(s) without multi-party validation. Missing: \
                                independent proof verification from redundant hosts, proof freshness validation, \
                                cross-verification of storage claims. Colluding hosts can: provide coordinated \
                                false proofs, fake data availability, avoid storing actual data while passing audits.",
                                pc, if call_count == 0 { 1 } else { call_count }
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
