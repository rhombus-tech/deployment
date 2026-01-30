use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidatorVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BridgeValidatorCollusionDetector {
    bytecode: Vec<u8>,
}

impl BridgeValidatorCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BridgeValidatorVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_low_threshold_multisig());
        vulnerabilities.extend(self.detect_validator_set_manipulation());
        vulnerabilities.extend(self.detect_stake_concentration());

        vulnerabilities
    }

    fn detect_low_threshold_multisig(&self) -> Vec<BridgeValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (validator signature count)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_signature_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2; // Multiple KECCAK256
                let has_threshold_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_signature_verification && has_threshold_check {
                    let has_high_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_validator_count_check = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                    
                    if !has_high_threshold {
                        vulns.push(BridgeValidatorVulnerability {
                            pc,
                            vulnerability_type: "LowThresholdMultisig".to_string(),
                            description: format!(
                                "Bridge validator threshold at PC {} potentially too low for security. Attack: bridge requires M of N validator signatures, if M/N ratio \
                                too low (e.g., 2-of-5 or 3-of-10), small group can collude to steal bridge funds. Example: Ronin bridge hack - required 5-of-9 validators, \
                                attacker compromised 5 keys, drained $600M. Risk scales with bridge TVL. Missing: minimum threshold validation (should be >66% for Byzantine \
                                fault tolerance), validator diversity requirements, slashing for collusion. Should enforce: M >= 2*N/3 + 1 (67%+ threshold) for bridges with \
                                >$10M TVL, use time-delayed withdrawals for additional security layer.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_validator_set_manipulation(&self) -> Vec<BridgeValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (validator set update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_control = window.iter().any(|&b| b == 0x33); // CALLER (admin)
                let has_validator_update = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                
                if has_admin_control && has_validator_update {
                    let has_timelock = window.iter().filter(|&&b| b == 0x42).count() >= 2; // TIMESTAMP delay
                    let has_governance = window.iter().filter(|&&b| b == 0x54).count() >= 4; // Multiple checks
                    
                    if !has_timelock && !has_governance {
                        vulns.push(BridgeValidatorVulnerability {
                            pc,
                            vulnerability_type: "ValidatorSetManipulation".to_string(),
                            description: format!(
                                "Validator set update at PC {} lacks governance protection. Attack: bridge admin can immediately replace validator set, admin adds own \
                                addresses as validators, approves fraudulent bridge transfer, drains bridge. Centralization risk. Example: admin changes from 'trusted \
                                validators' to 'attacker validators' in single transaction, no time for users to react. Missing: time-delayed validator updates (24-48h), \
                                governance vote requirement, validator addition caps per period. Should implement: validator changes via on-chain governance with 2-day \
                                timelock, maximum 1 validator replacement per week, emergency pause mechanism monitored by community.",
                                pc
                            ),
                            confidence: 0.87,
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

    fn detect_stake_concentration(&self) -> Vec<BridgeValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (stake-weighted voting)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_stake_calculation = window.iter().any(|&b| b == 0x54); // SLOAD (stake amount)
                let has_voting_power = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                
                if has_stake_calculation && has_voting_power {
                    let has_max_stake_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_distribution_check = window.iter().filter(|&&b| b == 0x04).count() >= 2;
                    
                    if !has_max_stake_check {
                        vulns.push(BridgeValidatorVulnerability {
                            pc,
                            vulnerability_type: "StakeConcentration".to_string(),
                            description: format!(
                                "Stake-weighted bridge validation at PC {} allows concentration risk. Attack: bridge uses stake-weighted validator voting, single entity \
                                accumulates >33% stake (or >50% depending on threshold), entity alone can block or approve fraudulent bridge operations. Plutocracy attack. \
                                Example: whale acquires 51% of validator tokens, unilaterally approves bridge withdrawal to their address, bypasses security. Missing: \
                                maximum stake per validator (cap at 10-15% total), stake distribution requirements, validator diversity metrics. Should enforce: no single \
                                validator holds >10% voting power, use quadratic staking (diminishing returns on large stakes), or require stake + identity diversity.",
                                pc
                            ),
                            confidence: 0.82,
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
