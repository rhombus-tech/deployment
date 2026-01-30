use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenomicsGovernanceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TokenomicsParameterGovernanceAttackDetector {
    bytecode: Vec<u8>,
}

impl TokenomicsParameterGovernanceAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TokenomicsGovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_emergency_parameter_override());
        vulnerabilities.extend(self.detect_parameter_change_frontrunning());
        vulnerabilities.extend(self.detect_circular_governance_dependency());

        vulnerabilities
    }

    fn detect_emergency_parameter_override(&self) -> Vec<TokenomicsGovernanceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (parameter update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_data_input = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_admin_check && has_data_input {
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_proposal_check = window.iter().filter(|&&b| b == 0x54).count() >= 2; // SLOAD for proposal state
                    
                    if !has_timelock && !has_proposal_check {
                        vulns.push(TokenomicsGovernanceVulnerability {
                            pc,
                            vulnerability_type: "EmergencyParameterOverride".to_string(),
                            description: format!(
                                "Tokenomics parameter update at PC {} bypasses governance via emergency admin. No timelock \
                                or proposal requirement allows instant parameter changes. Enables: sudden fee increases, \
                                immediate supply cap changes, instant burn rate modifications. Missing: mandatory timelock, \
                                multi-sig requirement, governance approval. Admin can rug pull by changing economics instantly.",
                                pc
                            ),
                            confidence: 0.88,
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

    fn detect_parameter_change_frontrunning(&self) -> Vec<TokenomicsGovernanceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (parameter change)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_timestamp = window.iter().any(|&b| b == 0x42);
                
                if has_timestamp {
                    let has_activation_delay = window.windows(3).any(|w| {
                        w[0] == 0x42 && w[1] == 0x01 // TIMESTAMP + ADD (future activation)
                    });
                    
                    let has_announcement = window.iter().any(|&b| matches!(b, 0xA0..=0xA4)); // LOGx
                    
                    if !has_activation_delay && !has_announcement {
                        vulns.push(TokenomicsGovernanceVulnerability {
                            pc,
                            vulnerability_type: "ParameterChangeFrontrunning".to_string(),
                            description: format!(
                                "Parameter change at PC {} takes effect immediately without warning. Users cannot react to \
                                proposed changes before activation. Attack: governance proposal passes, insiders frontrun \
                                with knowledge of upcoming change (e.g., fee increase, supply change). Missing: activation \
                                delay, public announcement period, gradual transition. Enables insider trading on parameter changes.",
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

    fn detect_circular_governance_dependency(&self) -> Vec<TokenomicsGovernanceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // External call to governance
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_token_balance_check = window.iter().any(|&b| b == 0x31); // BALANCE
                let has_voting_power_calc = window.iter().any(|&b| b == 0x02); // MUL (power calculation)
                
                if has_token_balance_check && has_voting_power_calc {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_parameter_update = forward.iter().any(|&b| b == 0x55); // SSTORE
                    let has_fallback = forward.iter().filter(|&&b| b == 0x57).count() > 1; // Multiple JUMPI
                    
                    if has_parameter_update && !has_fallback {
                        vulns.push(TokenomicsGovernanceVulnerability {
                            pc,
                            vulnerability_type: "CircularGovernanceDependency".to_string(),
                            description: format!(
                                "Governance call at PC {} creates circular dependency: token economics affect voting power, \
                                voting power controls economics. Attack: manipulate token supply/distribution to gain governance \
                                control, then change parameters to consolidate power further. Missing: governance independence \
                                from token economics, failsafe governance mechanism, parameter bounds. Enables governance capture \
                                via economic manipulation.",
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
