use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymasterVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PaymasterGasSponsorshipGriefingDetector {
    bytecode: Vec<u8>,
}

impl PaymasterGasSponsorshipGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PaymasterVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_gas_sponsorship());
        vulnerabilities.extend(self.detect_missing_user_operation_validation());
        vulnerabilities.extend(self.detect_paymaster_deposit_drain());

        vulnerabilities
    }

    fn detect_unbounded_gas_sponsorship(&self) -> Vec<PaymasterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for GAS opcode (0x5A) used in sponsorship calculation
            if opcode == 0x5A {
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for gas limit validation
                let has_gas_limit_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                // Check for multiplication (gas * price calculation)
                let has_mul = window.iter().any(|&b| b == 0x02); // MUL
                
                // Check for revert on excessive gas
                let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                
                if has_mul && !has_gas_limit_check && !has_revert {
                    vulns.push(PaymasterVulnerability {
                        pc,
                        vulnerability_type: "UnboundedGasSponsorship".to_string(),
                        description: format!(
                            "ERC-4337 paymaster at PC {} sponsors gas without upper bound validation. \
                            Griefing attack: malicious user submits UserOp with extremely high gas limit, \
                            paymaster pays excessive fees, draining deposit. Missing protections: maximum gas \
                            limit per operation, gas price ceiling, per-user spending limits. Attacker can \
                            exhaust paymaster funds through repeated high-gas operations.",
                            pc
                        ),
                        confidence: 0.88,
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

    fn detect_missing_user_operation_validation(&self) -> Vec<PaymasterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for CALLDATALOAD (reading UserOperation)
            if opcode == 0x35 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for signature verification (ECRECOVER)
                let has_sig_check = window.iter().any(|&b| b == 0x01);
                
                // Check for sender validation (CALLER check)
                let has_sender_check = window.iter().any(|&b| b == 0x33);
                
                // Check for nonce validation (SLOAD for nonce tracking)
                let has_nonce_check = window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x14); // SLOAD + EQ
                
                // Look for postOp execution (storage write after validation)
                let has_sstore = window.iter().any(|&b| b == 0x55);
                
                if has_sstore && !has_sig_check && !has_sender_check && !has_nonce_check {
                    vulns.push(PaymasterVulnerability {
                        pc,
                        vulnerability_type: "MissingUserOperationValidation".to_string(),
                        description: format!(
                            "Paymaster validatePaymasterUserOp at PC {} accepts operations without proper validation. \
                            Missing checks: UserOp signature verification, sender authenticity, nonce replay protection. \
                            Enables attacks: replay of valid UserOps, unauthorized gas sponsorship, nonce manipulation. \
                            Attacker can reuse intercepted UserOps or forge operations to drain paymaster deposit.",
                            pc
                        ),
                        confidence: 0.85,
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

    fn detect_paymaster_deposit_drain(&self) -> Vec<PaymasterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for CALL to EntryPoint (deposit/stake operations)
            if matches!(opcode, 0xF1 | 0xFA) {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if this is a deposit operation (CALLVALUE or balance transfer)
                let has_value = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_value {
                    // Check for withdrawal protection mechanisms
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_owner_check = window.iter().any(|&b| b == 0x33); // CALLER
                    
                    // Check for rate limiting
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_rate_limit = forward_window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_timelock && !has_owner_check && !has_rate_limit {
                        vulns.push(PaymasterVulnerability {
                            pc,
                            vulnerability_type: "PaymasterDepositDrain".to_string(),
                            description: format!(
                                "Paymaster deposit management at PC {} lacks withdrawal protection. \
                                Missing safeguards: withdrawal timelock, owner-only access, rate limiting. \
                                Compromise scenario: if paymaster owner key compromised, attacker drains \
                                entire deposit instantly. ERC-4337 EntryPoint stake can't prevent rapid \
                                withdrawal. Should implement multi-sig, timelock, or gradual unlock.",
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
}
