use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraxEtherValidatorVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FraxEtherValidatorDepositFrontrunDetector {
    bytecode: Vec<u8>,
}

impl FraxEtherValidatorDepositFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FraxEtherValidatorVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_validator_deposit_frontrun());
        vulnerabilities.extend(self.detect_operator_selection_manipulation());
        vulnerabilities.extend(self.detect_withdrawal_credential_exploit());

        vulnerabilities
    }

    fn detect_validator_deposit_frontrun(&self) -> Vec<FraxEtherValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (deposit contract)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_32_eth = window.windows(2).any(|w| {
                    w[0] == 0x6B && w[1] == 0x1B // PUSH12 for 32 ETH in wei
                });
                let has_deposit_data = window.iter().any(|&b| b == 0x39); // CODECOPY (deposit data)
                
                if has_32_eth && has_deposit_data {
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256 (commitment)
                    let has_deposit_queue = window.iter().any(|&b| b == 0x42); // TIMESTAMP (ordering)
                    
                    if !has_commit_reveal && !has_deposit_queue {
                        vulns.push(FraxEtherValidatorVulnerability {
                            pc,
                            vulnerability_type: "ValidatorDepositFrontrun".to_string(),
                            description: format!(
                                "Frax Ether validator deposit at PC {} allows operator frontrunning. Attack: protocol selects validator operator, prepares to \
                                deposit 32 ETH, malicious operator observes deposit tx in mempool, frontruns with own deposit using same validator pubkey, \
                                steals protocol's deposit slot. Or: operator learns protocol's validator credentials, registers them first. Missing: commit-reveal \
                                for validator credentials, deposit authorization signature, operator bond requirement. Should use: two-phase deposit with \
                                commitment or encrypted credentials.",
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

    fn detect_operator_selection_manipulation(&self) -> Vec<FraxEtherValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (operator selection)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_random_selection = window.iter().any(|&b| matches!(b, 0x40 | 0x41)); // BLOCKHASH, COINBASE
                let has_operator_list = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_random_selection {
                    let has_vrf = window.iter().any(|&b| b == 0x20); // KECCAK256 (but not true VRF)
                    let has_commit_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_vrf || !has_commit_delay {
                        vulns.push(FraxEtherValidatorVulnerability {
                            pc,
                            vulnerability_type: "OperatorSelectionManipulation".to_string(),
                            description: format!(
                                "Operator selection at PC {} uses predictable randomness. Frax selects node operators to run validators. Attack: operator predicts \
                                they'll be selected next (via blockhash/timestamp), prepares malicious validator setup, gets selected, runs dishonest validator. Or: \
                                miner/validator manipulates blockhash/timestamp to influence selection. Missing: VRF-based selection, commit-reveal selection process, \
                                operator reputation scoring. Should use Chainlink VRF or multi-block commit-reveal for unpredictable selection.",
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

    fn detect_withdrawal_credential_exploit(&self) -> Vec<FraxEtherValidatorVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x39 { // CODECOPY (withdrawal credentials in deposit data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_deposit_call = window.iter().any(|&b| b == 0xF1); // CALL (deposit contract)
                
                if has_deposit_call {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_credential_validation = pre_window.iter().any(|&b| b == 0x14); // EQ (address check)
                    let has_signature_check = pre_window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_credential_validation {
                        vulns.push(FraxEtherValidatorVulnerability {
                            pc,
                            vulnerability_type: "WithdrawalCredentialExploit".to_string(),
                            description: format!(
                                "Withdrawal credentials at PC {} not validated before deposit. Validators specify withdrawal credentials (where ETH goes after \
                                exit). Attack: compromised operator or malicious proposal sets withdrawal credentials to attacker's address, protocol deposits 32 \
                                ETH, validator exits, withdrawals go to attacker not protocol. 32 ETH stolen. Missing: withdrawal credential whitelist, protocol-controlled \
                                withdrawal address validation, credential signature verification. Should enforce: withdrawal credentials == protocolControlledAddress.",
                                pc
                            ),
                            confidence: 0.89,
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
