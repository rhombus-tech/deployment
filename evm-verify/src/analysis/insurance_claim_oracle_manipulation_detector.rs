use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsuranceClaimVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct InsuranceClaimOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl InsuranceClaimOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<InsuranceClaimVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_oracle_dependency());
        vulnerabilities.extend(self.detect_claim_trigger_manipulation());
        vulnerabilities.extend(self.detect_flash_loan_claim_exploit());

        vulnerabilities
    }

    fn detect_single_oracle_dependency(&self) -> Vec<InsuranceClaimVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xFA | 0xF1) { // STATICCALL, CALL (oracle query)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_address = window.windows(2).any(|w| w[0] >= 0x73 && w[0] <= 0x7F); // PUSH20
                
                if has_oracle_address {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let oracle_count = forward.iter().filter(|&&b| matches!(b, 0xFA | 0xF1)).count();
                    let has_median_calc = forward.iter().any(|&b| b == 0x04); // DIV (median calculation)
                    
                    if oracle_count < 3 && !has_median_calc {
                        vulns.push(InsuranceClaimVulnerability {
                            pc,
                            vulnerability_type: "SingleOracleDependency".to_string(),
                            description: format!(
                                "Insurance claim validation at PC {} relies on single oracle. Manipulation: attacker compromises \
                                one oracle to trigger fraudulent claims. Example: DeFi insurance protocol uses Chainlink price feed, \
                                attacker bribes node operator to report false price drop, triggers payout. Missing: multi-oracle \
                                consensus (≥3 sources), median calculation, outlier detection. Single point of failure for claim validation.",
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

    fn detect_claim_trigger_manipulation(&self) -> Vec<InsuranceClaimVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (claim approval)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_comparison = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (threshold check)
                let has_external_data = window.iter().any(|&b| matches!(b, 0xFA | 0xF1)); // Oracle call
                
                if has_comparison && has_external_data {
                    let has_time_window = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_historical_check = window.iter().filter(|&&b| b == 0x54).count() >= 3; // Multiple SLOAD
                    
                    if !has_time_window && !has_historical_check {
                        vulns.push(InsuranceClaimVulnerability {
                            pc,
                            vulnerability_type: "ClaimTriggerManipulation".to_string(),
                            description: format!(
                                "Claim trigger at PC {} uses instant threshold without historical verification. Attack: flash \
                                loan manipulates on-chain state (e.g., price, TVL) to cross threshold, immediately files claim. \
                                Example: borrow massive amount, crash pool ratio, claim depeg insurance, return loan. Missing: \
                                time-weighted average, minimum duration below threshold, cooldown period. Enables single-block \
                                claim exploits.",
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

    fn detect_flash_loan_claim_exploit(&self) -> Vec<InsuranceClaimVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (claim payout)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value_transfer = window.iter().any(|&b| b == 0x34); // CALLVALUE
                let has_amount_calc = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV
                
                if has_value_transfer || has_amount_calc {
                    let has_flash_loan_detection = window.iter().any(|&b| b == 0x43); // NUMBER (block tracking)
                    let has_balance_snapshot = window.iter().filter(|&&b| b == 0x31).count() >= 2; // Multiple BALANCE
                    
                    if !has_flash_loan_detection && !has_balance_snapshot {
                        vulns.push(InsuranceClaimVulnerability {
                            pc,
                            vulnerability_type: "FlashLoanClaimExploit".to_string(),
                            description: format!(
                                "Claim payout at PC {} vulnerable to flash loan attack. Sequence: (1) flash loan assets, \
                                (2) manipulate insured protocol state, (3) file and receive claim, (4) restore state, \
                                (5) repay loan - all in one transaction. Missing: multi-block claim processing, balance increase \
                                detection, transaction origin validation. Enables risk-free insurance fraud via atomic exploit.",
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
}
