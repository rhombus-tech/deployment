use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnderwritingBypassVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct UnderwritingRiskAssessmentBypassDetector {
    bytecode: Vec<u8>,
}

impl UnderwritingRiskAssessmentBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<UnderwritingBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_risk_score_manipulation());
        vulnerabilities.extend(self.detect_historical_data_bypass());
        vulnerabilities.extend(self.detect_premium_calculation_exploit());

        vulnerabilities
    }

    fn detect_risk_score_manipulation(&self) -> Vec<UnderwritingBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (risk parameters input)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_risk_calc = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV (scoring)
                let has_storage = window.iter().any(|&b| b == 0x55); // SSTORE (storing score)
                
                if has_risk_calc && has_storage {
                    let has_validation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3; // Multiple range checks
                    let has_sanity_bounds = window.iter().any(|&b| b == 0xFD); // REVERT on invalid
                    
                    if !has_validation || !has_sanity_bounds {
                        vulns.push(UnderwritingBypassVulnerability {
                            pc,
                            vulnerability_type: "RiskScoreManipulation".to_string(),
                            description: format!(
                                "Risk assessment at PC {} accepts user input without comprehensive validation. Attack: submit \
                                false risk parameters to receive lower premium. Example: claim protocol has low TVL, minimal \
                                historical activity to appear low-risk. Missing: input range validation, cross-reference with \
                                on-chain data, sanity checks. Enables adverse selection with underpriced coverage.",
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

    fn detect_historical_data_bypass(&self) -> Vec<UnderwritingBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (reading historical data)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_comparison = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_timestamp && has_comparison {
                    let has_minimum_history = window.windows(2).any(|w| {
                        (w[0] >= 0x60 && w[0] <= 0x7F) && w[1] == 0x03 // PUSH + SUB (minimum age check)
                    });
                    
                    let historical_loads = window.iter().filter(|&&b| b == 0x54).count();
                    
                    if !has_minimum_history || historical_loads < 3 {
                        vulns.push(UnderwritingBypassVulnerability {
                            pc,
                            vulnerability_type: "HistoricalDataBypass".to_string(),
                            description: format!(
                                "Underwriting at PC {} uses insufficient historical data ({} datapoints). New protocol can \
                                purchase coverage immediately without track record. Attack: deploy protocol, buy insurance, \
                                exploit vulnerability, claim payout. Missing: minimum operational period (e.g., 90 days), \
                                historical performance requirement, sufficient data points. Enables premeditated insurance fraud.",
                                pc, historical_loads
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

    fn detect_premium_calculation_exploit(&self) -> Vec<UnderwritingBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0x02 | 0x04) { // MUL, DIV (premium calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_coverage_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_risk_factor = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_coverage_amount && has_risk_factor {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_overflow_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_minimum_premium = forward.iter().any(|&b| b == 0xFD); // REVERT
                    let has_rounding_protection = forward.iter().any(|&b| b == 0x06); // MOD
                    
                    if !has_overflow_check || !has_minimum_premium || !has_rounding_protection {
                        vulns.push(UnderwritingBypassVulnerability {
                            pc,
                            vulnerability_type: "PremiumCalculationExploit".to_string(),
                            description: format!(
                                "Premium calculation at PC {} vulnerable to manipulation. Attack vectors: (1) overflow in \
                                multiplication causes premium wrap to zero, (2) rounding errors allow coverage for negligible \
                                premium, (3) no minimum premium enables dust coverage. Missing: overflow protection, minimum \
                                premium floor, proper rounding. Enables obtaining coverage essentially for free.",
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
}
