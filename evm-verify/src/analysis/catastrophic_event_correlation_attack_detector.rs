use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatastrophicEventVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CatastrophicEventCorrelationAttackDetector {
    bytecode: Vec<u8>,
}

impl CatastrophicEventCorrelationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CatastrophicEventVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_correlated_risk_underestimation());
        vulnerabilities.extend(self.detect_systemic_event_cascades());
        vulnerabilities.extend(self.detect_reinsurance_pool_exhaustion());

        vulnerabilities
    }

    fn detect_correlated_risk_underestimation(&self) -> Vec<CatastrophicEventVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (policy issuance)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_risk_calc = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV
                
                if has_risk_calc {
                    let has_correlation_check = window.iter().filter(|&&b| b == 0x54).count() >= 3; // Multiple SLOAD (checking other policies)
                    let has_concentration_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_correlation_check || !has_concentration_limit {
                        vulns.push(CatastrophicEventVulnerability {
                            pc,
                            vulnerability_type: "CorrelatedRiskUnderestimation".to_string(),
                            description: format!(
                                "Risk assessment at PC {} treats policies as independent without correlation analysis. Catastrophic \
                                event triggers multiple claims simultaneously. Example: insuring 100 DeFi protocols, all using same \
                                oracle - oracle exploit triggers all claims at once. Missing: correlation coefficient calculation, \
                                exposure concentration limits, shared dependency detection. Pool can be bankrupted by single event.",
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

    fn detect_systemic_event_cascades(&self) -> Vec<CatastrophicEventVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (claim payout)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pool_balance = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                
                if has_pool_balance {
                    let has_pending_claims = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    let has_cascade_detection = window.iter().any(|&b| b == 0x43); // NUMBER (block-based cascade detection)
                    
                    if !has_pending_claims || !has_cascade_detection {
                        vulns.push(CatastrophicEventVulnerability {
                            pc,
                            vulnerability_type: "SystemicEventCascades".to_string(),
                            description: format!(
                                "Claim payout at PC {} without cascade risk management. Systemic event triggers claim waterfall: \
                                initial claims reduce pool, increasing risk for remaining policies, triggering more claims in domino \
                                effect. Example: stablecoin depeg causes protocol failures, each claim increases others' risk. \
                                Missing: cascade circuit breaker, phased payout queue, emergency reserves. Death spiral risk.",
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

    fn detect_reinsurance_pool_exhaustion(&self) -> Vec<CatastrophicEventVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x03 { // SUB (pool depletion)
                let window_end = (pc + 60).min(self.bytecode.len());
                let has_transfer = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0xF1 | 0x55));
                
                if has_transfer {
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let window = &self.bytecode[start..pc];
                    
                    let has_reserve_ratio = window.iter().any(|&b| b == 0x04); // DIV (ratio calculation)
                    let has_reinsurance_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // External reinsurance
                    
                    if has_reserve_ratio && !has_reinsurance_call {
                        vulns.push(CatastrophicEventVulnerability {
                            pc,
                            vulnerability_type: "ReinsurancePoolExhaustion".to_string(),
                            description: format!(
                                "Pool depletion at PC {} lacks reinsurance backstop. Catastrophic event exceeds pool capacity \
                                with no secondary coverage layer. Traditional insurance uses reinsurance for tail risk. Missing: \
                                reinsurance protocol integration, excess-of-loss coverage, stop-loss protection. Single pool \
                                responsible for unlimited correlated claims without capacity expansion mechanism.",
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
}
