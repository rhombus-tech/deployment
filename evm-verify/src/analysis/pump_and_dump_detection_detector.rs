use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PumpAndDumpVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PumpAndDumpDetectionDetector {
    bytecode: Vec<u8>,
}

impl PumpAndDumpDetectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PumpAndDumpVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_coordinated_pump());
        vulnerabilities.extend(self.detect_insider_dump());
        vulnerabilities.extend(self.detect_artificial_scarcity());

        vulnerabilities
    }

    fn detect_coordinated_pump(&self) -> Vec<PumpAndDumpVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (price/supply calculation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_supply_control = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_price_impact = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                
                if has_supply_control {
                    let has_buy_pressure_detection = window.iter().filter(|&&b| b == 0xF1).count() >= 2;
                    let has_time_window_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    let has_pump_protection = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 4;
                    let has_circuit_breaker = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if has_buy_pressure_detection && !has_circuit_breaker {
                        vulns.push(PumpAndDumpVulnerability {
                            pc,
                            vulnerability_type: "CoordinatedPump".to_string(),
                            description: format!(
                                "Token mechanics at PC {} vulnerable to coordinated pump and dump. Attack: (1) insiders accumulate tokens cheaply, (2) coordinate marketing \
                                campaign with false promises, (3) retail FOMO buys drive price up 100-1000x, (4) insiders sell holdings into liquidity, (5) price crashes, \
                                retail loses. Classic rug pull pattern. Missing: circuit breakers on rapid price increases, gradual unlock schedules for team tokens, \
                                maximum daily price change limits, whale wallet concentration alerts. Should implement: if price increases >50% in 1 hour, pause trading \
                                or increase selling friction.",
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

    fn detect_insider_dump(&self) -> Vec<PumpAndDumpVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (token transfer/sell)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_large_transfer = window.iter().filter(|&&b| matches!(b, 0x6A..=0x7F)).count() >= 1; // PUSH11+ (large amount)
                let has_privileged_check = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_large_transfer {
                    let has_vesting_lock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_gradual_unlock = window.iter().filter(|&&b| b == 0x04).count() >= 2; // DIV (time-based release)
                    
                    if !has_vesting_lock && !has_gradual_unlock {
                        vulns.push(PumpAndDumpVulnerability {
                            pc,
                            vulnerability_type: "InsiderDump".to_string(),
                            description: format!(
                                "Large transfer capability at PC {} without vesting protection. Attack: team/insiders hold majority of tokens with no lock-up, project \
                                launches and price pumps on initial hype, insiders immediately dump entire allocation into market, price crashes 99%, retail investors \
                                left holding worthless tokens. Exit scam pattern. Missing: time-locked vesting (e.g., 4-year linear unlock), cliff periods (e.g., 1-year \
                                before any unlock), maximum % of supply sellable per period, on-chain vesting verification. Should implement: smart contract enforced vesting \
                                with public transparency of unlock schedules.",
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

    fn detect_artificial_scarcity(&self) -> Vec<PumpAndDumpVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (supply modification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_burn_mechanism = window.iter().any(|&b| b == 0x03); // SUB (reduce supply)
                let has_mint_control = window.iter().any(|&b| b == 0x01); // ADD (increase supply)
                
                if has_burn_mechanism || has_mint_control {
                    let has_access_control = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_transparent_schedule = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_transparent_schedule {
                        vulns.push(PumpAndDumpVulnerability {
                            pc,
                            vulnerability_type: "ArtificialScarcity".to_string(),
                            description: format!(
                                "Supply manipulation at PC {} enables artificial scarcity pump. Attack: (1) team burns tokens or restricts selling to create false scarcity, \
                                (2) marketing emphasizes 'deflationary' or 'limited supply', (3) scarcity narrative pumps price, (4) team sells at peak or mints new tokens \
                                diluting holders. Bait-and-switch on tokenomics. Example: burn mechanism that can be disabled, or hidden mint function. Missing: immutable \
                                supply rules, transparent burn/mint schedule, on-chain governance for tokenomics changes, supply change rate limits. Should make: total \
                                supply immutable or require time-locked governance vote for any changes.",
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
