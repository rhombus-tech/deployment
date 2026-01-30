use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RariFuseOracleVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RariFusePoolOracleUpdateLagDetector {
    bytecode: Vec<u8>,
}

impl RariFusePoolOracleUpdateLagDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RariFuseOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_stale_oracle_price_usage());
        vulnerabilities.extend(self.detect_oracle_update_manipulation());
        vulnerabilities.extend(self.detect_multi_oracle_desync());

        vulnerabilities
    }

    fn detect_stale_oracle_price_usage(&self) -> Vec<RariFuseOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (oracle price fetch)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_call = window.iter().any(|&b| b == 0x20); // KECCAK256 or address calculation
                
                if has_oracle_call {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_timestamp_check = forward.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_staleness_validation = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_timestamp_check || !has_staleness_validation {
                        vulns.push(RariFuseOracleVulnerability {
                            pc,
                            vulnerability_type: "StaleOraclePriceUsage".to_string(),
                            description: format!(
                                "Rari Fuse oracle call at PC {} without staleness check. Fuse pools use custom oracles that may not update frequently. Attack: oracle \
                                price stale (last update 1 hour ago), real price moved significantly, attacker borrows against inflated collateral or liquidates using \
                                stale price. Pools with illiquid assets especially vulnerable. Missing: oracle update timestamp validation, max staleness threshold (e.g., \
                                5 minutes), circuit breaker for stale prices. Should require: block.timestamp - oracleUpdateTime <= MAX_STALENESS.",
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

    fn detect_oracle_update_manipulation(&self) -> Vec<RariFuseOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (liquidation/borrow state)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_price = window.iter().any(|&b| b == 0xFA); // STATICCALL
                let has_collateral_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_oracle_price && has_collateral_check {
                    let has_price_deviation_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_multi_block_average = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_price_deviation_check {
                        vulns.push(RariFuseOracleVulnerability {
                            pc,
                            vulnerability_type: "OracleUpdateManipulation".to_string(),
                            description: format!(
                                "Oracle price usage at PC {} vulnerable to update timing manipulation. Fuse allows custom oracles, including on-chain AMM-based. Attack: \
                                (1) observe oracle update transaction in mempool, (2) sandwich: frontrun with position setup, (3) oracle updates to manipulated price, \
                                (4) trigger liquidation/borrow using brief price spike, (5) backrun to restore price. Missing: TWAP instead of spot price, multi-block \
                                price averaging, oracle update cooldown. Should use time-weighted oracle data.",
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

    fn detect_multi_oracle_desync(&self) -> Vec<RariFuseOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (oracle)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let oracle_calls = window.iter().filter(|&&b| b == 0xFA).count();
                
                if oracle_calls >= 2 {
                    let has_price_consistency_check = window.iter().any(|&b| b == 0x03); // SUB (price difference)
                    let has_deviation_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // comparison
                    
                    if !has_price_consistency_check {
                        vulns.push(RariFuseOracleVulnerability {
                            pc,
                            vulnerability_type: "MultiOracleDesync".to_string(),
                            description: format!(
                                "Multiple oracle calls at PC {} without cross-validation. Fuse pools may use multiple oracles for different assets. Attack: Pool has \
                                TokenA (Chainlink oracle) and TokenB (Uniswap TWAP oracle), Chainlink updates every 1%, Uniswap updates every block, prices desync by \
                                3%, arbitrage between borrow/collateral using price discrepancy. Missing: oracle price deviation checks, primary/fallback oracle logic, \
                                circuit breaker on price disagreement. Should validate: abs(oracle1.price - oracle2.price) / oracle1.price < MAX_DEVIATION.",
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
