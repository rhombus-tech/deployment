use crate::bytecode::SecurityFinding;

pub struct ComposableStablecoinDetector {
    bytecode: Vec<u8>,
}

impl ComposableStablecoinDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_collateral_composition_attack() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Composable stablecoin collateral mix vulnerable to manipulation at PC {}. \
                    Attacker can devalue backing by flooding with low-quality collateral.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_peg_arbitrage_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Multi-collateral stablecoin peg mechanism exploitable at PC {}. \
                    Arbitrage between collateral types can drain protocol reserves.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_liquidation_cascade() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Liquidation mechanism can trigger cascade failure at PC {}. \
                    Correlated collateral types amplify liquidation pressure.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_collateral_composition_attack(&self) -> Option<usize> {
        // Look for multi-collateral minting without composition limits
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // mint, deposit, addCollateral selectors
                if matches!(selector, [0x40, 0xc1, 0x0f, 0x19] | [0xd0, 0xe3, _, _] | [0xe1, 0xf4, _, _]) {
                    let mut accepts_multiple_collaterals = false;
                    let mut has_composition_limit = false;
                    let mut validates_collateral_quality = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for collateral type parameter
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (collateral type)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x20 { // KECCAK256 (mapping lookup)
                                accepts_multiple_collaterals = true;
                            }
                        }
                        // Check for composition percentage limits
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (collateral balance)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x04 && // DIV (calculating percentage)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (checking limit)
                                has_composition_limit = true;
                            }
                        }
                        // Check for collateral quality/rating validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (collateral rating)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (minimum quality)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (require)
                                validates_collateral_quality = true;
                            }
                        }
                    }
                    
                    if accepts_multiple_collaterals && !has_composition_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_peg_arbitrage_exploit(&self) -> Option<usize> {
        // Look for redemption/minting without price deviation limits
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // redeem, swap, exchange selectors
                if matches!(selector, [0xdb, 0x00, 0x6a, 0x75] | [0x38, 0xed, 0x17, 0x39] | [0xa2, 0x3e, _, _]) {
                    let mut uses_oracle_prices = false;
                    let mut has_deviation_limit = false;
                    let mut enforces_trading_fee = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for oracle price usage
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getPrice, latestRoundData selectors
                            if matches!(sub_selector, [0xfe, 0xaf, 0x96, 0x8c] | [0xa1, 0x3e, _, _]) {
                                uses_oracle_prices = true;
                            }
                        }
                        // Check for price deviation limits
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (target price)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x03 && // SUB (deviation)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x10 { // LT (max deviation)
                                has_deviation_limit = true;
                            }
                        }
                        // Check for trading fee application
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (fee rate)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x02 && // MUL (applying fee)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x04 { // DIV (fee calculation)
                                enforces_trading_fee = true;
                            }
                        }
                    }
                    
                    if uses_oracle_prices && (!has_deviation_limit || !enforces_trading_fee) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_liquidation_cascade(&self) -> Option<usize> {
        // Look for liquidations without cascade protection
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // liquidate, seize selectors
                if matches!(selector, [0x96, 0xcd, 0x46, 0x93] | [0xa1, 0x3e, _, _]) {
                    let mut has_circuit_breaker = false;
                    let mut limits_liquidation_size = false;
                    let mut validates_collateral_correlation = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for circuit breaker
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (pause flag)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 { // ISZERO (checking not paused)
                                has_circuit_breaker = true;
                            }
                        }
                        // Check for liquidation size limits
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (position size)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x04 && // DIV (partial liquidation)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x60 { // PUSH1 (max percentage)
                                limits_liquidation_size = true;
                            }
                        }
                        // Check for correlation validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (correlation matrix)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x10 { // LT (correlation threshold)
                                validates_collateral_correlation = true;
                            }
                        }
                    }
                    
                    if !has_circuit_breaker || !limits_liquidation_size {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
