use crate::bytecode::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicAttack {
    DeathSpiral,
    BankRun,
    LiquidityCrisis,
    PegDeviation,
    ReserveDrain,
    ConfidenceDecay,
    EquilibriumBreak,
    ReflexivityCascade,
    ArbitrageFailure,
    LiquidationCascade,
    InvariantViolation,
    MarketManipulation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicCondition {
    LowLiquidity,
    RedemptionPressure,
    OracleLag,
    CollateralConcentration,
    GovernanceConcentration,
    ExternalDependency,
    AsymmetricInfo,
    NetworkBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicVulnerability {
    pub attack_type: EconomicAttack,
    pub conditions: Vec<EconomicCondition>,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub economic_model: String,
    pub attack_vector: String,
    pub manipulation_cost: Option<f64>,
    pub time_window: Option<u64>,
    pub detection_confidence: f32,
    pub affected_functions: Vec<[u8; 4]>,
    pub economic_invariants: Vec<String>,
}

pub struct EconomicAttackAnalyzer {
    bytecode: Vec<u8>,
    mint_functions: HashSet<[u8; 4]>,
    burn_functions: HashSet<[u8; 4]>,
    redeem_functions: HashSet<[u8; 4]>,
    swap_functions: HashSet<[u8; 4]>,
    oracle_functions: HashSet<[u8; 4]>,
}

impl EconomicAttackAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut mint_functions = HashSet::new();
        mint_functions.insert([0x40, 0xc1, 0x0f, 0x19]); // mint()
        mint_functions.insert([0xa0, 0x71, 0x2d, 0x68]); // mint(uint256)

        let mut burn_functions = HashSet::new();
        burn_functions.insert([0x42, 0x96, 0x6c, 0x68]); // burn()
        burn_functions.insert([0x9d, 0xc2, 0x9f, 0xac]); // burn(uint256)

        let mut redeem_functions = HashSet::new();
        redeem_functions.insert([0xdb, 0x00, 0x6a, 0x75]); // redeem()
        redeem_functions.insert([0x95, 0x2b, 0x27, 0x97]); // withdraw()

        let mut swap_functions = HashSet::new();
        swap_functions.insert([0x38, 0xed, 0x17, 0x39]); // swapExactTokensForTokens()
        swap_functions.insert([0x8a, 0x03, 0xd2, 0xe1]); // swapTokensForExactTokens()

        let mut oracle_functions = HashSet::new();
        oracle_functions.insert([0x50, 0xd2, 0x5b, 0xcd]); // latestAnswer()
        oracle_functions.insert([0xfe, 0xaf, 0x96, 0x8c]); // latestRoundData()

        Self {
            bytecode,
            mint_functions,
            burn_functions,
            redeem_functions,
            swap_functions,
            oracle_functions,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_death_spiral_risks());
        vulnerabilities.extend(self.detect_bank_run_risks());
        vulnerabilities.extend(self.detect_liquidity_crisis_risks());
        vulnerabilities.extend(self.detect_peg_deviation_risks());
        vulnerabilities.extend(self.detect_market_manipulation_risks());

        vulnerabilities
    }

    fn detect_death_spiral_risks(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_mint = self.has_function_signatures(&self.mint_functions);
        let has_burn = self.has_function_signatures(&self.burn_functions);
        let has_confidence_backstop = self.analyze_confidence_mechanisms();

        if has_mint && has_burn && !has_confidence_backstop {
            vulnerabilities.push(EconomicVulnerability {
                attack_type: EconomicAttack::DeathSpiral,
                conditions: vec![
                    EconomicCondition::LowLiquidity,
                    EconomicCondition::RedemptionPressure,
                    EconomicCondition::NetworkBreakdown,
                ],
                severity: SecuritySeverity::Critical,
                location: 0,
                description: "Death spiral risk: unstable mint/burn equilibrium without confidence backstops".to_string(),
                economic_model: "Mint/burn mechanism without stabilization safeguards".to_string(),
                attack_vector: "Coordinated redemptions trigger confidence loss cascade".to_string(),
                manipulation_cost: Some(100000.0),
                time_window: Some(3600),
                detection_confidence: 0.85,
                affected_functions: self.get_mint_burn_selectors(),
                economic_invariants: vec![
                    "mint_rate <= burn_rate + arbitrage_buffer".to_string(),
                    "confidence_index > critical_threshold".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_bank_run_risks(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_redeem = self.has_function_signatures(&self.redeem_functions);
        let has_rate_limits = self.analyze_withdrawal_limits();

        if has_redeem && !has_rate_limits {
            vulnerabilities.push(EconomicVulnerability {
                attack_type: EconomicAttack::BankRun,
                conditions: vec![
                    EconomicCondition::LowLiquidity,
                    EconomicCondition::RedemptionPressure,
                ],
                severity: SecuritySeverity::Critical,
                location: 0,
                description: "Bank run risk: unlimited redemptions without rate limiting".to_string(),
                economic_model: "Withdrawal mechanisms without velocity controls".to_string(),
                attack_vector: "Coordinated withdrawals exceed available reserves".to_string(),
                manipulation_cost: Some(500000.0),
                time_window: Some(1800),
                detection_confidence: 0.90,
                affected_functions: self.redeem_functions.iter().cloned().collect(),
                economic_invariants: vec![
                    "withdrawal_rate <= max_sustainable_rate".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_liquidity_crisis_risks(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_swap = self.has_function_signatures(&self.swap_functions);
        let has_emergency_liquidity = self.analyze_emergency_liquidity();

        if has_swap && !has_emergency_liquidity {
            vulnerabilities.push(EconomicVulnerability {
                attack_type: EconomicAttack::LiquidityCrisis,
                conditions: vec![
                    EconomicCondition::LowLiquidity,
                    EconomicCondition::ExternalDependency,
                ],
                severity: SecuritySeverity::High,
                location: 0,
                description: "Liquidity crisis risk: no emergency liquidity sources".to_string(),
                economic_model: "Liquidity dependent on external market makers".to_string(),
                attack_vector: "Remove liquidity to create trading crisis".to_string(),
                manipulation_cost: Some(250000.0),
                time_window: Some(900),
                detection_confidence: 0.75,
                affected_functions: self.swap_functions.iter().cloned().collect(),
                economic_invariants: vec![
                    "available_liquidity > min_operational_threshold".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_peg_deviation_risks(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_oracle = self.has_function_signatures(&self.oracle_functions);
        let has_peg_defense = self.analyze_peg_defense_mechanisms();

        if has_oracle && !has_peg_defense {
            vulnerabilities.push(EconomicVulnerability {
                attack_type: EconomicAttack::PegDeviation,
                conditions: vec![
                    EconomicCondition::OracleLag,
                    EconomicCondition::AsymmetricInfo,
                ],
                severity: SecuritySeverity::Medium,
                location: 0,
                description: "Peg deviation risk: oracle price lag without active defense".to_string(),
                economic_model: "Oracle-dependent pricing without stabilization mechanisms".to_string(),
                attack_vector: "Exploit oracle lag to trade against stale prices".to_string(),
                manipulation_cost: Some(50000.0),
                time_window: Some(300),
                detection_confidence: 0.70,
                affected_functions: self.oracle_functions.iter().cloned().collect(),
                economic_invariants: vec![
                    "abs(price - peg) <= max_deviation".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_market_manipulation_risks(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_large_trade_protection = self.analyze_trade_size_limits();

        if !has_large_trade_protection {
            vulnerabilities.push(EconomicVulnerability {
                attack_type: EconomicAttack::MarketManipulation,
                conditions: vec![
                    EconomicCondition::LowLiquidity,
                    EconomicCondition::AsymmetricInfo,
                ],
                severity: SecuritySeverity::Medium,
                location: 0,
                description: "Market manipulation risk: no limits on large trades".to_string(),
                economic_model: "Unrestricted trade sizes in low liquidity environment".to_string(),
                attack_vector: "Use large trades to manipulate prices significantly".to_string(),
                manipulation_cost: Some(1000000.0),
                time_window: Some(600),
                detection_confidence: 0.85,
                affected_functions: self.swap_functions.iter().cloned().collect(),
                economic_invariants: vec![
                    "single_trade_impact < max_price_impact".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    // Helper methods
    fn has_function_signatures(&self, signatures: &HashSet<[u8; 4]>) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            if signatures.contains(&sig) {
                return true;
            }
        }
        false
    }

    fn get_mint_burn_selectors(&self) -> Vec<[u8; 4]> {
        self.mint_functions.union(&self.burn_functions).cloned().collect()
    }

    fn analyze_confidence_mechanisms(&self) -> bool {
        // Look for confidence-related patterns like backstop funds
        self.has_emergency_functions()
    }

    fn analyze_withdrawal_limits(&self) -> bool {
        // Look for rate limiting patterns in withdrawal functions
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for time-based checks (TIMESTAMP, delay patterns)
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 5 < self.bytecode.len() && 
               (self.bytecode[i + 5] == 0x10 || self.bytecode[i + 5] == 0x11) { // LT/GT
                return true;
            }
        }
        false
    }

    fn analyze_emergency_liquidity(&self) -> bool {
        self.has_emergency_functions()
    }

    fn analyze_peg_defense_mechanisms(&self) -> bool {
        // Look for automatic peg defense mechanisms
        let peg_defense_sigs = [
            [0x8d, 0xa5, 0xcb, 0x5b], // Generic defense function
            [0x2e, 0x1a, 0x7d, 0x4d], // Rebalance function
        ];
        
        for sig in &peg_defense_sigs {
            if self.has_function_signature(sig) {
                return true;
            }
        }
        false
    }

    fn analyze_trade_size_limits(&self) -> bool {
        // Look for max trade size patterns
        for i in 0..self.bytecode.len().saturating_sub(8) {
            // Look for amount checks before trades
            if self.bytecode[i] == 0x11 && // GT comparison
               i + 3 < self.bytecode.len() && self.bytecode[i + 3] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_emergency_functions(&self) -> bool {
        let emergency_sigs = [
            [0x8b, 0x78, 0xc6, 0xd8], // pause()
            [0x3f, 0x4b, 0xa8, 0x3a], // emergencyStop()
        ];
        
        for sig in &emergency_sigs {
            if self.has_function_signature(sig) {
                return true;
            }
        }
        false
    }

    fn has_function_signature(&self, signature: &[u8; 4]) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            if sig == *signature {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_death_spiral_detection() {
        let bytecode_with_mint_burn = vec![
            // Some padding to make signatures findable
            0x60, 0x80, 0x60, 0x40,
            // mint() signature
            0x40, 0xc1, 0x0f, 0x19,
            // More padding
            0x52, 0x60, 0x04, 0x36,
            // burn() signature  
            0x42, 0x96, 0x6c, 0x68,
            // More padding to separate from any potential emergency sigs
            0x10, 0x15, 0x61, 0x02,
        ];

        let analyzer = EconomicAttackAnalyzer::new(bytecode_with_mint_burn);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, EconomicAttack::DeathSpiral)));
    }

    #[test]
    fn test_bank_run_detection() {
        let bytecode_with_redeem = vec![
            // redeem() signature
            0xdb, 0x00, 0x6a, 0x75,
            // No rate limiting patterns
        ];

        let analyzer = EconomicAttackAnalyzer::new(bytecode_with_redeem);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        let bank_run_vuln = vulnerabilities.iter()
            .find(|v| matches!(v.attack_type, EconomicAttack::BankRun));
        assert!(bank_run_vuln.is_some());
    }

    #[test]
    fn test_oracle_lag_detection() {
        let bytecode_with_oracle = vec![
            // latestAnswer() signature
            0x50, 0xd2, 0x5b, 0xcd,
            // No peg defense mechanisms
        ];

        let analyzer = EconomicAttackAnalyzer::new(bytecode_with_oracle);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        let peg_vuln = vulnerabilities.iter()
            .find(|v| matches!(v.attack_type, EconomicAttack::PegDeviation));
        assert!(peg_vuln.is_some());
    }
}
