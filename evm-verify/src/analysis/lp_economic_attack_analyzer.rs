use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LPAttackType {
    LiquidityProviderTokenManipulation,
    ImpermanentLossAmplification,
    LPRewardExploitation,
    LiquidityMigrationAttack,
    YieldFarmingManipulation,
    LPTokenFlashLoanAttack,
    EmergencyWithdrawalExploit,
    LiquidityConcentrationAttack,
    MEVLiquidityExtraction,
    CrossPoolArbitrageManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LPEconomicVulnerability {
    pub attack_type: LPAttackType,
    pub severity: SecuritySeverity,
    pub target_pool: String,
    pub attack_cost_eth: f64,
    pub potential_profit_eth: f64,
    pub liquidity_impact_percent: f32,
    pub execution_window_seconds: u64,
    pub success_probability: f32,
    pub detection_confidence: f32,
    pub affected_lp_count: u32,
    pub mitigation_strategies: Vec<String>,
    pub attack_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPoolMetrics {
    pub total_liquidity_usd: f64,
    pub lp_token_supply: f64,
    pub average_lp_position_size: f64,
    pub concentration_ratio: f32, // Top 10 LP concentration
    pub daily_volume_to_liquidity: f32,
    pub impermanent_loss_risk: f32,
    pub withdrawal_fee_percentage: f32,
    pub lock_period_days: u32,
}

pub struct LPEconomicAttackAnalyzer {
    bytecode: Vec<u8>,
    lp_functions: HashSet<[u8; 4]>,
    staking_functions: HashSet<[u8; 4]>,
    reward_functions: HashSet<[u8; 4]>,
    emergency_functions: HashSet<[u8; 4]>,
    execution_trace: Option<EVMExecutionTrace>,
    pool_metrics: LiquidityPoolMetrics,
}

impl LPEconomicAttackAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut lp_functions = HashSet::new();
        lp_functions.insert([0xe8, 0xe3, 0x37, 0x00]); // addLiquidity()
        lp_functions.insert([0xf3, 0x05, 0xd7, 0x19]); // addLiquidityETH()
        lp_functions.insert([0xba, 0xc2, 0x78, 0x08]); // removeLiquidity()
        lp_functions.insert([0x02, 0x75, 0x1c, 0xec]); // removeLiquidityETH()

        let mut staking_functions = HashSet::new();
        staking_functions.insert([0xa6, 0x94, 0xfc, 0x3a]); // stake()
        staking_functions.insert([0x2e, 0x1a, 0x7d, 0x4d]); // unstake()
        staking_functions.insert([0x38, 0xd0, 0x7a, 0x36]); // withdraw()

        let mut reward_functions = HashSet::new();
        reward_functions.insert([0x3d, 0x18, 0xb9, 0x12]); // getReward()
        reward_functions.insert([0xe9, 0xfb, 0x1e, 0x72]); // claimRewards()
        reward_functions.insert([0x81, 0x2b, 0x52, 0x2e]); // harvestRewards()

        let mut emergency_functions = HashSet::new();
        emergency_functions.insert([0x5c, 0x97, 0x5a, 0xbb]); // emergencyWithdraw()
        emergency_functions.insert([0x8d, 0xa5, 0xcb, 0x5b]); // pause()

        Self {
            bytecode,
            lp_functions,
            staking_functions,  
            reward_functions,
            emergency_functions,
            execution_trace: None,
            pool_metrics: LiquidityPoolMetrics {
                total_liquidity_usd: 1_000_000.0, // Default values
                lp_token_supply: 1000.0,
                average_lp_position_size: 1000.0,
                concentration_ratio: 0.5,
                daily_volume_to_liquidity: 0.1,
                impermanent_loss_risk: 0.3,
                withdrawal_fee_percentage: 0.5,
                lock_period_days: 0,
            },
        }
    }

    pub fn with_pool_metrics(mut self, metrics: LiquidityPoolMetrics) -> Self {
        self.pool_metrics = metrics;
        self
    }

    pub fn with_execution_trace(mut self, trace: EVMExecutionTrace) -> Self {
        self.execution_trace = Some(trace);
        self
    }

    pub fn analyze_lp_economic_attacks(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_lp_token_manipulation());
        vulnerabilities.extend(self.detect_impermanent_loss_amplification());
        vulnerabilities.extend(self.detect_liquidity_migration_attacks());
        vulnerabilities.extend(self.detect_yield_farming_manipulation());
        vulnerabilities.extend(self.detect_lp_flash_loan_attacks());
        vulnerabilities.extend(self.detect_liquidity_concentration_risks());
        vulnerabilities.extend(self.detect_mev_liquidity_extraction());

        vulnerabilities
    }

    fn detect_lp_token_manipulation(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_transferable_lp_tokens() && self.lacks_lp_protection() {
            let manipulation_profit = self.calculate_lp_manipulation_profit();
            let manipulation_cost = self.pool_metrics.total_liquidity_usd * 0.001; // 0.1% of pool

            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::LiquidityProviderTokenManipulation,
                severity: SecuritySeverity::High,
                target_pool: "Primary Liquidity Pool".to_string(),
                attack_cost_eth: manipulation_cost,
                potential_profit_eth: manipulation_profit,
                liquidity_impact_percent: 15.0,
                execution_window_seconds: 3600, // 1 hour manipulation window
                success_probability: 0.7,
                detection_confidence: 0.85,
                affected_lp_count: (self.pool_metrics.lp_token_supply as u32 / 10).max(1),
                mitigation_strategies: vec![
                    "Implement LP token transfer restrictions".to_string(),
                    "Add time-weighted LP calculations".to_string(),
                    "Use non-transferable LP positions".to_string(),
                ],
                attack_description: "Manipulate LP token pricing through coordinated trades".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_impermanent_loss_amplification(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.pool_metrics.impermanent_loss_risk > 0.5 && self.lacks_il_protection() {
            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::ImpermanentLossAmplification,
                severity: SecuritySeverity::Medium,
                target_pool: "High IL Risk Pool".to_string(),
                attack_cost_eth: 10_000.0,
                potential_profit_eth: 50_000.0,
                liquidity_impact_percent: 25.0,
                execution_window_seconds: 86400, // 24 hour amplification window
                success_probability: 0.6,
                detection_confidence: 0.8,
                affected_lp_count: (self.pool_metrics.lp_token_supply as f64 * 0.8) as u32,
                mitigation_strategies: vec![
                    "Implement impermanent loss protection".to_string(),
                    "Add dynamic fee adjustments".to_string(),
                    "Use concentrated liquidity ranges".to_string(),
                ],
                attack_description: "Amplify impermanent loss through coordinated price movements".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_liquidity_migration_attacks(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.pool_metrics.concentration_ratio > 0.7 && self.lacks_migration_protection() {
            let migration_impact = self.pool_metrics.total_liquidity_usd * 0.7; // 70% could migrate

            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::LiquidityMigrationAttack,
                severity: SecuritySeverity::Critical,
                target_pool: "Concentrated Liquidity Pool".to_string(),
                attack_cost_eth: 1_000.0, // Coordination cost
                potential_profit_eth: migration_impact * 0.02, // 2% of migrated liquidity
                liquidity_impact_percent: 70.0,
                execution_window_seconds: 7200, // 2 hour coordination window
                success_probability: 0.8,
                detection_confidence: 0.9,
                affected_lp_count: (self.pool_metrics.lp_token_supply as f64 * 0.1) as u32, // Top 10% LPs
                mitigation_strategies: vec![
                    "Implement gradual withdrawal limits".to_string(),
                    "Add exit fee structures".to_string(),
                    "Diversify LP base".to_string(),
                ],
                attack_description: "Coordinate mass LP withdrawal to destabilize pool".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_yield_farming_manipulation(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_yield_farming() && self.lacks_farming_protection() {
            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::YieldFarmingManipulation,
                severity: SecuritySeverity::High,
                target_pool: "Yield Farm Pool".to_string(),
                attack_cost_eth: 5_000.0,
                potential_profit_eth: 25_000.0,
                liquidity_impact_percent: 20.0,
                execution_window_seconds: 43200, // 12 hour farming cycle
                success_probability: 0.65,
                detection_confidence: 0.75,
                affected_lp_count: (self.pool_metrics.lp_token_supply as f64 * 0.5) as u32,
                mitigation_strategies: vec![
                    "Implement anti-gaming measures".to_string(),
                    "Use time-weighted reward calculations".to_string(),
                    "Add minimum staking periods".to_string(),
                ],
                attack_description: "Manipulate yield farming rewards through timing attacks".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_lp_flash_loan_attacks(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_flash_loan_vulnerable_lp_tokens() {
            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::LPTokenFlashLoanAttack,
                severity: SecuritySeverity::Critical,
                target_pool: "Flash Loan Vulnerable Pool".to_string(),
                attack_cost_eth: 100.0, // Flash loan fee
                potential_profit_eth: 100_000.0,
                liquidity_impact_percent: 50.0,
                execution_window_seconds: 15, // Single block attack
                success_probability: 0.9,
                detection_confidence: 0.95,
                affected_lp_count: (self.pool_metrics.lp_token_supply as u32) as u32,
                mitigation_strategies: vec![
                    "Implement flash loan protection".to_string(),
                    "Add same-block restrictions".to_string(),
                    "Use time-delayed LP calculations".to_string(),
                ],
                attack_description: "Flash loan LP tokens to manipulate pool rewards or governance".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_liquidity_concentration_risks(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.pool_metrics.concentration_ratio > 0.8 {
            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::LiquidityConcentrationAttack,
                severity: SecuritySeverity::High,
                target_pool: "Highly Concentrated Pool".to_string(),
                attack_cost_eth: self.pool_metrics.total_liquidity_usd * 0.4, // Need 40% control
                potential_profit_eth: self.pool_metrics.total_liquidity_usd * 0.1, // 10% extraction
                liquidity_impact_percent: 80.0,
                execution_window_seconds: 1800, // 30 minute control window
                success_probability: 0.75,
                detection_confidence: 0.9,
                affected_lp_count: (self.pool_metrics.lp_token_supply as f64 * 0.9) as u32,
                mitigation_strategies: vec![
                    "Implement LP concentration limits".to_string(),
                    "Add progressive withdrawal fees".to_string(),
                    "Incentivize LP diversification".to_string(),
                ],
                attack_description: "Control large portion of liquidity to manipulate pool dynamics".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_mev_liquidity_extraction(&self) -> Vec<LPEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.pool_metrics.daily_volume_to_liquidity > 0.5 && self.lacks_mev_protection() {
            let daily_mev_extraction = self.pool_metrics.total_liquidity_usd * 
                                      self.pool_metrics.daily_volume_to_liquidity as f64 * 0.003; // 0.3% MEV tax

            vulnerabilities.push(LPEconomicVulnerability {
                attack_type: LPAttackType::MEVLiquidityExtraction,
                severity: SecuritySeverity::Medium,
                target_pool: "High Volume Pool".to_string(),
                attack_cost_eth: 50.0, // MEV bot operational cost
                potential_profit_eth: daily_mev_extraction,
                liquidity_impact_percent: 5.0, // Gradual impact
                execution_window_seconds: 86400, // Daily extraction
                success_probability: 0.95,
                detection_confidence: 0.85,
                affected_lp_count: (self.pool_metrics.lp_token_supply as u32) as u32,
                mitigation_strategies: vec![
                    "Implement MEV protection mechanisms".to_string(),
                    "Add batch auction systems".to_string(),
                    "Use commit-reveal schemes".to_string(),
                ],
                attack_description: "Extract MEV from high-volume LP pools through sandwich attacks".to_string(),
            });
        }

        vulnerabilities
    }

    // Helper methods
    fn has_transferable_lp_tokens(&self) -> bool {
        let erc20_functions = [
            [0xa9, 0x05, 0x9c, 0xbb], // transfer()
            [0x23, 0xb8, 0x72, 0xdd], // transferFrom()
        ];
        erc20_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_lp_protection(&self) -> bool {
        // Look for LP protection mechanisms
        let protection_functions = [
            [0xc8, 0x9c, 0x2a, 0x78], // lockLP()
            [0xd4, 0x5e, 0x23, 0x91], // vestedLP()
        ];
        !protection_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_il_protection(&self) -> bool {
        let il_protection_functions = [
            [0x7b, 0x15, 0x47, 0x2e], // protectIL()
            [0xa2, 0x34, 0x8d, 0x5f], // compensateIL()
        ];
        !il_protection_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_migration_protection(&self) -> bool {
        // Check for exit fee or withdrawal limit mechanisms
        let migration_protection = [
            [0x54, 0x78, 0x23, 0xcd], // exitFee()
            [0x8f, 0x45, 0x12, 0x9a], // withdrawalLimit()
        ];
        !migration_protection.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_yield_farming(&self) -> bool {
        self.staking_functions.iter().any(|sig| self.has_function_signature(sig)) ||
        self.reward_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_farming_protection(&self) -> bool {
        let farming_protection = [
            [0x6c, 0x54, 0x89, 0x12], // stakingDelay()
            [0x9f, 0x21, 0x45, 0x8a], // antiGameMechanism()
        ];
        !farming_protection.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_flash_loan_vulnerable_lp_tokens(&self) -> bool {
        // If LP tokens are transferable and can be used immediately
        self.has_transferable_lp_tokens() && 
        !self.has_time_delays() &&
        self.pool_metrics.lock_period_days == 0
    }

    fn lacks_mev_protection(&self) -> bool {
        let mev_protection = [
            [0xa8, 0x76, 0x54, 0x23], // commitReveal()
            [0xc2, 0x19, 0x87, 0x4f], // batchAuction()
        ];
        !mev_protection.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_time_delays(&self) -> bool {
        // Look for time delay patterns in bytecode
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 5 < self.bytecode.len() && 
               self.bytecode[i + 5] == 0x01 { // ADD (timestamp + delay)
                return true;
            }
        }
        false
    }

    fn calculate_lp_manipulation_profit(&self) -> f64 {
        // Simplified profit calculation based on pool size and concentration
        let base_profit = self.pool_metrics.total_liquidity_usd * 0.01; // 1% base extraction
        let concentration_multiplier = self.pool_metrics.concentration_ratio as f64;
        base_profit * (1.0 + concentration_multiplier)
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
    fn test_lp_token_manipulation_detection() {
        let bytecode = vec![
            // transfer() signature
            0xa9, 0x05, 0x9c, 0xbb,
            // addLiquidity() signature
            0xe8, 0xe3, 0x37, 0x00,
        ];

        let analyzer = LPEconomicAttackAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.analyze_lp_economic_attacks();

        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, LPAttackType::LiquidityProviderTokenManipulation)));
    }

    #[test]
    fn test_flash_loan_lp_attack_detection() {
        let bytecode = vec![
            // Transferable LP tokens without time delays
            0xa9, 0x05, 0x9c, 0xbb, // transfer()
            0x23, 0xb8, 0x72, 0xdd, // transferFrom()
            0xe8, 0xe3, 0x37, 0x00, // addLiquidity()
        ];

        let pool_metrics = LiquidityPoolMetrics {
            total_liquidity_usd: 1_000_000.0,
            lp_token_supply: 1000.0,
            average_lp_position_size: 1000.0,
            concentration_ratio: 0.5,
            daily_volume_to_liquidity: 0.1,
            impermanent_loss_risk: 0.3,
            withdrawal_fee_percentage: 0.0,
            lock_period_days: 0, // No lock period = vulnerable
        };

        let analyzer = LPEconomicAttackAnalyzer::new(bytecode).with_pool_metrics(pool_metrics);
        let vulnerabilities = analyzer.analyze_lp_economic_attacks();

        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, LPAttackType::LPTokenFlashLoanAttack)));
    }
}
