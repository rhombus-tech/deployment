/// Attack Cost Calculator
/// Calculates economic feasibility of exploits including gas costs and capital requirements
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct AttackCostCalculator {
    bytecode: Vec<u8>,
    gas_price_gwei: u64,
    eth_price_usd: f64,
}

#[derive(Debug, Clone)]
pub struct AttackCost {
    pub vulnerability_type: String,
    pub gas_cost: u64,
    pub gas_cost_eth: f64,
    pub gas_cost_usd: f64,
    pub capital_required_eth: f64,
    pub capital_required_usd: f64,
    pub total_cost_usd: f64,
    pub expected_profit_usd: f64,
    pub profit_margin: f64,
    pub is_profitable: bool,
}

impl AttackCostCalculator {
    pub fn new(bytecode: Vec<u8>, gas_price_gwei: u64, eth_price_usd: f64) -> Self {
        Self {
            bytecode,
            gas_price_gwei,
            eth_price_usd,
        }
    }

    pub fn calculate_attack_cost(&self, vuln_type: &str, target_tvl_usd: f64) -> AttackCost {
        match vuln_type {
            "Reentrancy" => self.calculate_reentrancy_cost(target_tvl_usd),
            "Flash Loan Attack" => self.calculate_flash_loan_cost(target_tvl_usd),
            "Price Manipulation" => self.calculate_price_manipulation_cost(target_tvl_usd),
            "Integer Overflow" => self.calculate_overflow_cost(target_tvl_usd),
            "Oracle Manipulation" => self.calculate_oracle_manipulation_cost(target_tvl_usd),
            _ => self.calculate_generic_attack_cost(vuln_type, target_tvl_usd),
        }
    }

    fn calculate_reentrancy_cost(&self, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 300_000u64; // Deploy + attack
        let capital_required_eth = 1.0; // Initial deposit
        
        self.build_attack_cost(
            "Reentrancy",
            gas_cost,
            capital_required_eth,
            target_tvl_usd * 0.5, // Expect to drain 50%
        )
    }

    fn calculate_flash_loan_cost(&self, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 500_000u64; // Flash loan + operations
        let flash_loan_fee = target_tvl_usd * 0.0009; // 0.09% Aave fee
        let capital_required_usd = flash_loan_fee;
        
        AttackCost {
            vulnerability_type: "Flash Loan Attack".to_string(),
            gas_cost,
            gas_cost_eth: self.gas_to_eth(gas_cost),
            gas_cost_usd: self.gas_to_usd(gas_cost),
            capital_required_eth: capital_required_usd / self.eth_price_usd,
            capital_required_usd,
            total_cost_usd: self.gas_to_usd(gas_cost) + capital_required_usd,
            expected_profit_usd: target_tvl_usd * 0.1, // 10% extraction
            profit_margin: self.calculate_profit_margin(
                self.gas_to_usd(gas_cost) + capital_required_usd,
                target_tvl_usd * 0.1,
            ),
            is_profitable: (target_tvl_usd * 0.1) > (self.gas_to_usd(gas_cost) + capital_required_usd),
        }
    }

    fn calculate_price_manipulation_cost(&self, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 800_000u64; // Multiple swaps
        // Need significant capital to move price
        let capital_required_eth = (target_tvl_usd * 0.3) / self.eth_price_usd;
        
        self.build_attack_cost(
            "Price Manipulation",
            gas_cost,
            capital_required_eth,
            target_tvl_usd * 0.05, // 5% profit from arbitrage
        )
    }

    fn calculate_overflow_cost(&self, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 200_000u64; // Single transaction
        let capital_required_eth = 0.1; // Minimal capital
        
        self.build_attack_cost(
            "Integer Overflow",
            gas_cost,
            capital_required_eth,
            target_tvl_usd * 0.8, // Can potentially drain everything
        )
    }

    fn calculate_oracle_manipulation_cost(&self, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 1_000_000u64; // Complex multi-step attack
        let capital_required_eth = (target_tvl_usd * 0.5) / self.eth_price_usd; // Large capital
        
        self.build_attack_cost(
            "Oracle Manipulation",
            gas_cost,
            capital_required_eth,
            target_tvl_usd * 0.2, // 20% extraction
        )
    }

    fn calculate_generic_attack_cost(&self, vuln_type: &str, target_tvl_usd: f64) -> AttackCost {
        let gas_cost = 400_000u64;
        let capital_required_eth = 0.5;
        
        self.build_attack_cost(
            vuln_type,
            gas_cost,
            capital_required_eth,
            target_tvl_usd * 0.1,
        )
    }

    fn build_attack_cost(
        &self,
        vuln_type: &str,
        gas_cost: u64,
        capital_required_eth: f64,
        expected_profit_usd: f64,
    ) -> AttackCost {
        let gas_cost_eth = self.gas_to_eth(gas_cost);
        let gas_cost_usd = gas_cost_eth * self.eth_price_usd;
        let capital_required_usd = capital_required_eth * self.eth_price_usd;
        let total_cost_usd = gas_cost_usd + capital_required_usd;
        
        AttackCost {
            vulnerability_type: vuln_type.to_string(),
            gas_cost,
            gas_cost_eth,
            gas_cost_usd,
            capital_required_eth,
            capital_required_usd,
            total_cost_usd,
            expected_profit_usd,
            profit_margin: self.calculate_profit_margin(total_cost_usd, expected_profit_usd),
            is_profitable: expected_profit_usd > total_cost_usd,
        }
    }

    fn gas_to_eth(&self, gas: u64) -> f64 {
        (gas as f64 * self.gas_price_gwei as f64) / 1_000_000_000.0
    }

    fn gas_to_usd(&self, gas: u64) -> f64 {
        self.gas_to_eth(gas) * self.eth_price_usd
    }

    fn calculate_profit_margin(&self, cost: f64, profit: f64) -> f64 {
        if cost == 0.0 {
            return 0.0;
        }
        ((profit - cost) / cost) * 100.0
    }

    pub fn get_profitable_attacks(&self, vulnerabilities: &[(String, f64)]) -> Vec<AttackCost> {
        vulnerabilities
            .iter()
            .map(|(vuln_type, tvl)| self.calculate_attack_cost(vuln_type, *tvl))
            .filter(|cost| cost.is_profitable)
            .collect()
    }

    pub fn calculate_roi(&self, cost: &AttackCost) -> f64 {
        if cost.total_cost_usd == 0.0 {
            return 0.0;
        }
        ((cost.expected_profit_usd - cost.total_cost_usd) / cost.total_cost_usd) * 100.0
    }

    pub fn get_minimum_profitable_tvl(&self, vuln_type: &str) -> f64 {
        // Binary search for minimum TVL where attack becomes profitable
        let mut low = 1000.0;
        let mut high = 10_000_000.0;
        
        while high - low > 100.0 {
            let mid = (low + high) / 2.0;
            let cost = self.calculate_attack_cost(vuln_type, mid);
            
            if cost.is_profitable {
                high = mid;
            } else {
                low = mid;
            }
        }
        
        high
    }
}
