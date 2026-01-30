/// Economic Model Validator
/// Validates that protocol economic models are sound and resistant to manipulation
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct EconomicModelValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EconomicVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub description: String,
    pub potential_loss: f64,
    pub severity: SecuritySeverity,
}

impl EconomicModelValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_economic_model(&self) -> Vec<EconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for inflation vulnerabilities
        vulnerabilities.extend(self.check_inflation_resistance());
        
        // Check for deflation spirals
        vulnerabilities.extend(self.check_deflation_risks());
        
        // Check for economic exploits
        vulnerabilities.extend(self.check_economic_exploits());
        
        // Check for incentive misalignment
        vulnerabilities.extend(self.check_incentive_alignment());

        vulnerabilities
    }

    fn check_inflation_resistance(&self) -> Vec<EconomicVulnerability> {
        let mut vulns = Vec::new();

        // Check for unbounded minting
        if self.has_unbounded_mint() {
            vulns.push(EconomicVulnerability {
                vulnerability_type: "Unbounded Inflation".to_string(),
                location: 0,
                description: "Token supply can be inflated without limit".to_string(),
                potential_loss: 1000000.0,
                severity: SecuritySeverity::Critical,
            });
        }

        vulns
    }

    fn check_deflation_risks(&self) -> Vec<EconomicVulnerability> {
        let mut risks = Vec::new();

        // Check for burn without limits
        if self.has_uncontrolled_burn() {
            risks.push(EconomicVulnerability {
                vulnerability_type: "Deflation Spiral".to_string(),
                location: 0,
                description: "Excessive burning can cause deflation spiral".to_string(),
                potential_loss: 500000.0,
                severity: SecuritySeverity::High,
            });
        }

        risks
    }

    fn check_economic_exploits(&self) -> Vec<EconomicVulnerability> {
        let mut exploits = Vec::new();

        // Check for arbitrage vulnerabilities
        if self.has_arbitrage_opportunity() {
            exploits.push(EconomicVulnerability {
                vulnerability_type: "Arbitrage Exploit".to_string(),
                location: 0,
                description: "Price discrepancies enable risk-free arbitrage".to_string(),
                potential_loss: 250000.0,
                severity: SecuritySeverity::High,
            });
        }

        exploits
    }

    fn check_incentive_alignment(&self) -> Vec<EconomicVulnerability> {
        let mut issues = Vec::new();

        // Check for misaligned incentives
        if self.has_misaligned_incentives() {
            issues.push(EconomicVulnerability {
                vulnerability_type: "Incentive Misalignment".to_string(),
                location: 0,
                description: "Economic incentives misaligned with protocol goals".to_string(),
                potential_loss: 100000.0,
                severity: SecuritySeverity::Medium,
            });
        }

        issues
    }

    fn has_unbounded_mint(&self) -> bool {
        // Mint function without supply cap check
        let has_mint = self.bytecode.windows(4).any(|w| w == &[0x60, 0x00, 0x60, 0x00]); // PUSH 0 twice
        let has_supply_check = self.bytecode.contains(&0x11); // GT opcode for comparison
        
        has_mint && !has_supply_check
    }

    fn has_uncontrolled_burn(&self) -> bool {
        // Burn without minimum supply check
        self.bytecode.contains(&0x03) && // SUB (reduce supply)
        !self.bytecode.contains(&0x10) // LT (check minimum)
    }

    fn has_arbitrage_opportunity(&self) -> bool {
        // Multiple price sources without arbitrage check
        let price_reads = self.bytecode.iter().filter(|&&b| b == 0x54).count(); // SLOAD
        price_reads > 2
    }

    fn has_misaligned_incentives(&self) -> bool {
        // Rewards that don't align with desired behavior
        let has_reward = self.bytecode.contains(&0xf1); // CALL (transfer reward)
        let has_validation = self.bytecode.contains(&0x57); // JUMPI (condition check)
        
        has_reward && !has_validation
    }

    pub fn calculate_economic_risk_score(&self) -> f64 {
        let vulns = self.validate_economic_model();
        let critical_count = vulns.iter().filter(|v| matches!(v.severity, SecuritySeverity::Critical)).count();
        let high_count = vulns.iter().filter(|v| matches!(v.severity, SecuritySeverity::High)).count();
        
        (critical_count as f64 * 1.0) + (high_count as f64 * 0.5)
    }
}
