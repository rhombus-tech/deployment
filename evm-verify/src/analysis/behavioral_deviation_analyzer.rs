/// Behavioral Deviation Analyzer
/// Detects contracts that behave differently than expected for their type
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct BehavioralDeviationAnalyzer {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BehavioralDeviation {
    pub contract_type: String,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub deviation_score: f32,
    pub severity: SecuritySeverity,
}

impl BehavioralDeviationAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze_deviations(&self) -> Vec<BehavioralDeviation> {
        let mut deviations = Vec::new();

        // Identify contract type
        let contract_type = self.identify_contract_type();

        // Check if behavior matches expectations
        match contract_type.as_str() {
            "ERC20" => deviations.extend(self.check_erc20_deviations()),
            "ERC721" => deviations.extend(self.check_erc721_deviations()),
            "Vault" => deviations.extend(self.check_vault_deviations()),
            "DEX" => deviations.extend(self.check_dex_deviations()),
            _ => {}
        }

        deviations
    }

    fn identify_contract_type(&self) -> String {
        // Identify based on function selectors
        if self.has_selector(&[0x70, 0xa0, 0x82, 0x31]) { // balanceOf
            if self.has_selector(&[0xa9, 0x05, 0x9c, 0xbb]) { // transfer
                return "ERC20".to_string();
            }
        }
        "Unknown".to_string()
    }

    fn has_selector(&self, selector: &[u8]) -> bool {
        self.bytecode.windows(4).any(|w| w == selector)
    }

    fn check_erc20_deviations(&self) -> Vec<BehavioralDeviation> {
        let mut deviations = Vec::new();

        // ERC20 should emit Transfer events
        if !self.has_transfer_event() {
            deviations.push(BehavioralDeviation {
                contract_type: "ERC20".to_string(),
                expected_behavior: "Emit Transfer events".to_string(),
                actual_behavior: "No Transfer events found".to_string(),
                deviation_score: 0.85,
                severity: SecuritySeverity::High,
            });
        }

        deviations
    }

    fn check_erc721_deviations(&self) -> Vec<BehavioralDeviation> {
        Vec::new() // Placeholder
    }

    fn check_vault_deviations(&self) -> Vec<BehavioralDeviation> {
        Vec::new() // Placeholder
    }

    fn check_dex_deviations(&self) -> Vec<BehavioralDeviation> {
        Vec::new() // Placeholder
    }

    fn has_transfer_event(&self) -> bool {
        // Look for LOG opcode (0xa0-0xa4)
        self.bytecode.iter().any(|&b| (0xa0..=0xa4).contains(&b))
    }

    pub fn calculate_trust_score(&self) -> f32 {
        // Higher score = more trustworthy (behaves as expected)
        let deviations = self.analyze_deviations();
        let avg_deviation = deviations.iter()
            .map(|d| d.deviation_score)
            .sum::<f32>() / (deviations.len() as f32).max(1.0);
        
        1.0 - avg_deviation
    }
}
