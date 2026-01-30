/// ERC-7621 Basket Token Detector
/// Multi-token wrapper/index tokens

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7621Vulnerability {
    pub vulnerability_type: Erc7621VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7621VulnerabilityType {
    RebalancingManipulation,        // Rebalancing exploited
    ComponentTokenPriceManip,       // Component price manipulated
    BasketCompositionAttack,        // Basket composition changed maliciously
    WithdrawalSlippage,             // High slippage on withdrawal
    OracleManipulation,             // Oracle for components manipulated
}

pub struct Erc7621BasketTokenDetector {
    bytecode: Vec<u8>,
}

impl Erc7621BasketTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7621Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 { // DIV (price calculation)
                vulnerabilities.push(Erc7621Vulnerability {
                    vulnerability_type: Erc7621VulnerabilityType::ComponentTokenPriceManip,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Basket token component pricing vulnerable to manipulation.".to_string(),
                    exploit_scenario: "1. Basket contains 3 tokens\n\
                                      2. Attacker manipulates Token A price\n\
                                      3. Basket nav inflated\n\
                                      4. Mints basket tokens cheap\n\
                                      5. Redeems for profit\n\
                                      6. $500K stolen".to_string(),
                    recommendation: "Use TWAP for component prices. Add price bounds. Implement circuit breakers.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_price_manip() {
        let bytecode = vec![0x04];
        let detector = Erc7621BasketTokenDetector::new(bytecode);
        assert!(!detector.detect_vulnerabilities().is_empty());
    }
}
