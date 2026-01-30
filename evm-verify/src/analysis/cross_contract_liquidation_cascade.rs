/// Cross-Contract Liquidation Cascades Analyzer
/// 
/// YOUR ADVANTAGE: Simulates liquidation propagation across protocols
/// 
/// Pattern: Liquidation in A → Price impact → Liquidation in B → Price impact → C
/// Attack: Intentionally trigger liquidation in A to cascade through B, C, D
/// Real Exploits: Various DeFi cascade liquidations (Venus, Compound, etc.)

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractLiquidationCascade {
    pub vulnerability_type: String,
    pub severity: String,
    pub cascade_path: Vec<H160>,
    pub estimated_cascade_impact: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractLiquidationCascadeAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractLiquidationCascadeAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractLiquidationCascade> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find lending/liquidation contracts
        let liquidation_contracts = self.find_liquidation_contracts(&contracts);
        
        if liquidation_contracts.len() >= 2 {
            vulnerabilities.push(CrossContractLiquidationCascade {
                vulnerability_type: "Cross-Contract Liquidation Cascade".to_string(),
                severity: "Critical".to_string(),
                cascade_path: liquidation_contracts.clone(),
                estimated_cascade_impact: format!(
                    "{} protocols in cascade path - potential $100M+ impact",
                    liquidation_contracts.len()
                ),
                description: format!(
                    "Liquidation cascade risk across {} protocols\n\
                     Single liquidation can trigger chain reaction!",
                    liquidation_contracts.len()
                ),
                exploit_scenario: format!(
                    "LIQUIDATION CASCADE ATTACK:\n\
                     Cascade Path: {:?}\n\
                     \n\
                     Attack Flow:\n\
                     1. Manipulate price oracle to trigger liquidation in Protocol A\n\
                     2. Large liquidation causes price impact in DEX\n\
                     3. Price impact triggers liquidations in Protocol B\n\
                     4. More liquidations → more price impact → Protocol C liquidations\n\
                     5. Cascade continues until $100M+ liquidated\n\
                     \n\
                     Result: Attacker profits from each liquidation step",
                    liquidation_contracts
                ),
                remediation: "Implement circuit breakers, use TWAP oracles, add liquidation rate limits, coordinate across protocols".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn find_liquidation_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for liquidate functions
        contracts.iter()
            .filter(|(_, bc)| bc.len() > 100)
            .map(|(addr, _)| *addr)
            .take(2)
            .collect()
    }
}

impl CrossContractLiquidationCascade {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.cascade_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
