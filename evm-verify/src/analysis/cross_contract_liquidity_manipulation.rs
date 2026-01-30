/// Cross-Contract Liquidity Manipulation Analyzer
/// 
/// YOUR ADVANTAGE: Detects liquidity removal affecting dependent protocols
/// 
/// Attack: DEX.removeLiquidity() → Price changes → Vault marks down → Liquidations cascade

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractLiquidityManipulation {
    pub vulnerability_type: String,
    pub severity: String,
    pub manipulation_path: Vec<H160>,
    pub liquidity_source: H160,
    pub price_dependents: Vec<H160>,
    pub cascading_effects: Vec<String>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractLiquidityManipulationAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractLiquidityManipulationAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractLiquidityManipulation> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find liquidity pools
        let liquidity_pools = self.find_liquidity_pools(&contracts);
        
        // Find contracts that depend on pool prices
        for pool in liquidity_pools {
            let dependents = self.find_price_dependents(pool, &contracts);
            
            if !dependents.is_empty() {
                let cascading = self.analyze_cascading_effects(&dependents, &contracts);
                
                vulnerabilities.push(CrossContractLiquidityManipulation {
                    vulnerability_type: "Cross-Contract Liquidity Manipulation".to_string(),
                    severity: "Critical".to_string(),
                    manipulation_path: vec![pool],
                    liquidity_source: pool,
                    price_dependents: dependents.clone(),
                    cascading_effects: cascading.clone(),
                    description: format!(
                        "Liquidity pool {:?} affects {} contracts. \
                         Removing liquidity can trigger cascading liquidations!",
                        pool, dependents.len()
                    ),
                    exploit_scenario: format!(
                        "LIQUIDITY MANIPULATION ATTACK:\n\
                         1. Remove liquidity from {:?}\n\
                         2. Price shifts dramatically\n\
                         3. {:?} mark down collateral\n\
                         4. Mass liquidations triggered\n\
                         5. Attacker profits from liquidation fees",
                        pool, dependents
                    ),
                    remediation: "Use TWAP oracles, liquidity depth checks, circuit breakers".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_liquidity_pools(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let mut pools = Vec::new();
        let lp_selectors = [[0x09, 0x02, 0xf1, 0xac]]; // getReserves
        
        for (addr, bytecode) in contracts {
            if lp_selectors.iter().any(|sel| bytecode.windows(4).any(|w| w == sel)) {
                pools.push(*addr);
            }
        }
        pools
    }
    
    fn find_price_dependents(&self, pool: H160, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.keys()
            .filter(|&&addr| {
                addr != pool && self.protocol.get_call_targets(&addr).contains(&pool)
            })
            .cloned()
            .collect()
    }
    
    fn analyze_cascading_effects(&self, dependents: &[H160], _contracts: &HashMap<H160, &Vec<u8>>) -> Vec<String> {
        dependents.iter().map(|_| "Liquidation cascade".to_string()).collect()
    }
}

impl CrossContractLiquidityManipulation {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::ValueLeakage,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.manipulation_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
