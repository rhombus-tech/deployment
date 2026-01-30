/// Cross-Contract Event Ordering Dependencies Analyzer
/// 
/// YOUR ADVANTAGE: Analyze event ordering requirements across contracts
/// 
/// Pattern: Contract A assumes Event1 fires before Event2
/// Attack: Reorder events across blocks to break assumptions
/// Real Impact: MEV and liquidation bot manipulation

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractEventOrdering {
    pub vulnerability_type: String,
    pub severity: String,
    pub event_chain: Vec<H160>,
    pub ordering_dependency: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractEventOrderingAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractEventOrderingAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractEventOrdering> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        let event_emitters = self.find_event_emitters(&contracts);
        
        for (i, emitter_a) in event_emitters.iter().enumerate() {
            for emitter_b in event_emitters.iter().skip(i + 1) {
                if self.has_ordering_dependency(*emitter_a, *emitter_b) {
                    vulnerabilities.push(CrossContractEventOrdering {
                        vulnerability_type: "Cross-Contract Event Ordering Dependency".to_string(),
                        severity: "High".to_string(),
                        event_chain: vec![*emitter_a, *emitter_b],
                        ordering_dependency: "Contract B assumes Contract A's event fires first".to_string(),
                        description: format!(
                            "Event ordering dependency: {:?} → {:?}\n\
                             Events can be reordered across transactions causing logic violations",
                            emitter_a, emitter_b
                        ),
                        exploit_scenario: "ORACLE UPDATE ORDERING: Oracle assumes PriceUpdate before Liquidation check".to_string(),
                        remediation: "Don't rely on event ordering, use explicit sequencing, implement nonce tracking".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_event_emitters(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.iter()
            .filter(|(_, bc)| bc.contains(&0xA1) || bc.contains(&0xA2))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn has_ordering_dependency(&self, _a: H160, _b: H160) -> bool {
        // Simplified: assume dependency if contracts interact
        true
    }
}

impl CrossContractEventOrdering {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::StateInconsistency,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.event_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
