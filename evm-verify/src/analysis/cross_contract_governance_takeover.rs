/// Cross-Contract Governance Takeover Analyzer
/// 
/// Detects: Flash loan governance tokens → Vote in Protocol → Extract value
/// Real exploit: Beanstalk ($182M)

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractGovernanceTakeover {
    pub vulnerability_type: String,
    pub severity: String,
    pub attack_path: Vec<H160>,  // FlashLoan → GovernanceToken → DAO → Target
    pub governance_token: H160,
    pub dao_contract: H160,
    pub flash_loan_source: Option<H160>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractGovernanceTakeoverAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractGovernanceTakeoverAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractGovernanceTakeover> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find governance tokens (have balanceOf and voting functions)
        let gov_tokens = self.find_governance_tokens(&contracts);
        
        // Find DAOs (have propose/vote functions)
        let daos = self.find_dao_contracts(&contracts);
        
        // Find flash loan providers
        let flash_lenders = self.find_flash_loan_providers(&contracts);
        
        // Check if governance token can be flash loaned
        for gov_token in &gov_tokens {
            for dao in &daos {
                // Check if DAO uses this token for voting
                if self.dao_uses_token(*dao, *gov_token, &contracts) {
                    // Check if token can be flash loaned
                    let flash_source = flash_lenders.iter()
                        .find(|&&lender| self.can_flash_loan_token(lender, *gov_token, &contracts));
                    
                    let path = if let Some(&source) = flash_source {
                        vec![source, *gov_token, *dao]
                    } else {
                        vec![*gov_token, *dao]
                    };
                    
                    vulnerabilities.push(CrossContractGovernanceTakeover {
                        vulnerability_type: "Cross-Contract Governance Takeover".to_string(),
                        severity: if flash_source.is_some() { "Critical" } else { "High" }.to_string(),
                        attack_path: path,
                        governance_token: *gov_token,
                        dao_contract: *dao,
                        flash_loan_source: flash_source.copied(),
                        description: format!(
                            "Governance token {:?} can be {}borrowed to manipulate DAO {:?}",
                            gov_token,
                            if flash_source.is_some() { "flash-" } else { "" },
                            dao
                        ),
                        exploit_scenario: format!(
                            "GOVERNANCE TAKEOVER ATTACK:\n\
                             1. Flash loan {} governance tokens from {:?}\n\
                             2. Propose malicious proposal in DAO {:?}\n\
                             3. Vote with flash-loaned tokens\n\
                             4. Execute proposal (drain treasury, change parameters)\n\
                             5. Repay flash loan\n\
                             \n\
                             Real example: Beanstalk $182M hack used this exact pattern!",
                            if flash_source.is_some() { "massive" } else { "acquire" },
                            flash_source,
                            dao
                        ),
                        remediation: "Use vote-escrowed tokens, time-locks, snapshot voting, or quorum requirements".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_governance_tokens(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let vote_selectors = [[0x01, 0x5f, 0xad, 0xa7]]; // vote()
        contracts.iter()
            .filter(|(_, bc)| vote_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_dao_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let dao_selectors = [[0xda, 0x95, 0x69, 0x1e]]; // propose()
        contracts.iter()
            .filter(|(_, bc)| dao_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_flash_loan_providers(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let flash_selectors = [[0x5c, 0xef, 0xe3, 0x67]]; // flashLoan
        contracts.iter()
            .filter(|(_, bc)| flash_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn dao_uses_token(&self, dao: H160, token: H160, _contracts: &HashMap<H160, &Vec<u8>>) -> bool {
        self.protocol.get_call_targets(&dao).contains(&token)
    }
    
    fn can_flash_loan_token(&self, _lender: H160, _token: H160, _contracts: &HashMap<H160, &Vec<u8>>) -> bool {
        true // Simplified
    }
}

impl CrossContractGovernanceTakeover {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: if self.severity == "Critical" { SecuritySeverity::Critical } else { SecuritySeverity::High },
            description: self.description.clone(),
            call_path: self.attack_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
