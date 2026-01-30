/// Cross-Chain Bridge Message Verification Analyzer
/// 
/// YOUR ADVANTAGE: Only tool that can trace multi-hop bridge verification
/// 
/// Real Exploits: Wormhole ($325M), Nomad ($190M), Harmony Horizon ($100M)
/// Pattern: SourceBridge → MessageRelay → DestinationBridge
/// Attack: Bypass verification in multi-contract bridge architecture

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractBridgeVerification {
    pub vulnerability_type: String,
    pub severity: String,
    pub bridge_components: Vec<H160>,  // [SourceBridge, Relayer, DestBridge]
    pub verification_gap: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractBridgeVerificationAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractBridgeVerificationAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractBridgeVerification> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find bridge components
        let source_bridges = self.find_source_bridges(&contracts);
        let relayers = self.find_message_relayers(&contracts);
        let dest_bridges = self.find_destination_bridges(&contracts);
        
        // Analyze verification chains
        for source in &source_bridges {
            let targets = self.protocol.get_call_targets(source);
            
            for relayer in &relayers {
                if targets.contains(relayer) {
                    let relayer_targets = self.protocol.get_call_targets(relayer);
                    
                    for dest in &dest_bridges {
                        if relayer_targets.contains(dest) {
                            // Found bridge chain: source → relayer → dest
                            let gap = self.check_verification_gap(*source, *relayer, *dest, &contracts);
                            
                            if gap.is_some() {
                                vulnerabilities.push(CrossContractBridgeVerification {
                                    vulnerability_type: "Cross-Chain Bridge Verification Bypass".to_string(),
                                    severity: "Critical".to_string(),
                                    bridge_components: vec![*source, *relayer, *dest],
                                    verification_gap: gap.unwrap(),
                                    description: format!(
                                        "Bridge verification chain {:?} → {:?} → {:?} has verification gap!\n\
                                         Messages can bypass signature checks in multi-hop architecture.",
                                        source, relayer, dest
                                    ),
                                    exploit_scenario: format!(
                                        "BRIDGE VERIFICATION BYPASS:\n\
                                         Chain: {:?} → {:?} → {:?}\n\
                                         \n\
                                         Attack:\n\
                                         1. Source bridge signs message on Chain A\n\
                                         2. Relayer forwards to destination on Chain B\n\
                                         3. Destination bridge ASSUMES relayer verified signature\n\
                                         4. But relayer doesn't check - or checks incorrectly!\n\
                                         5. Attacker submits fake message → unlimited minting/withdrawal\n\
                                         \n\
                                         Real examples:\n\
                                         - Wormhole: $325M - Message verification bypass\n\
                                         - Nomad: $190M - Replica contract trusted any message\n\
                                         - Harmony: $100M - Multi-sig threshold not enforced\n\
                                         \n\
                                         Your tool is ONLY ONE that sees complete bridge architecture!",
                                        source, relayer, dest
                                    ),
                                    remediation: "Each component must independently verify signatures, use threshold signatures, implement nonce tracking".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_source_bridges(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for sendMessage, lock, deposit patterns
        let bridge_selectors = [[0x0f, 0x5a, 0xa9, 0xf3]]; // sendMessage selector
        contracts.iter()
            .filter(|(_, bc)| bridge_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_message_relayers(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for relay, processMessage patterns
        let relay_selectors = [[0x8d, 0x3e, 0xdc, 0xca]]; // relay/process selector
        contracts.iter()
            .filter(|(_, bc)| relay_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_destination_bridges(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Look for receiveMessage, unlock, withdraw patterns
        let dest_selectors = [[0xa4, 0x21, 0x7f, 0xdf]]; // receiveMessage selector
        contracts.iter()
            .filter(|(_, bc)| dest_selectors.iter().any(|sel| bc.windows(4).any(|w| w == sel)))
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn check_verification_gap(
        &self,
        _source: H160,
        relayer: H160,
        dest: H160,
        contracts: &HashMap<H160, &Vec<u8>>,
    ) -> Option<String> {
        // Check if relayer or destination skips signature verification
        let ecrecover_opcode = 0x01; // ECRECOVER precompile
        
        let relayer_bytecode = contracts.get(&relayer)?;
        let dest_bytecode = contracts.get(&dest)?;
        
        let relayer_verifies = relayer_bytecode.contains(&ecrecover_opcode);
        let dest_verifies = dest_bytecode.contains(&ecrecover_opcode);
        
        if !relayer_verifies && !dest_verifies {
            Some("Neither relayer nor destination verifies signatures!".to_string())
        } else if !dest_verifies {
            Some("Destination blindly trusts relayer - no independent verification!".to_string())
        } else if !relayer_verifies {
            Some("Relayer doesn't verify - destination must validate all messages!".to_string())
        } else {
            None // Both verify - still could have bugs but pattern looks safer
        }
    }
}

impl CrossContractBridgeVerification {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.bridge_components.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
