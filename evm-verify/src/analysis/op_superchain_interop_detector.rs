/// OP Superchain Interop Vulnerability Detector
///
/// Detects vulnerabilities in Optimism Superchain cross-L2 interoperability.
/// The Superchain enables native L2↔L2 messaging without going through L1.
///
/// Real-world context:
/// - $30B+ TVL (Base, OP Mainnet, Zora, Mode, Blast)
/// - Native cross-chain messaging launches Q1 2025
/// - Attack surface: Message replay, sequencer manipulation, finality gaps
/// - Risk: Cross-L2 exploits can drain multiple chains simultaneously

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpSuperchainVulnerability {
    pub vulnerability_type: OpSuperchainVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OpSuperchainVulnerabilityType {
    CrossChainMessageReplay,        // Message replayed on multiple L2s
    SharedSequencerManipulation,    // Shared sequencer controls ordering
    CrossL2FinalityGap,             // Finality timing differences exploited
    ChainIdConfusion,               // Wrong chain ID in cross-L2 message
    DepositReplayAttack,            // Deposit message replayed
    CrossChainReentrancy,           // Reentrancy across L2 boundaries
    MessageRelayerDOS,              // Message relayer can be DOSed
    OptimisticFinalityExploit,      // 7-day finality window exploited
    SuperchainBridgeBypass,         // Native bridge bypassed
    CrossChainNonceDesync,          // Nonce desync between chains
}

pub struct OpSuperchainInteropDetector {
    bytecode: Vec<u8>,
}

impl OpSuperchainInteropDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<OpSuperchainVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Cross-chain message replay
        if let Some(vuln) = self.detect_message_replay() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Chain ID confusion
        if let Some(vuln) = self.detect_chainid_confusion() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Cross-L2 finality gap
        if let Some(vuln) = self.detect_finality_gap() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Cross-chain reentrancy
        if let Some(vuln) = self.detect_cross_chain_reentrancy() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Message relayer DOS
        if let Some(vuln) = self.detect_relayer_dos() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_message_replay(&self) -> Option<OpSuperchainVulnerability> {
        // Cross-L2 messages must be replay-protected with unique identifiers
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for cross-chain message handling
            let mut has_message_handler = false;
            let mut has_replay_protection = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Message handling (likely calls CrossL2Inbox)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA { // CALL/STATICCALL
                    has_message_handler = true;
                }
                
                // Replay protection: nonce or message ID check
                if self.bytecode[j] == 0x54 { // SLOAD (checking if processed)
                    if j + 2 < self.bytecode.len() && 
                       (self.bytecode[j+1] == 0x15 || self.bytecode[j+1] == 0x14) { // ISZERO/EQ
                        has_replay_protection = true;
                    }
                }
            }
            
            if has_message_handler && !has_replay_protection {
                return Some(OpSuperchainVulnerability {
                    vulnerability_type: OpSuperchainVulnerabilityType::CrossChainMessageReplay,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Cross-L2 message handling lacks replay protection. Same message \
                                can be executed multiple times on same chain or replayed across \
                                different Superchain L2s.".to_string(),
                    exploit_scenario: "1. User sends cross-L2 message: 'Transfer 100 ETH from Base to OP'\n\
                                      2. Message executed on OP Mainnet\n\
                                      3. No message ID/nonce tracking\n\
                                      4. Attacker captures message data\n\
                                      5. Replays same message on OP Mainnet (double-spend)\n\
                                      6. Replays on Zora, Mode, Blast (5x spend!)\n\
                                      7. Each Superchain L2 processes same withdrawal\n\
                                      8. $100 turns into $500 exploit\n\
                                      9. Similar to Wormhole $325M exploit pattern".to_string(),
                    recommendation: "Track processed message IDs: require(!processedMessages[msgId]). \
                                  Use unique nonce per (sourceChain, destChain, sender). Include \
                                  chain-specific data in message hash. Use Superchain message ID \
                                  format: hash(sourceChain, nonce, sender, data). Reference: LayerZero \
                                  nonce tracking.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_chainid_confusion(&self) -> Option<OpSuperchainVulnerability> {
        // Must validate messages came from intended source chain
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for chainid() opcode
            let mut has_chainid = false;
            let mut validates_source_chain = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0x46 { // CHAINID
                    has_chainid = true;
                }
                
                // Validation: compare chainid with expected
                if self.bytecode[j] == 0x14 && has_chainid { // EQ after CHAINID
                    validates_source_chain = true;
                }
            }
            
            // If handling cross-chain messages without chain validation
            if !validates_source_chain {
                return Some(OpSuperchainVulnerability {
                    vulnerability_type: OpSuperchainVulnerabilityType::ChainIdConfusion,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Contract doesn't validate source chain ID in cross-L2 messages. \
                                Attacker can send messages claiming to be from trusted chain.".to_string(),
                    exploit_scenario: "1. Contract on OP Mainnet trusts messages from Base\n\
                                      2. No source chain validation\n\
                                      3. Attacker deploys on Zora (untrusted chain)\n\
                                      4. Sends message claiming sourceChain = Base\n\
                                      5. OP contract processes it as trusted\n\
                                      6. Malicious message executes privileged operations\n\
                                      7. Attacker drains contract despite being on wrong chain".to_string(),
                    recommendation: "Validate source chain: require(sourceChainId == TRUSTED_CHAIN). \
                                  Maintain whitelist of allowed source chains. Use Superchain \
                                  CrossL2Inbox for validation. Verify message came through official \
                                  bridge. Add chain-specific access control.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_finality_gap(&self) -> Option<OpSuperchainVulnerability> {
        // L2s have different finality times - creates arbitrage window
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for cross-chain state dependency
            let mut has_cross_chain_dependency = false;
            let mut has_finality_check = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // External call (could be cross-chain)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                    has_cross_chain_dependency = true;
                }
                
                // Finality check (timestamp or block number comparison)
                if self.bytecode[j] == 0x42 || self.bytecode[j] == 0x43 { // TIMESTAMP/NUMBER
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x10 { // LT (time check)
                        has_finality_check = true;
                    }
                }
            }
            
            if has_cross_chain_dependency && !has_finality_check {
                return Some(OpSuperchainVulnerability {
                    vulnerability_type: OpSuperchainVulnerabilityType::CrossL2FinalityGap,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Contract relies on cross-L2 state without accounting for finality \
                                differences. Base might be final while OP Mainnet is not, creating \
                                arbitrage and front-running opportunities.".to_string(),
                    exploit_scenario: "1. Oracle on Base updates price: ETH = $3000\n\
                                      2. Base reaches finality instantly (2 seconds)\n\
                                      3. Contract on OP reads Base oracle\n\
                                      4. OP finality takes 7 days for L1 confirmation\n\
                                      5. Real ETH price moves to $3100\n\
                                      6. Attacker exploits 7-day window for arbitrage\n\
                                      7. Similar to L1→L2 7-day challenge period exploits\n\
                                      8. $50M+ potential with price manipulation".to_string(),
                    recommendation: "Wait for cross-chain finality before trusting state. Use \
                                  finalized flag from CrossL2Inbox. Add time delays for cross-chain \
                                  operations. Implement optimistic verification with fraud proofs. \
                                  Consider L1 finality as source of truth. Add finality attestations.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_cross_chain_reentrancy(&self) -> Option<OpSuperchainVulnerability> {
        // Reentrancy can happen across L2 boundaries
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for cross-chain call followed by state change
            let mut has_cross_chain_call = false;
            let mut state_change_after_call = false;
            let mut has_reentrancy_guard = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0xF1 { // CALL
                    has_cross_chain_call = true;
                }
                
                if has_cross_chain_call && self.bytecode[j] == 0x55 { // SSTORE after call
                    state_change_after_call = true;
                }
                
                // Reentrancy guard check
                if self.bytecode[j] == 0x54 { // SLOAD (loading guard)
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        has_reentrancy_guard = true;
                    }
                }
            }
            
            if state_change_after_call && !has_reentrancy_guard {
                return Some(OpSuperchainVulnerability {
                    vulnerability_type: OpSuperchainVulnerabilityType::CrossChainReentrancy,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "State changes after cross-L2 external call without reentrancy \
                                protection. Attacker can reenter from different chain before state \
                                updates.".to_string(),
                    exploit_scenario: "1. Contract on OP calls contract on Base\n\
                                      2. Base contract calls back to OP (cross-chain callback)\n\
                                      3. Callback arrives before original call finishes\n\
                                      4. State not yet updated (classic reentrancy)\n\
                                      5. Attacker drains funds via cross-L2 reentrancy loop\n\
                                      6. More complex than single-chain reentrancy\n\
                                      7. Similar to Curve read-only reentrancy but cross-chain".to_string(),
                    recommendation: "Use checks-effects-interactions pattern. Apply nonReentrant \
                                  modifier to all cross-chain functions. Update state before external \
                                  calls. Consider cross-chain mutex. Add callback validation. \
                                  Use pull payment pattern for cross-chain transfers.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_relayer_dos(&self) -> Option<OpSuperchainVulnerability> {
        // Message relayers can be DOSed, preventing message delivery
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for relayer-dependent operations
            let mut depends_on_relayer = false;
            let mut has_fallback = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Relayer call (external dependency)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                    depends_on_relayer = true;
                }
                
                // Fallback mechanism (alternative execution path)
                if self.bytecode[j] == 0x57 { // JUMPI (conditional jump - fallback)
                    has_fallback = true;
                }
            }
            
            if depends_on_relayer && !has_fallback {
                return Some(OpSuperchainVulnerability {
                    vulnerability_type: OpSuperchainVulnerabilityType::MessageRelayerDOS,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Contract depends on message relayer without fallback mechanism. \
                                If relayer is DOSed or goes offline, cross-chain functionality breaks.".to_string(),
                    exploit_scenario: "1. User initiates cross-L2 withdrawal: OP → Base\n\
                                      2. Message sent to relayer network\n\
                                      3. Attacker DOSes all relayers (gas griefing)\n\
                                      4. Message never delivered to destination\n\
                                      5. Funds locked on source chain\n\
                                      6. No alternative delivery mechanism\n\
                                      7. User cannot access funds until relayer recovers".to_string(),
                    recommendation: "Implement manual message relay as fallback. Allow multiple \
                                  relayers with incentives. Add timelock for self-relay after delay. \
                                  Use decentralized relayer network. Implement message queue with \
                                  priority. Add relayer slashing for non-delivery.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_replay() {
        // Message handler without replay protection
        let bytecode = vec![
            0xF1, // CALL (message handler, no SLOAD check)
        ];
        
        let detector = OpSuperchainInteropDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            OpSuperchainVulnerabilityType::CrossChainMessageReplay
        )));
    }
    
    #[test]
    fn test_cross_chain_reentrancy() {
        // CALL followed by SSTORE without guard
        let bytecode = vec![
            0xF1, // CALL (cross-chain)
            0x55, // SSTORE (state change after call, no guard)
        ];
        
        let detector = OpSuperchainInteropDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            OpSuperchainVulnerabilityType::CrossChainReentrancy
        )));
    }
}
