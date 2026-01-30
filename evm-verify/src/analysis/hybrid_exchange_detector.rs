/// Hybrid Exchange (Off-chain Orderbook + On-chain Settlement) Detector
///
/// Detects vulnerabilities in hybrid decentralized exchanges that use off-chain
/// orderbooks with on-chain settlement (Hyperliquid, dYdX V4 style).
///
/// This architecture creates unique trust boundaries where:
/// - Off-chain: Fast matching, operator-controlled
/// - On-chain: Final settlement, trustless
/// - Attack surface: The bridge between these two worlds
///
/// Real-world context:
/// - Hyperliquid: $500M+ volume/day, single sequencer
/// - dYdX V4: Cosmos app-chain, validator set risk
/// - Key risk: Sequencer/operator has temporary control over ordering
/// - Exploit potential: $100M+ if sequencer compromised

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridExchangeVulnerability {
    pub vulnerability_type: HybridExchangeVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HybridExchangeVulnerabilityType {
    SequencerCensorship,          // Operator can censor withdrawals
    OrderbookManipulation,        // Off-chain matching can be manipulated
    SettlementDelayAttack,        // Delay between match and settlement
    CrossDomainReplay,            // Off-chain signature replayed on-chain
    OracleOrderbookMismatch,      // Price divergence between off/on chain
    WithdrawalDelayDos,           // Forced withdrawals blocked
    OperatorFrontrunning,         // Sequencer sees orders before execution
    FallbackMechanismMissing,      // No escape hatch if operator fails
    StateProofManipulation,       // Invalid Merkle proofs accepted
    EmergencyWithdrawalBypass,    // Emergency mode exploited
}

pub struct HybridExchangeDetector {
    bytecode: Vec<u8>,
}

impl HybridExchangeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<HybridExchangeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Detect sequencer censorship risk
        if let Some(vuln) = self.detect_sequencer_censorship() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Detect settlement delay attacks
        if let Some(vuln) = self.detect_settlement_delay() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Detect missing fallback mechanism
        if let Some(vuln) = self.detect_missing_fallback() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Detect operator frontrunning
        if let Some(vuln) = self.detect_operator_frontrunning() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Detect state proof manipulation
        if let Some(vuln) = self.detect_state_proof_manipulation() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_sequencer_censorship(&self) -> Option<HybridExchangeVulnerability> {
        // Hybrid exchanges have operator-controlled ordering
        // Must have forced withdrawal mechanism for censorship resistance
        
        let mut has_withdrawal = false;
        let mut has_forced_withdrawal = false;
        let mut has_timelock = false;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for withdrawal function
            if i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i..i+4];
                // withdraw() selector: 0x3ccfd60b
                if selector == [0x3c, 0xcf, 0xd6, 0x0b] {
                    has_withdrawal = true;
                }
                // forceWithdraw() or escapeHatch() selector
                if selector == [0x9e, 0x6e, 0xa4, 0x7b] ||
                   selector == [0x4c, 0x64, 0x50, 0xc1] {
                    has_forced_withdrawal = true;
                }
            }
            
            // Check for timelock mechanism
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                if i + 5 < self.bytecode.len() && 
                   (self.bytecode[i+1] == 0x01 || self.bytecode[i+1] == 0x03) { // ADD/SUB
                    has_timelock = true;
                }
            }
        }
        
        if has_withdrawal && !has_forced_withdrawal {
            return Some(HybridExchangeVulnerability {
                vulnerability_type: HybridExchangeVulnerabilityType::SequencerCensorship,
                severity: "Critical".to_string(),
                location: vec![0],
                description: "Hybrid exchange lacks forced withdrawal mechanism. If off-chain \
                            operator censors withdrawals, users have no escape hatch. Funds \
                            can be held hostage.".to_string(),
                exploit_scenario: "1. User requests withdrawal from off-chain balance\n\
                                  2. Operator ignores request (censorship)\n\
                                  3. User has no way to force withdrawal on-chain\n\
                                  4. Funds locked until operator cooperates\n\
                                  5. Operator can extort users or steal funds\n\
                                  6. Similar to CEX risk but supposed to be 'decentralized'".to_string(),
                recommendation: "Implement forced withdrawal: After N days without operator processing, \
                              users can submit Merkle proof of balance directly on-chain. Include \
                              emergency mode that allows direct on-chain trading if operator offline >7 days. \
                              Example: StarkEx escape hatch.".to_string(),
            });
        }
        
        None
    }
    
    fn detect_settlement_delay(&self) -> Option<HybridExchangeVulnerability> {
        // Gap between off-chain match and on-chain settlement
        // Price can move during this window
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for settlement with timestamp but no price staleness check
            let mut has_timestamp = false;
            let mut has_price_check = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    has_timestamp = true;
                }
                // Price staleness check (comparing timestamps)
                if self.bytecode[j] == 0x03 && has_timestamp { // SUB after timestamp
                    for k in j+1..self.bytecode.len().min(j + 5) {
                        if self.bytecode[k] == 0x10 { // LT (checking if stale)
                            has_price_check = true;
                        }
                    }
                }
            }
            
            if has_timestamp && !has_price_check {
                return Some(HybridExchangeVulnerability {
                    vulnerability_type: HybridExchangeVulnerabilityType::SettlementDelayAttack,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Settlement delay between off-chain matching and on-chain execution \
                                creates arbitrage window. No staleness check on settlement prices.".to_string(),
                    exploit_scenario: "1. User submits order off-chain at $100\n\
                                      2. Matched off-chain immediately\n\
                                      3. Settlement submitted on-chain 10 seconds later\n\
                                      4. Price now $105 (5% move)\n\
                                      5. User expects $100 but settles at $105\n\
                                      6. Operator profits from delay arbitrage\n\
                                      7. Or attacker DOSes settlement to amplify delay".to_string(),
                    recommendation: "Add price staleness check: require(block.timestamp - matchTime < MAX_DELAY). \
                                  Compensate users if settlement price deviates >X% from match price. \
                                  Use commit-reveal for settlement timestamps. Implement priority queue.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_missing_fallback(&self) -> Option<HybridExchangeVulnerability> {
        // If operator goes offline, system must have fallback
        
        let mut has_operator_check = false;
        let mut has_fallback_mode = false;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Operator address check
            if self.bytecode[i] == 0x33 { // CALLER
                if i + 5 < self.bytecode.len() && self.bytecode[i+1] == 0x14 { // EQ
                    has_operator_check = true;
                }
            }
            
            // Fallback/emergency mode flag
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if there's a mode switch
                for j in i+1..self.bytecode.len().min(i + 10) {
                    if self.bytecode[j] == 0x15 { // ISZERO (checking boolean flag)
                        has_fallback_mode = true;
                    }
                }
            }
        }
        
        if has_operator_check && !has_fallback_mode {
            return Some(HybridExchangeVulnerability {
                vulnerability_type: HybridExchangeVulnerabilityType::FallbackMechanismMissing,
                severity: "Critical".to_string(),
                location: vec![0],
                description: "System depends on operator but lacks fallback mechanism. If operator \
                            goes offline (outage, regulatory shutdown, rug), all funds locked.".to_string(),
                exploit_scenario: "1. Operator controls all order matching\n\
                                  2. Operator server goes down or gets seized\n\
                                  3. No fallback to on-chain matching\n\
                                  4. All users' funds locked\n\
                                  5. No way to trade or withdraw\n\
                                  6. Complete system freeze until operator returns\n\
                                  7. Similar to Celsius/FTX but 'on-chain'".to_string(),
                recommendation: "Implement progressive decentralization: After N hours of operator \
                              inactivity, enable emergency mode. Emergency mode: on-chain orderbook \
                              (slow but works), direct peer-to-peer, or force settlement. Add \
                              multi-sig operator with automatic failover.".to_string(),
            });
        }
        
        None
    }
    
    fn detect_operator_frontrunning(&self) -> Option<HybridExchangeVulnerability> {
        // Operator sees all orders before executing
        // Can frontrun profitable trades
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for order matching without commit-reveal or privacy
            let mut has_order_matching = false;
            let mut has_commitment = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                // Order matching (likely involves signature verification)
                if self.bytecode[j] == 0xFA { // STATICCALL (could be ecrecover)
                    has_order_matching = true;
                }
                
                // Commitment scheme (hash-based)
                if self.bytecode[j] == 0x20 { // SHA3/KECCAK256
                    has_commitment = true;
                }
            }
            
            if has_order_matching && !has_commitment {
                return Some(HybridExchangeVulnerability {
                    vulnerability_type: HybridExchangeVulnerabilityType::OperatorFrontrunning,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Operator has full visibility into all pending orders and can \
                                frontrun profitable trades. No commit-reveal or encrypted orderbook.".to_string(),
                    exploit_scenario: "1. User submits large buy order for Token X\n\
                                      2. Operator sees order in mempool/off-chain\n\
                                      3. Operator buys Token X first (frontrun)\n\
                                      4. User's order executes at worse price\n\
                                      5. Operator sells for profit (backrun)\n\
                                      6. Invisible to users, happens off-chain\n\
                                      7. $100Ms extracted like Robinhood payment for order flow".to_string(),
                    recommendation: "Implement commit-reveal: Users commit hash(order) first, reveal later. \
                                  Use threshold encryption (FHE): Orders encrypted until batch executes. \
                                  Add operator slashing: Provable frontrunning causes penalty. \
                                  Require operator trades to be public and time-delayed.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_state_proof_manipulation(&self) -> Option<HybridExchangeVulnerability> {
        // Off-chain state proven via Merkle proofs
        // Invalid proofs must be rejected
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for Merkle proof verification
            let mut has_merkle_verify = false;
            let mut has_root_check = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Merkle verification (multiple KECCAK256 in loop)
                if self.bytecode[j] == 0x20 { // KECCAK256
                    has_merkle_verify = true;
                }
                
                // Root comparison
                if self.bytecode[j] == 0x14 && has_merkle_verify { // EQ
                    has_root_check = true;
                }
            }
            
            if has_merkle_verify && !has_root_check {
                return Some(HybridExchangeVulnerability {
                    vulnerability_type: HybridExchangeVulnerabilityType::StateProofManipulation,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Merkle proof verification present but missing proper root validation. \
                                Attacker can submit invalid proofs to fake balances or trades.".to_string(),
                    exploit_scenario: "1. User has 0 balance in off-chain orderbook\n\
                                      2. Constructs fake Merkle proof showing 1000 ETH\n\
                                      3. Submits withdrawal with invalid proof\n\
                                      4. Contract doesn't properly validate against state root\n\
                                      5. Withdrawal succeeds with fabricated balance\n\
                                      6. Drains all contract funds\n\
                                      7. Similar to Poly Network $600M hack (bad proof validation)".to_string(),
                    recommendation: "Strictly validate Merkle proofs: require(computedRoot == stateRoot). \
                                  Use battle-tested libraries (OpenZeppelin MerkleProof). Sign state roots \
                                  with operator key. Add fraud proofs: Anyone can challenge invalid state. \
                                  Implement checkpointing with delays.".to_string(),
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
    fn test_sequencer_censorship_detection() {
        // Has withdrawal but no forced withdrawal
        let bytecode = vec![
            0x3c, 0xcf, 0xd6, 0x0b, // withdraw() selector
            // No forceWithdraw selector
        ];
        
        let detector = HybridExchangeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            HybridExchangeVulnerabilityType::SequencerCensorship
        )));
    }
    
    #[test]
    fn test_settlement_delay_detection() {
        // TIMESTAMP without staleness check
        let bytecode = vec![
            0x42, // TIMESTAMP (no subsequent staleness check)
        ];
        
        let detector = HybridExchangeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            HybridExchangeVulnerabilityType::SettlementDelayAttack
        )));
    }
    
    #[test]
    fn test_missing_fallback() {
        // Operator check without fallback mode
        let bytecode = vec![
            0x33, // CALLER
            0x14, // EQ (operator check, no fallback mode)
        ];
        
        let detector = HybridExchangeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            HybridExchangeVulnerabilityType::FallbackMechanismMissing
        )));
    }
}
