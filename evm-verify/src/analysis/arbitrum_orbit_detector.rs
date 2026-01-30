/// Arbitrum Orbit Chain Vulnerability Detector
///
/// Detects vulnerabilities specific to Arbitrum Orbit custom L2/L3 chains.
/// Orbit allows anyone to deploy their own Arbitrum-based rollup.
///
/// Real-world context:
/// - $5B+ across 50+ Orbit chains (Xai, Rari, Proof of Play, etc.)
/// - Custom chains can modify sequencer, gas tokens, governance
/// - Attack surface: Custom params, sequencer control, escape hatch, L2→L3 bridge
/// - Risk: One misconfigured Orbit chain can be fully drained

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrumOrbitVulnerability {
    pub vulnerability_type: ArbitrumOrbitVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArbitrumOrbitVulnerabilityType {
    CustomSequencerControl,         // Centralized sequencer can censor
    MisconfiguredGasToken,          // Custom gas token creates exploits
    MissingEscapeHatch,             // Users trapped if sequencer fails
    L2ToL3BridgeRisk,               // L2→L3 bridge lacks validation
    OrbitChainGovernanceBypass,     // Governance can be bypassed
    InvalidBatchPosting,            // Batch posting to L1/L2 broken
    CustomPrecompileExploit,        // Custom precompiles have bugs
    SequencerInboxManipulation,     // Sequencer inbox can be manipulated
    DelayedInboxBypass,             // Force inclusion via delayed inbox bypassed
    ChainOwnerPrivilegeAbuse,       // Chain owner has excessive privileges
}

pub struct ArbitrumOrbitDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumOrbitDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ArbitrumOrbitVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Custom sequencer control
        if let Some(vuln) = self.detect_sequencer_control() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Misconfigured gas token
        if let Some(vuln) = self.detect_gas_token_misconfiguration() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Missing escape hatch
        if let Some(vuln) = self.detect_missing_escape_hatch() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Chain owner privilege abuse
        if let Some(vuln) = self.detect_owner_privilege_abuse() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Delayed inbox bypass
        if let Some(vuln) = self.detect_delayed_inbox_bypass() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_sequencer_control(&self) -> Option<ArbitrumOrbitVulnerability> {
        // Orbit chains often have single sequencer - must have decentralization path
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for sequencer validation
            let mut has_sequencer_check = false;
            let mut has_decentralization_mechanism = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Sequencer address check
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        has_sequencer_check = true;
                    }
                }
                
                // Decentralization: multiple sequencers or rotation mechanism
                if self.bytecode[j] == 0x54 { // SLOAD (loading sequencer set)
                    has_decentralization_mechanism = true;
                }
            }
            
            if has_sequencer_check && !has_decentralization_mechanism {
                return Some(ArbitrumOrbitVulnerability {
                    vulnerability_type: ArbitrumOrbitVulnerabilityType::CustomSequencerControl,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Orbit chain uses single centralized sequencer without decentralization \
                                mechanism. Sequencer can censor transactions, steal MEV, or go offline.".to_string(),
                    exploit_scenario: "1. Orbit chain has single sequencer (common setup)\n\
                                      2. User deposits $10M to Orbit chain\n\
                                      3. Sequencer censors user's withdrawal transaction\n\
                                      4. User cannot exit chain (funds trapped)\n\
                                      5. Sequencer extracts MEV from all transactions\n\
                                      6. Or sequencer goes offline → chain halts entirely\n\
                                      7. No delayed inbox fallback\n\
                                      8. $5B+ at risk across all Orbit chains with single sequencer".to_string(),
                    recommendation: "Implement decentralization path: (1) Use Arbitrum AnyTrust committee, \
                                  (2) Allow delayed inbox for censorship resistance, (3) Implement sequencer \
                                  rotation, (4) Add forced transaction inclusion, (5) Set decentralization \
                                  timeline. Reference: Base progressive decentralization roadmap.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_gas_token_misconfiguration(&self) -> Option<ArbitrumOrbitVulnerability> {
        // Orbit allows custom gas tokens - must handle edge cases
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for gas payment logic
            let mut has_gas_payment = false;
            let mut validates_gas_token = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Gas payment (balance reduction)
                if self.bytecode[j] == 0x03 && self.bytecode[j+1] == 0x55 { // SUB + SSTORE
                    has_gas_payment = true;
                }
                
                // Gas token validation (checking token contract)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA { // CALL/STATICCALL
                    validates_gas_token = true;
                }
            }
            
            if has_gas_payment && !validates_gas_token {
                return Some(ArbitrumOrbitVulnerability {
                    vulnerability_type: ArbitrumOrbitVulnerabilityType::MisconfiguredGasToken,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Custom gas token logic doesn't properly validate token contract. \
                                Can lead to incorrect gas payments, DOS, or free transactions.".to_string(),
                    exploit_scenario: "1. Orbit chain uses custom ERC-20 as gas token (e.g., $GAME)\n\
                                      2. Gas payment doesn't validate token decimals\n\
                                      3. $GAME has 6 decimals (USDC-style)\n\
                                      4. Chain expects 18 decimals (ETH-style)\n\
                                      5. Gas cost: should be 0.01 GAME (10^4 units)\n\
                                      6. Calculated as 0.01 * 10^18 = 10^16 (way too much)\n\
                                      7. All transactions revert from insufficient gas token\n\
                                      8. Chain completely DOSed\n\
                                      9. Or opposite: gas is free due to underflow".to_string(),
                    recommendation: "Validate gas token: (1) Check decimals() matches expected, \
                                  (2) Verify token contract code hash, (3) Handle fee-on-transfer tokens, \
                                  (4) Add gas token balance checks, (5) Implement gas price oracle, \
                                  (6) Add emergency fallback to ETH. Reference: ZKSync fee model.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_missing_escape_hatch(&self) -> Option<ArbitrumOrbitVulnerability> {
        // Users must be able to exit even if sequencer fails
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for withdrawal mechanism
            let mut has_withdrawal = false;
            let mut has_forced_withdrawal = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Normal withdrawal
                if j + 4 < self.bytecode.len() {
                    let selector = &self.bytecode[j..j+4];
                    if selector == [0x3c, 0xcf, 0xd6, 0x0b] { // withdraw()
                        has_withdrawal = true;
                    }
                    // Forced withdrawal (via delayed inbox)
                    if selector == [0x9e, 0x6e, 0xa4, 0x7b] { // forceInclusion()
                        has_forced_withdrawal = true;
                    }
                }
            }
            
            if has_withdrawal && !has_forced_withdrawal {
                return Some(ArbitrumOrbitVulnerability {
                    vulnerability_type: ArbitrumOrbitVulnerabilityType::MissingEscapeHatch,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "No forced transaction inclusion mechanism. If sequencer censors or \
                                goes offline, users cannot exit and funds are permanently locked.".to_string(),
                    exploit_scenario: "1. User deposits $10M to Orbit chain\n\
                                      2. Sequencer operator disappears (rug pull)\n\
                                      3. User tries to withdraw funds\n\
                                      4. No sequencer to process transaction\n\
                                      5. No delayed inbox for force inclusion\n\
                                      6. Funds permanently locked on L2/L3\n\
                                      7. Similar to CEX freeze but 'decentralized'\n\
                                      8. $5B+ at risk if all Orbit chains lose sequencers".to_string(),
                    recommendation: "Implement escape hatch: (1) Enable delayed inbox for force inclusion, \
                                  (2) Allow direct L1→L2 or L2→L3 messages after timeout, (3) Add emergency \
                                  withdrawal via fraud proof, (4) Implement forced batch posting, \
                                  (5) Allow direct state root challenge. Reference: Arbitrum delayed inbox, \
                                  StarkEx escape hatch.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_owner_privilege_abuse(&self) -> Option<ArbitrumOrbitVulnerability> {
        // Chain owner should have limited privileges
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for owner-controlled functions
            let mut has_owner_control = false;
            let mut has_timelock = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Owner check
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        has_owner_control = true;
                    }
                }
                
                // Timelock (timestamp comparison)
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x10 { // LT
                        has_timelock = true;
                    }
                }
            }
            
            if has_owner_control && !has_timelock {
                return Some(ArbitrumOrbitVulnerability {
                    vulnerability_type: ArbitrumOrbitVulnerabilityType::ChainOwnerPrivilegeAbuse,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Chain owner has unrestricted privileges without timelock. Can instantly \
                                upgrade contracts, change parameters, or drain funds.".to_string(),
                    exploit_scenario: "1. Orbit chain owner has upgrade privileges\n\
                                      2. No timelock on upgrades\n\
                                      3. Owner upgrades bridge contract\n\
                                      4. New implementation has backdoor\n\
                                      5. Owner drains all bridge funds ($5B)\n\
                                      6. Happens in single transaction\n\
                                      7. Users cannot react or exit\n\
                                      8. Similar to Ronin bridge $625M exploit pattern".to_string(),
                    recommendation: "Limit owner privileges: (1) Add 7-day timelock for upgrades, \
                                  (2) Use multi-sig (3/5) for admin actions, (3) Implement emergency \
                                  pause only (no upgrades), (4) Add governance delay, (5) Require \
                                  community veto period. Reference: Compound timelock, Optimism \
                                  Security Council.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_delayed_inbox_bypass(&self) -> Option<ArbitrumOrbitVulnerability> {
        // Delayed inbox must work even if sequencer hostile
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for inbox validation
            let mut has_inbox_handler = false;
            let mut validates_forced_inclusion = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Inbox message processing
                if self.bytecode[j] == 0xF1 { // CALL
                    has_inbox_handler = true;
                }
                
                // Forced inclusion check (timestamp delay verification)
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x03 { // SUB
                        validates_forced_inclusion = true;
                    }
                }
            }
            
            if has_inbox_handler && !validates_forced_inclusion {
                return Some(ArbitrumOrbitVulnerability {
                    vulnerability_type: ArbitrumOrbitVulnerabilityType::DelayedInboxBypass,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Delayed inbox doesn't validate forced inclusion delay. Sequencer can \
                                prevent forced transactions from being included.".to_string(),
                    exploit_scenario: "1. Sequencer censors user's withdrawal\n\
                                      2. User submits to delayed inbox (24h delay)\n\
                                      3. After 24h, user calls forceInclusion()\n\
                                      4. Sequencer ignores forced message\n\
                                      5. No validation that delay passed\n\
                                      6. User still cannot exit\n\
                                      7. Censorship resistance mechanism completely broken".to_string(),
                    recommendation: "Enforce forced inclusion: require(block.timestamp >= message.timestamp + DELAY). \
                                  Allow anyone to force include after delay. Add incentives for force \
                                  inclusion. Implement automatic processing. Reference: Arbitrum \
                                  SequencerInbox forceInclusion.".to_string(),
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
    fn test_sequencer_control() {
        // Sequencer check without decentralization
        let bytecode = vec![
            0x33, // CALLER
            0x14, // EQ (no sequencer set SLOAD)
        ];
        
        let detector = ArbitrumOrbitDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            ArbitrumOrbitVulnerabilityType::CustomSequencerControl
        )));
    }
    
    #[test]
    fn test_missing_escape_hatch() {
        // Withdrawal without forced inclusion
        let bytecode = vec![
            0x3c, 0xcf, 0xd6, 0x0b, // withdraw() selector
            // No forceInclusion() selector
        ];
        
        let detector = ArbitrumOrbitDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            ArbitrumOrbitVulnerabilityType::MissingEscapeHatch
        )));
    }
}
