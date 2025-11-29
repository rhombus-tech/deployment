/// RWA (Real-World Asset) Tokenization Risk Analyzer
/// Detects vulnerabilities in tokenized real-world assets
/// Critical for: MakerDAO RWA, Centrifuge, Ondo Finance, Backed Finance

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RWAVulnerability {
    pub vulnerability_type: RWAIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RWAIssueType {
    OffChainDataReliability,       // Off-chain price feed manipulation
    RedemptionMechanismBypass,     // Bypass freeze/blacklist for redemption
    RegulatoryComplianceBypass,    // Circumvent KYC/AML restrictions
    IlliquidAssetOracleFailure,    // Oracle failure for illiquid RWAs
    FractionalOwnershipError,      // Incorrect fractional calculation
    MaturityDateManipulation,      // Bond maturity date exploits
    WhitelistBypass,               // Transfer restriction bypass
}

pub struct RWATokenizationDetector {
    bytecode: Vec<u8>,
    rwa_selectors: HashSet<[u8; 4]>,
}

impl RWATokenizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut rwa_selectors = HashSet::new();
        rwa_selectors.insert([0x1e, 0x83, 0x40, 0x9b]); // redeem()
        rwa_selectors.insert([0xdb, 0x00, 0x6a, 0x75]); // updatePrice() off-chain
        rwa_selectors.insert([0x39, 0x50, 0x93, 0x51]); // transfer() (may be restricted)
        
        Self { bytecode, rwa_selectors }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RWAVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_rwa_token() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_oracle_reliability());
        vulnerabilities.extend(self.detect_redemption_issues());
        vulnerabilities.extend(self.detect_transfer_restrictions());

        vulnerabilities
    }

    fn detect_oracle_reliability(&self) -> Vec<RWAVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Off-chain price updates without staleness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let update_price = [0xdb, 0x00, 0x6a, 0x75];
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &update_price {
                // Check for timestamp staleness validation
                if !self.has_staleness_check(i) {
                    vulnerabilities.push(RWAVulnerability {
                        vulnerability_type: RWAIssueType::OffChainDataReliability,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "RWA price update without staleness check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Off-chain oracle updates RWA price\n\
                            2. No check if price is recent (<24h)\n\
                            3. Attacker uses stale price for arbitrage\n\
                            4. RWA mispriced in DeFi protocols\n\
                            5. Protocol incurs losses\n\n\
                            Fix: require(block.timestamp - lastUpdate < 1 days)",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for multi-sig or oracle quorum
                if !self.has_multi_sig_pattern(i) {
                    vulnerabilities.push(RWAVulnerability {
                        vulnerability_type: RWAIssueType::OffChainDataReliability,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Single oracle for illiquid RWA pricing".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Single address controls RWA price feed\n\
                            2. No redundancy or validation\n\
                            3. Compromised key = manipulated prices\n\
                            4. Entire RWA protocol at risk\n\n\
                            Fix: Use multi-sig or decentralized oracle network",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_redemption_issues(&self) -> Vec<RWAVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: redeem() function
        for i in 0..self.bytecode.len().saturating_sub(40) {
            let redeem = [0x1e, 0x83, 0x40, 0x9b];
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &redeem {
                // Check if blacklist can be bypassed
                if !self.has_blacklist_check(i) {
                    vulnerabilities.push(RWAVulnerability {
                        vulnerability_type: RWAIssueType::RedemptionMechanismBypass,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Redemption doesn't check blacklist status".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Sanctioned address holds RWA tokens\n\
                            2. Redemption function doesn't check blacklist\n\
                            3. Sanctioned entity redeems for real assets\n\
                            4. Regulatory compliance violated\n\
                            5. Protocol at legal risk\n\n\
                            Fix: require(!blacklisted[msg.sender])",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for maturity date validation (bonds)
                if !self.has_maturity_check(i) {
                    vulnerabilities.push(RWAVulnerability {
                        vulnerability_type: RWAIssueType::MaturityDateManipulation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Bond redemption without maturity date check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Tokenized bond has maturity date\n\
                            2. redeem() doesn't check if matured\n\
                            3. Early redemption possible\n\
                            4. Bond mechanics broken\n\n\
                            Fix: require(block.timestamp >= maturityDate)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_transfer_restrictions(&self) -> Vec<RWAVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: transfer() with restrictions
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let transfer = [0xa9, 0x05, 0x9c, 0xbb]; // transfer()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &transfer {
                // Check for whitelist enforcement
                if !self.has_whitelist_check(i) {
                    vulnerabilities.push(RWAVulnerability {
                        vulnerability_type: RWAIssueType::WhitelistBypass,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Transfer doesn't enforce whitelist (KYC bypass)".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. RWA requires KYC/whitelisting\n\
                            2. transfer() doesn't check whitelist\n\
                            3. Non-KYC address receives RWA tokens\n\
                            4. Regulatory compliance broken\n\
                            5. Protocol at legal risk\n\n\
                            Fix: require(whitelisted[to])",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_rwa_token(&self) -> bool {
        // Check for RWA-specific patterns
        for selector in &self.rwa_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        // Or blacklist/whitelist patterns
        let blacklist = [0x0a, 0x3b, 0x0a, 0x4f]; // blacklist()
        self.bytecode.windows(4).any(|w| w == blacklist)
    }

    fn has_staleness_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP comparison
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && i + 3 < self.bytecode.len() && self.bytecode[i+2] == 0x03 {
                return true; // TIMESTAMP - lastUpdate
            }
        }
        false
    }

    fn has_multi_sig_pattern(&self, pos: usize) -> bool {
        // Look for multiple SLOAD checks (multi-sig approval pattern)
        let mut sload_count = 0;
        for i in pos.saturating_sub(30)..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 {
                sload_count += 1;
            }
        }
        sload_count >= 3 // Heuristic: multi-sig needs multiple storage reads
    }

    fn has_blacklist_check(&self, pos: usize) -> bool {
        // Look for SLOAD (blacklist mapping check)
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD
                return true;
            }
        }
        false
    }

    fn has_maturity_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP comparison (maturity date)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 && i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x11 {
                return true; // TIMESTAMP >= maturityDate
            }
        }
        false
    }

    fn has_whitelist_check(&self, pos: usize) -> bool {
        // Similar to blacklist check
        self.has_blacklist_check(pos)
    }
}
