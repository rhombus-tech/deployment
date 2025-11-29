/// Front-Running Pattern Analyzer (Granular)
/// Beyond MEV - specific patterns: Transaction reordering attacks, priority gas auctions

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FrontrunningVulnerabilityType {
    TransactionReordering,
    PriorityGasAuction,
    SlippageExploit,
    OracleUpdateFrontrun,
    CommitRevealMissing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity { Critical, High, Medium, Low }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontrunningVulnerability {
    pub vulnerability_type: FrontrunningVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct FrontrunningPatternAnalyzer {
    bytecode: Vec<u8>,
}

impl FrontrunningPatternAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_slippage_exploits());
        vulnerabilities.extend(self.detect_oracle_frontrunning());
        vulnerabilities.extend(self.detect_commit_reveal_missing());
        vulnerabilities
    }

    fn detect_slippage_exploits(&self) -> Vec<FrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let swap_sigs = [&[0x38, 0xed, 0x17, 0x39][..], &[0x7f, 0xf3, 0x6a, 0xb5][..]];
        
        for sig in swap_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
                
                let has_slippage_check = window.windows(8).any(|w| {
                    w.contains(&0x10) && // LT (amount >= minAmount)
                    w.contains(&0x57)    // JUMPI (revert if too low)
                });
                
                if !has_slippage_check {
                    vulnerabilities.push(FrontrunningVulnerability {
                        vulnerability_type: FrontrunningVulnerabilityType::SlippageExploit,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Swap lacks slippage protection. Attacker can sandwich attack for profit.".to_string(),
                        remediation: "Add minAmountOut: require(amountOut >= minAmountOut, 'Slippage exceeded')".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_oracle_frontrunning(&self) -> Vec<FrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let price_update_sigs = [&[0xa5, 0x2c, 0x10, 0x1e][..], &[0x8d, 0x6c, 0xc5, 0x6d][..]];
        
        for sig in price_update_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
                
                let has_delay = window.contains(&0x42) && window.contains(&0x10);
                let has_twap = window.windows(10).any(|w| w.contains(&0x04) && w.contains(&0x54));
                
                if !has_delay && !has_twap {
                    vulnerabilities.push(FrontrunningVulnerability {
                        vulnerability_type: FrontrunningVulnerabilityType::OracleUpdateFrontrun,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Price update immediately affects contract state. Can be front-run.".to_string(),
                        remediation: "Use TWAP or add delay: price = (oldPrice * 9 + newPrice) / 10".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }

    fn detect_commit_reveal_missing(&self) -> Vec<FrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let sensitive_sigs = [&[0xb3, 0xa9, 0x6b, 0x4f][..], &[0xd4, 0x0e, 0x71, 0xa5][..]];
        
        for sig in sensitive_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                let window = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                
                let has_commit = self.bytecode.windows(4).any(|w| w == &[0xf3, 0x4f, 0xc7, 0xd2]);
                let has_reveal = self.bytecode.windows(4).any(|w| w == &[0x85, 0xb8, 0x61, 0x48]);
                
                if !has_commit || !has_reveal {
                    vulnerabilities.push(FrontrunningVulnerability {
                        vulnerability_type: FrontrunningVulnerabilityType::CommitRevealMissing,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Sensitive operation lacks commit-reveal scheme. Values visible before execution.".to_string(),
                        remediation: "Implement commit-reveal: commit(hash) in tx1, reveal(value, salt) in tx2".to_string(),
                    });
                }
            }
        }
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_slippage_exploit() {
        let bytecode = vec![0x38, 0xed, 0x17, 0x39, 0xf1]; // swap + CALL (no slippage check)
        let analyzer = FrontrunningPatternAnalyzer::new(bytecode);
        let vulns = analyzer.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, FrontrunningVulnerabilityType::SlippageExploit)));
    }
}
