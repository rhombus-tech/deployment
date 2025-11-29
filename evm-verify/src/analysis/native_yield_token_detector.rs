/// Native Yield Token Advanced Detector
/// Detects vulnerabilities in native yield-bearing tokens
/// Critical for: eETH, pufETH, mETH, native rebasing tokens

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeYieldVulnerability {
    pub vulnerability_type: NativeYieldIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NativeYieldIssueType {
    NativeRebasingManipulation,    // Native rebasing exploit
    ValidatorMEVDistribution,      // MEV distribution manipulation
    YieldAccrualFrontrunning,      // Frontrunning yield updates
    OraclePriceStaleness,          // Native yield oracle stale
    SharePriceManipulation,        // Share price calculation exploit
}

pub struct NativeYieldTokenDetector {
    bytecode: Vec<u8>,
}

impl NativeYieldTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NativeYieldVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_native_yield_token() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_rebasing_issues());
        vulnerabilities.extend(self.detect_yield_manipulation());

        vulnerabilities
    }

    fn detect_rebasing_issues(&self) -> Vec<NativeYieldVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Balance update without rebase protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_balance_update(i) {
                if !self.has_rebase_guard(i) {
                    vulnerabilities.push(NativeYieldVulnerability {
                        vulnerability_type: NativeYieldIssueType::NativeRebasingManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Native yield token balance update without rebase protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Token rebases (shares → tokens conversion changes)\n\
                            2. Balance updates during rebase\n\
                            3. Attacker frontrunsor backruns rebase\n\
                            4. Captures yield meant for others\n\n\
                            Fix: Lock during rebase or use share-based accounting",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_yield_manipulation(&self) -> Vec<NativeYieldVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Yield distribution without staleness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_yield_distribution(i) {
                if !self.has_oracle_freshness_check(i) {
                    vulnerabilities.push(NativeYieldVulnerability {
                        vulnerability_type: NativeYieldIssueType::OraclePriceStaleness,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Native yield distribution without oracle freshness check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Oracle price becomes stale\n\
                            2. Yield distributed based on old price\n\
                            3. Share price miscalculated\n\
                            4. Arbitrage opportunity or unfair distribution\n\n\
                            Fix: Validate oracle timestamp < MAX_AGE",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_native_yield_token(&self) -> bool {
        // Look for native yield token patterns
        let shares_to_assets = [0x07, 0xa2, 0xd1, 0x3a]; // convertToAssets()
        let assets_to_shares = [0xc6, 0xe6, 0xf5, 0x92]; // convertToShares()
        
        self.bytecode.windows(4).any(|w| w == shares_to_assets || w == assets_to_shares)
    }

    fn has_balance_update(&self, pos: usize) -> bool {
        // Look for balance modification (SSTORE)
        pos < self.bytecode.len() && self.bytecode[pos] == 0x55
    }

    fn has_rebase_guard(&self, pos: usize) -> bool {
        // Look for reentrancy guard or lock
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x54 && i + 3 < self.bytecode.len() && self.bytecode[i+3] == 0x15 {
                return true; // SLOAD ISZERO (lock check)
            }
        }
        false
    }

    fn has_yield_distribution(&self, pos: usize) -> bool {
        // Look for yield update function
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x02 // MUL (yield calculation)
    }

    fn has_oracle_freshness_check(&self, pos: usize) -> bool {
        // Look for timestamp validation
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }
}
