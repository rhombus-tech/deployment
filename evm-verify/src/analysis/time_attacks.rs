use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};

/// Time-based attack patterns
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeAttackType {
    TimestampManipulation,
    BlockDependency,
    DeadlineBypass,
    OracleTimingExploit,
    MEVTiming,
    OrderingDependency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeVulnerability {
    pub attack_type: TimeAttackType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub risk_score: u8, // 0-10 objective scoring
    pub manipulation_window: u64, // seconds
    pub description: String,
}

pub struct TimeAttackDetector {
    bytecode: Vec<u8>,
}

impl TimeAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_timestamp_risks());
        vulns.extend(self.detect_block_risks());
        vulns.extend(self.detect_deadline_risks());
        vulns.extend(self.detect_oracle_timing());
        vulns.extend(self.detect_mev_timing());
        vulns.extend(self.detect_ordering_risks());
        vulns
    }

    fn detect_timestamp_risks(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Direct comparison without buffer
                if self.has_direct_comparison(i) && !self.has_time_buffer(i) {
                    vulns.push(TimeVulnerability {
                        attack_type: TimeAttackType::TimestampManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        risk_score: 8,
                        manipulation_window: 900, // 15 minutes
                        description: "Direct timestamp comparison without buffer enables manipulation".to_string(),
                    });
                }
                // Arithmetic operations
                if self.has_timestamp_arithmetic(i) {
                    vulns.push(TimeVulnerability {
                        attack_type: TimeAttackType::TimestampManipulation,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        risk_score: 6,
                        manipulation_window: 600,
                        description: "Timestamp arithmetic vulnerable to manipulation".to_string(),
                    });
                }
            }
        }
        vulns
    }

    fn detect_block_risks(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x43 { // NUMBER
                if self.has_short_block_window(i) {
                    vulns.push(TimeVulnerability {
                        attack_type: TimeAttackType::BlockDependency,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        risk_score: 5,
                        manipulation_window: 300,
                        description: "Short block number window vulnerable to manipulation".to_string(),
                    });
                }
            }
            if self.bytecode[i] == 0x40 { // BLOCKHASH for randomness
                vulns.push(TimeVulnerability {
                    attack_type: TimeAttackType::BlockDependency,
                    severity: SecuritySeverity::Low,
                    location: i,
                    risk_score: 3,
                    manipulation_window: 600,
                    description: "Block hash used for randomness is predictable".to_string(),
                });
            }
        }
        vulns
    }

    fn detect_deadline_risks(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.has_deadline_param(i) && self.is_deadline_bypassable(i) {
                vulns.push(TimeVulnerability {
                    attack_type: TimeAttackType::DeadlineBypass,
                    severity: SecuritySeverity::High,
                    location: i,
                    risk_score: 7,
                    manipulation_window: 0,
                    description: "Deadline parameter can be bypassed or set to maximum value".to_string(),
                });
            }
        }
        vulns
    }

    fn detect_oracle_timing(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.has_oracle_call(i) {
                if self.allows_stale_oracle_data(i) {
                    vulns.push(TimeVulnerability {
                        attack_type: TimeAttackType::OracleTimingExploit,
                        severity: SecuritySeverity::High,
                        location: i,
                        risk_score: 9,
                        manipulation_window: 3600, // 1 hour
                        description: "Oracle allows stale data usage for price manipulation".to_string(),
                    });
                }
                if !self.has_twap_protection(i) {
                    vulns.push(TimeVulnerability {
                        attack_type: TimeAttackType::OracleTimingExploit,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        risk_score: 6,
                        manipulation_window: 60,
                        description: "Spot price usage without TWAP protection".to_string(),
                    });
                }
            }
        }
        vulns
    }

    fn detect_mev_timing(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.has_value_operation(i) && self.has_predictable_timing(i) {
                vulns.push(TimeVulnerability {
                    attack_type: TimeAttackType::MEVTiming,
                    severity: SecuritySeverity::Medium,
                    location: i,
                    risk_score: 6,
                    manipulation_window: 180,
                    description: "Predictable timing enables MEV extraction".to_string(),
                });
            }
        }
        vulns
    }

    fn detect_ordering_risks(&self) -> Vec<TimeVulnerability> {
        let mut vulns = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.has_ordering_dependency(i) {
                let risk = self.assess_ordering_risk(i);
                vulns.push(TimeVulnerability {
                    attack_type: TimeAttackType::OrderingDependency,
                    severity: if risk >= 7 { SecuritySeverity::High } else { SecuritySeverity::Medium },
                    location: i,
                    risk_score: risk,
                    manipulation_window: 300,
                    description: "Transaction ordering dependency creates manipulation opportunity".to_string(),
                });
            }
        }
        vulns
    }

    // Helper methods
    fn has_direct_comparison(&self, pos: usize) -> bool {
        let end = std::cmp::min(pos + 10, self.bytecode.len());
        for i in (pos + 1)..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x10 | 0x11 | 0x14 => return true, // LT, GT, EQ
                    _ => {}
                }
            }
        }
        false
    }

    fn has_time_buffer(&self, pos: usize) -> bool {
        let start = pos.saturating_sub(10);
        let end = std::cmp::min(pos + 10, self.bytecode.len());
        for i in start..end {
            if i < self.bytecode.len() && self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f {
                let push_size = (self.bytecode[i] - 0x5f) as usize;
                if push_size >= 2 && i + push_size < self.bytecode.len() {
                    let value = self.extract_push_value_at(i);
                    if value >= 300 { // At least 5 minute buffer
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_timestamp_arithmetic(&self, pos: usize) -> bool {
        let end = std::cmp::min(pos + 15, self.bytecode.len());
        for i in (pos + 1)..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x01..=0x04 => return true, // ADD, SUB, MUL, DIV
                    _ => {}
                }
            }
        }
        false
    }

    fn has_short_block_window(&self, pos: usize) -> bool {
        let end = std::cmp::min(pos + 20, self.bytecode.len());
        for i in (pos + 1)..end {
            if i < self.bytecode.len() && self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f {
                let value = self.extract_push_value_at(i);
                if value > 0 && value < 100 { // Less than 100 blocks (~20 minutes)
                    return true;
                }
            }
        }
        false
    }

    fn has_deadline_param(&self, pos: usize) -> bool {
        // Look for common deadline parameter patterns
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x38, 0xed, 0x17, 0x39] || // swapExactTokensForTokens
            self.bytecode[pos..pos+4] == [0x7f, 0xf3, 0x6a, 0xb5]    // swapExactETHForTokens
        )
    }

    fn is_deadline_bypassable(&self, pos: usize) -> bool {
        // Check if deadline can be set to type(uint256).max or similar
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        for i in pos..end.saturating_sub(4) {
            if self.bytecode[i] == 0x7f { // PUSH32
                // Check for max uint256 pattern
                let all_ff = self.bytecode[i+1..i+33].iter().all(|&b| b == 0xff);
                if all_ff {
                    return true;
                }
            }
        }
        false
    }

    fn has_oracle_call(&self, pos: usize) -> bool {
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x50, 0xd2, 0x5b, 0xcd] || // latestRoundData
            self.bytecode[pos..pos+4] == [0xfe, 0xaf, 0x96, 0x8c] || // latestAnswer
            self.bytecode[pos..pos+4] == [0x66, 0x8a, 0x0f, 0x03]    // latestTimestamp
        )
    }

    fn allows_stale_oracle_data(&self, pos: usize) -> bool {
        // Oracle call without timestamp validation
        let end = std::cmp::min(pos + 50, self.bytecode.len());
        for i in pos..end {
            if i < self.bytecode.len() && self.bytecode[i] == 0x42 { // TIMESTAMP check
                return false;
            }
        }
        true // No timestamp validation found
    }

    fn has_twap_protection(&self, pos: usize) -> bool {
        // Look for time-weighted average price logic
        let end = std::cmp::min(pos + 40, self.bytecode.len());
        let mut has_multiple_prices = false;
        let mut price_count = 0;
        
        for i in pos..end.saturating_sub(4) {
            if self.bytecode[i] == 0xfa { // STATICCALL (price calls)
                price_count += 1;
            }
        }
        
        price_count >= 2 // Multiple price calls suggest TWAP
    }

    fn has_value_operation(&self, pos: usize) -> bool {
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0xa9, 0x05, 0x9c, 0xbb] || // transfer
            self.bytecode[pos..pos+4] == [0x38, 0xed, 0x17, 0x39] || // swap functions
            self.bytecode[pos] == 0xf1 // CALL with value
        )
    }

    fn has_predictable_timing(&self, pos: usize) -> bool {
        // Check for timestamp or block number dependencies that create predictable timing
        let end = std::cmp::min(pos + 20, self.bytecode.len());
        for i in pos..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x42 | 0x43 => return true, // TIMESTAMP or NUMBER
                    _ => {}
                }
            }
        }
        false
    }

    fn has_ordering_dependency(&self, pos: usize) -> bool {
        // Look for operations that depend on transaction ordering
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        let mut has_state_read = false;
        let mut has_state_write = false;
        
        for i in pos..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x54 => has_state_read = true,  // SLOAD
                    0x55 => has_state_write = true, // SSTORE
                    _ => {}
                }
            }
        }
        
        has_state_read && has_state_write
    }

    fn assess_ordering_risk(&self, pos: usize) -> u8 {
        let mut risk = 3; // Base risk
        
        if self.has_value_operation(pos) {
            risk += 2; // Higher risk for value operations
        }
        if self.has_predictable_timing(pos) {
            risk += 2; // Higher risk for predictable timing
        }
        if !self.has_reentrancy_guard(pos) {
            risk += 2; // Higher risk without protection
        }
        
        risk.min(10)
    }

    fn has_reentrancy_guard(&self, pos: usize) -> bool {
        // Simple check for reentrancy protection patterns
        let start = pos.saturating_sub(20);
        let end = std::cmp::min(pos + 20, self.bytecode.len());
        
        for i in start..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x54 => { // SLOAD - check for status flag
                        if i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x14 { // EQ
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    fn extract_push_value_at(&self, pos: usize) -> u64 {
        if pos >= self.bytecode.len() {
            return 0;
        }
        
        let push_size = match self.bytecode[pos] {
            0x60..=0x7f => (self.bytecode[pos] - 0x5f) as usize,
            _ => return 0,
        };
        
        if pos + push_size >= self.bytecode.len() {
            return 0;
        }
        
        let value_bytes = &self.bytecode[pos + 1..pos + 1 + push_size];
        value_bytes.iter().fold(0u64, |acc, &b| {
            acc.saturating_mul(256).saturating_add(b as u64)
        })
    }
}

/// Integration function
pub fn detect_time_based_attacks(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let bytecode = analyzer.get_bytecode_vec();
    let detector = TimeAttackDetector::new(bytecode);
    let vulnerabilities = detector.detect_vulnerabilities();

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::MEVVulnerability,
            severity: vuln.severity,
            pc: vuln.location as u64,
            description: vuln.description.clone(),
            operations: vec![],
            remediation: "Implement time-delay protection".to_string(),
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_manipulation() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x01, // PUSH1 1
            0x14, // EQ (exact match - risky)
        ];
        
        let detector = TimeAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(v.attack_type, TimeAttackType::TimestampManipulation)));
    }

    #[test]
    fn test_oracle_timing() {
        let bytecode = vec![
            0x63, 0x50, 0xd2, 0x5b, 0xcd, // latestRoundData()
            0xfa, // STATICCALL
            // No timestamp validation
            0x55, // SSTORE
        ];
        
        let detector = TimeAttackDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.attack_type, TimeAttackType::OracleTimingExploit)));
    }
}
