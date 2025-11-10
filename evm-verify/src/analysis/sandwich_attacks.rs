use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::{H160, H256};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Types of sandwich attack patterns
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandwichAttackType {
    /// Classic front-run + back-run sandwich
    ClassicSandwich,
    /// MEV sandwich through block building
    MevSandwich,
    /// Cross-pool sandwich attack
    CrossPoolSandwich,
    /// Time-based sandwich using block delays
    TimeBasedSandwich,
    /// Governance sandwich (front-run governance actions)
    GovernanceSandwich,
    /// Oracle sandwich (front-run oracle updates)
    OracleSandwich,
}

/// Information about a detected sandwich attack vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandwichVulnerability {
    /// Type of sandwich attack
    pub attack_type: SandwichAttackType,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Vulnerable code location
    pub location: usize,
    /// Description of the vulnerability
    pub description: String,
    /// Estimated MEV extraction potential (in basis points)
    pub mev_potential: u64,
    /// Recommended mitigation
    pub mitigation: String,
}

/// Advanced sandwich attack detection with MEV analysis
pub struct SandwichAttackDetector {
    /// Bytecode being analyzed
    bytecode: Vec<u8>,
    /// Known DEX router addresses
    dex_routers: HashMap<H160, String>,
    /// Known AMM pool patterns
    amm_patterns: Vec<Vec<u8>>,
}

impl SandwichAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        // NEUTRAL: No hardcoded addresses - detect ANY DEX by pattern
        let dex_routers = HashMap::new(); // Empty - will detect dynamically
        
        // Generic AMM swap patterns (protocol-agnostic)
        // These patterns are common across ALL AMMs
        let amm_patterns = vec![
            // Generic "swap exact input" pattern (4-byte function selector)
            vec![0x38, 0xed, 0x17, 0x39],
            vec![0x8c, 0x03, 0xf3, 0x12],
            vec![0x7f, 0xf3, 0x6a, 0xb5],
            vec![0x49, 0x16, 0xd5, 0xd7],
            vec![0x18, 0xcb, 0xaf, 0xe5],
            vec![0xfb, 0x3b, 0xdb, 0x41],
            vec![0x41, 0x4b, 0xf3, 0x89],
            vec![0xdb, 0x3e, 0x21, 0x98],
            // Add more generic patterns as needed
        ];

        Self {
            bytecode,
            dex_routers,
            amm_patterns,
        }
    }

    /// Detect all types of sandwich attack vulnerabilities
    pub fn detect_vulnerabilities(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect classic sandwich attacks
        vulnerabilities.extend(self.detect_classic_sandwich());
        
        // Detect MEV-based sandwich attacks
        vulnerabilities.extend(self.detect_mev_sandwich());
        
        // Detect cross-pool sandwich opportunities
        vulnerabilities.extend(self.detect_cross_pool_sandwich());
        
        // Detect time-based sandwich vulnerabilities
        vulnerabilities.extend(self.detect_time_based_sandwich());
        
        // Detect governance sandwich opportunities
        vulnerabilities.extend(self.detect_governance_sandwich());
        
        // Detect oracle sandwich vulnerabilities
        vulnerabilities.extend(self.detect_oracle_sandwich());

        vulnerabilities
    }

    /// Detect classic front-run/back-run sandwich patterns
    fn detect_classic_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for swap function calls without sufficient protection
            if self.has_swap_function_call(i) {
                // Check for missing slippage protection
                if !self.has_adequate_slippage_protection(i) {
                    // Check for predictable transaction ordering
                    if self.has_predictable_ordering(i) {
                        vulnerabilities.push(SandwichVulnerability {
                            attack_type: SandwichAttackType::ClassicSandwich,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Contract performs swaps without adequate slippage protection, enabling sandwich attacks".to_string(),
                            mev_potential: self.estimate_mev_potential(i),
                            mitigation: "Implement strict slippage limits and consider commit-reveal schemes for large trades".to_string(),
                        });
                    }
                }
                
                // Check for missing deadline protection
                if !self.has_deadline_protection(i) {
                    vulnerabilities.push(SandwichVulnerability {
                        attack_type: SandwichAttackType::ClassicSandwich,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Swap operations lack deadline protection, enabling time-based manipulation".to_string(),
                        mev_potential: self.estimate_mev_potential(i) / 2,
                        mitigation: "Add strict deadline parameters to all swap operations".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect MEV-based sandwich attacks through block building
    fn detect_mev_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for large value transfers that could attract MEV
            if self.has_large_value_transfer(i) {
                // Check if transfer is atomic with price-sensitive operations
                if self.has_atomic_price_operation(i) {
                    // Check for missing MEV protection
                    if !self.has_mev_protection(i) {
                        vulnerabilities.push(SandwichVulnerability {
                            attack_type: SandwichAttackType::MevSandwich,
                            severity: SecuritySeverity::Critical,
                            location: i,
                            description: "Large atomic operations without MEV protection enable block-builder sandwich attacks".to_string(),
                            mev_potential: self.estimate_mev_potential(i) * 2, // Higher potential
                            mitigation: "Implement private mempool solutions or MEV-resistant patterns".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect cross-pool arbitrage sandwich opportunities
    fn detect_cross_pool_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for interactions with multiple DEX protocols
        let mut dex_interactions = 0;
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if self.has_multi_dex_interaction(i) {
                dex_interactions += 1;
            }
        }

        if dex_interactions >= 2 {
            // Check for cross-pool price inconsistency risks
            for i in 0..self.bytecode.len().saturating_sub(50) {
                if self.has_cross_pool_vulnerability(i) {
                    vulnerabilities.push(SandwichVulnerability {
                        attack_type: SandwichAttackType::CrossPoolSandwich,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Cross-pool operations create arbitrage opportunities for sandwich attacks".to_string(),
                        mev_potential: self.estimate_cross_pool_mev(i),
                        mitigation: "Implement cross-pool price checks and atomic execution patterns".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect time-based sandwich attacks using block delays
    fn detect_time_based_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for time-dependent operations
            if self.has_time_dependency(i) {
                // Check for sandwich vulnerability in time windows
                if self.has_time_window_vulnerability(i) {
                    vulnerabilities.push(SandwichVulnerability {
                        attack_type: SandwichAttackType::TimeBasedSandwich,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Time-dependent operations create windows for sandwich attacks".to_string(),
                        mev_potential: self.estimate_time_based_mev(i),
                        mitigation: "Minimize time windows and add randomization to sensitive operations".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect governance sandwich attacks
    fn detect_governance_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for governance parameter changes
            if self.has_governance_parameter_change(i) {
                // Check for front-runnable governance actions
                if self.is_governance_front_runnable(i) {
                    vulnerabilities.push(SandwichVulnerability {
                        attack_type: SandwichAttackType::GovernanceSandwich,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Governance changes can be front-run for profit extraction".to_string(),
                        mev_potential: self.estimate_governance_mev(i),
                        mitigation: "Implement time delays and commit-reveal for governance changes".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Detect oracle update sandwich attacks
    fn detect_oracle_sandwich(&self) -> Vec<SandwichVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for oracle price usage
            if self.has_oracle_price_usage(i) {
                // Check for front-runnable oracle updates
                if self.is_oracle_front_runnable(i) {
                    vulnerabilities.push(SandwichVulnerability {
                        attack_type: SandwichAttackType::OracleSandwich,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Oracle price updates can be front-run for arbitrage profits".to_string(),
                        mev_potential: self.estimate_oracle_mev(i),
                        mitigation: "Use TWAP oracles and implement oracle update delays".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    // Helper methods for pattern detection

    fn has_swap_function_call(&self, pos: usize) -> bool {
        for pattern in &self.amm_patterns {
            if pos + pattern.len() <= self.bytecode.len() {
                if self.bytecode[pos..pos + pattern.len()] == *pattern {
                    return true;
                }
            }
        }
        false
    }

    fn has_adequate_slippage_protection(&self, pos: usize) -> bool {
        // Look for slippage parameters in surrounding bytecode
        let start = pos.saturating_sub(50);
        let end = std::cmp::min(pos + 50, self.bytecode.len());
        
        for i in start..end.saturating_sub(4) {
            // Look for percentage calculations (typically slippage)
            if self.bytecode[i] == 0x64 && // PUSH1 100 (for percentage)
               i + 10 < self.bytecode.len() &&
               self.bytecode[i + 2] == 0x04 { // DIV opcode
                return true;
            }
        }
        false
    }

    fn has_predictable_ordering(&self, pos: usize) -> bool {
        // Check if transaction ordering can be predicted
        // Look for absence of randomization or commit-reveal patterns
        let start = pos.saturating_sub(30);
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        
        // Look for randomization patterns (timestamp, blockhash usage)
        for i in start..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0x42 => return false, // TIMESTAMP
                    0x40 => return false, // BLOCKHASH
                    _ => {}
                }
            }
        }
        true // Predictable if no randomization found
    }

    fn has_deadline_protection(&self, pos: usize) -> bool {
        // Look for deadline parameters
        let start = pos.saturating_sub(40);
        let end = std::cmp::min(pos + 40, self.bytecode.len());
        
        for i in start..end {
            if i < self.bytecode.len() && self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if timestamp is used in comparison
                if i + 5 < self.bytecode.len() {
                    match self.bytecode[i + 2] {
                        0x10 => return true, // LT
                        0x11 => return true, // GT  
                        0x14 => return true, // EQ
                        _ => {}
                    }
                }
            }
        }
        false
    }

    fn has_large_value_transfer(&self, pos: usize) -> bool {
        // Look for large PUSH operations indicating significant value
        if pos + 10 < self.bytecode.len() {
            // Check for PUSH4 or larger with significant values
            match self.bytecode[pos] {
                0x63..=0x7f => { // PUSH4 to PUSH32
                    let push_size = (self.bytecode[pos] - 0x5f) as usize;
                    if push_size >= 4 && pos + push_size < self.bytecode.len() {
                        // Check if value is significant (> 1000 in any unit)
                        let value_bytes = &self.bytecode[pos + 1..pos + 1 + push_size];
                        let value = value_bytes.iter().fold(0u64, |acc, &b| {
                            acc.saturating_mul(256).saturating_add(b as u64)
                        });
                        return value > 1000;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn has_atomic_price_operation(&self, pos: usize) -> bool {
        // Check if price-sensitive operations occur in same transaction context
        let start = pos.saturating_sub(20);
        let end = std::cmp::min(pos + 20, self.bytecode.len());
        
        let mut has_price_read = false;
        let mut has_state_change = false;
        
        for i in start..end {
            if i < self.bytecode.len() {
                match self.bytecode[i] {
                    0xfa => has_price_read = true,  // STATICCALL (often price reads)
                    0x55 => has_state_change = true, // SSTORE
                    _ => {}
                }
            }
        }
        
        has_price_read && has_state_change
    }

    fn has_mev_protection(&self, pos: usize) -> bool {
        // Look for MEV protection patterns
        let start = pos.saturating_sub(50);
        let end = std::cmp::min(pos + 50, self.bytecode.len());
        
        for i in start..end.saturating_sub(4) {
            // Look for commit-reveal patterns (hash operations)
            if self.bytecode[i] == 0x20 { // SHA3
                return true;
            }
            // Look for private mempool signatures
            if self.bytecode[i..i+4] == [0x84, 0x32, 0xa1, 0xc8] { // Example private pool signature
                return true;
            }
        }
        false
    }

    // Additional helper methods with simplified implementations
    fn has_multi_dex_interaction(&self, pos: usize) -> bool {
        // Simplified: look for multiple different swap signatures
        self.has_swap_function_call(pos)
    }

    fn has_cross_pool_vulnerability(&self, pos: usize) -> bool {
        // Look for operations that span multiple pools without proper price checks
        self.has_swap_function_call(pos) && !self.has_adequate_slippage_protection(pos)
    }

    fn has_time_dependency(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0x42 // TIMESTAMP
    }

    fn has_time_window_vulnerability(&self, pos: usize) -> bool {
        self.has_time_dependency(pos) && !self.has_adequate_slippage_protection(pos)
    }

    fn has_governance_parameter_change(&self, pos: usize) -> bool {
        // Look for admin/owner function signatures
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x8d, 0xa5, 0xcb, 0x5b] || // changeAdmin
            self.bytecode[pos..pos+4] == [0xf2, 0xfb, 0x5d, 0xb9]    // setParameter
        )
    }

    fn is_governance_front_runnable(&self, pos: usize) -> bool {
        // Check if governance action lacks time delay
        !self.has_time_delay_after_governance(pos)
    }

    fn has_time_delay_after_governance(&self, pos: usize) -> bool {
        // Look for time delay patterns after governance calls
        let end = std::cmp::min(pos + 30, self.bytecode.len());
        for i in pos..end {
            if i < self.bytecode.len() && self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn has_oracle_price_usage(&self, pos: usize) -> bool {
        // Look for oracle function signatures
        pos + 4 <= self.bytecode.len() && (
            self.bytecode[pos..pos+4] == [0x50, 0xd2, 0x5b, 0xcd] || // latestRoundData
            self.bytecode[pos..pos+4] == [0xfe, 0xaf, 0x96, 0x8c]    // latestAnswer
        )
    }

    fn is_oracle_front_runnable(&self, pos: usize) -> bool {
        // Check if oracle usage lacks proper time buffers
        !self.has_oracle_time_buffer(pos)
    }

    fn has_oracle_time_buffer(&self, pos: usize) -> bool {
        // Look for TWAP or time-delayed oracle patterns
        self.has_time_dependency(pos + 10)
    }

    // MEV estimation methods
    fn estimate_mev_potential(&self, pos: usize) -> u64 {
        let mut potential = 100; // Base MEV potential in basis points
        
        if self.has_large_value_transfer(pos) {
            potential += 200;
        }
        if !self.has_adequate_slippage_protection(pos) {
            potential += 300;
        }
        if !self.has_deadline_protection(pos) {
            potential += 100;
        }
        
        potential.min(1000) // Cap at 10%
    }

    fn estimate_cross_pool_mev(&self, pos: usize) -> u64 {
        self.estimate_mev_potential(pos) + 150 // Higher for cross-pool
    }

    fn estimate_time_based_mev(&self, pos: usize) -> u64 {
        self.estimate_mev_potential(pos) / 2 // Lower for time-based
    }

    fn estimate_governance_mev(&self, pos: usize) -> u64 {
        500 // High MEV potential for governance front-running
    }

    fn estimate_oracle_mev(&self, pos: usize) -> u64 {
        800 // Very high MEV potential for oracle manipulation
    }
}

/// Main detection function for integration
pub fn detect_sandwich_attacks(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let bytecode = analyzer.get_bytecode_vec();
    let detector = SandwichAttackDetector::new(bytecode);
    let vulnerabilities = detector.detect_vulnerabilities();

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::MEVVulnerability,
            severity: vuln.severity,
            pc: vuln.location as u64,
            description: vuln.description,
            operations: vec![],
            remediation: vuln.mitigation,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_sandwich_detection() {
        // Test bytecode with swap call but no slippage protection
        let bytecode = vec![
            0x63, 0x38, 0xed, 0x17, 0x39, // PUSH4 swapExactTokensForTokens
            0xf1, // CALL
            0x55, // SSTORE (state change)
        ];
        
        let detector = SandwichAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, SandwichAttackType::ClassicSandwich)));
    }

    #[test]
    fn test_mev_sandwich_detection() {
        // Test bytecode with large value transfer and atomic price operation
        let bytecode = vec![
            0x67, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // PUSH8 large value
            0xfa, // STATICCALL (price read)
            0x55, // SSTORE (state change)
        ];
        
        let detector = SandwichAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, SandwichAttackType::MevSandwich)));
    }

    #[test]
    fn test_oracle_sandwich_detection() {
        // Test bytecode with oracle call
        let bytecode = vec![
            0x63, 0x50, 0xd2, 0x5b, 0xcd, // PUSH4 latestRoundData
            0xfa, // STATICCALL
            0x55, // SSTORE
        ];
        
        let detector = SandwichAttackDetector::new(bytecode);
        let vulnerabilities = detector.detect_vulnerabilities();
        
        assert!(vulnerabilities.iter().any(|v| matches!(v.attack_type, SandwichAttackType::OracleSandwich)));
    }
}
