// Katana Finance Tranched Vault Waterfall Detector
// Detects manipulation in multi-tranche structured products with priority waterfalls

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KatanaTrancheVulnerability {
    pub location: usize,
    pub vulnerability_type: KatanaVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KatanaVulnerabilityType {
    WaterfallOrderingManipulation,  // Tranche priority incorrectly ordered
    DefaultEventGaming,             // Gaming of default/loss classification
    TrancheRebalancingExploit,      // Exploit during tranche rebalancing
    SubordinationRatioViolation,    // Subordination requirements not enforced
    InterestDistributionUnfair,     // Interest allocated incorrectly across tranches
    JuniorTrancheGriefing,          // Senior tranche drains junior unfairly
    LossAllocationRounding,         // Rounding errors in loss allocation
}

pub struct KatanaTrancheDetector {
    bytecode: Vec<u8>,
}

impl KatanaTrancheDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<KatanaTrancheVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_waterfall_ordering_manipulation() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::WaterfallOrderingManipulation,
                severity: SecuritySeverity::Critical,
                description: "Tranche waterfall distribution order is not enforced. Senior tranches \
                             should be paid before junior, but implementation allows reversed payments \
                             draining junior tranche holders.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_default_gaming() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::DefaultEventGaming,
                severity: SecuritySeverity::High,
                description: "Default event detection uses manipulable price oracle. Attacker can \
                             trigger false default to force loss allocation and drain junior tranches.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_tranche_rebalancing_exploit() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::TrancheRebalancingExploit,
                severity: SecuritySeverity::High,
                description: "Tranche rebalancing allows withdrawals mid-rebalance. User can withdraw \
                             from junior tranche after seeing senior gets paid but before losses allocated.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_subordination_violation() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::SubordinationRatioViolation,
                severity: SecuritySeverity::Critical,
                description: "Senior/junior subordination ratio not enforced on deposits. Senior tranche \
                             can grow too large relative to junior, violating safety constraints.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_interest_distribution_unfair() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::InterestDistributionUnfair,
                severity: SecuritySeverity::Medium,
                description: "Interest distribution uses fixed percentages without considering actual \
                             tranche sizes. Leads to incorrect yield attribution between tranches.".to_string(),
                confidence: 0.77,
            });
        }

        if let Some(loc) = self.detect_junior_griefing() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::JuniorTrancheGriefing,
                severity: SecuritySeverity::High,
                description: "Senior tranche withdrawal can drain junior protection buffer. No minimum \
                             junior balance requirement after senior withdrawals.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_loss_allocation_rounding() {
            vulnerabilities.push(KatanaTrancheVulnerability {
                location: loc,
                vulnerability_type: KatanaVulnerabilityType::LossAllocationRounding,
                severity: SecuritySeverity::Medium,
                description: "Loss allocation rounds down losses to senior tranche. Accumulated rounding \
                             errors unfairly burden junior tranche holders over time.".to_string(),
                confidence: 0.73,
            });
        }

        vulnerabilities
    }

    fn detect_waterfall_ordering_manipulation(&self) -> Option<usize> {
        // Pattern: Multiple SSTOREs (tranche payments) without proper ordering enforcement
        // Should see: GT/LT checks between each SSTORE to enforce waterfall
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            let mut sstore_count = 0;
            let mut has_ordering_check = false;
            let start_loc = i;
            
            for j in i..(i+35).min(self.bytecode.len()) {
                if self.bytecode[j] == 0x55 {  // SSTORE (tranche payment)
                    sstore_count += 1;
                    
                    // Check if there's ordering verification after first payment
                    if sstore_count == 1 {
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            // Look for comparison (senior paid first check)
                            if self.bytecode[k] == 0x11 || self.bytecode[k] == 0x10 {  // GT/LT
                                has_ordering_check = true;
                            }
                        }
                    }
                }
                
                // Multiple payments without ordering
                if sstore_count >= 2 && !has_ordering_check {
                    return Some(start_loc);
                }
            }
        }
        None
    }

    fn detect_default_gaming(&self) -> Option<usize> {
        // Pattern: Default detection from single oracle without consensus
        // CALL (oracle) → LT (threshold) → SSTORE (default flag) without additional validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL (oracle)
                let mut oracle_calls = 1;
                let mut has_threshold_check = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                        oracle_calls += 1;
                    }
                    
                    if self.bytecode[j] == 0x10 {  // LT (value < threshold)
                        has_threshold_check = true;
                    }
                    
                    // Single oracle triggers default
                    if has_threshold_check && oracle_calls == 1 && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_tranche_rebalancing_exploit(&self) -> Option<usize> {
        // Pattern: Withdrawal allowed during rebalancing state
        // SLOAD (rebalancing flag) → ISZERO → withdrawal without proper lock
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD
                let mut checks_rebalancing = false;
                let mut has_strict_lock = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 {  // ISZERO (not rebalancing)
                        checks_rebalancing = true;
                    }
                    
                    // Strict lock would have REVERT, not JUMPI
                    if checks_rebalancing && self.bytecode[j] == 0xFD {  // REVERT
                        has_strict_lock = true;
                    }
                    
                    // Weak protection with JUMPI allows bypass
                    if checks_rebalancing && !has_strict_lock && self.bytecode[j] == 0x57 {  // JUMPI
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_subordination_violation(&self) -> Option<usize> {
        // Pattern: Deposit without checking senior/junior ratio
        // SSTORE (deposit) without prior ratio validation (DIV + LT)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 {  // SSTORE (likely deposit)
                let mut has_ratio_check = false;
                
                // Check preceding opcodes for ratio validation
                for j in (i.saturating_sub(15))..i {
                    // Ratio check: DIV followed by LT/GT
                    if self.bytecode[j] == 0x04 {  // DIV
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                has_ratio_check = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like a deposit (multiple SLOADs before)
                let mut storage_reads = 0;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x54 {
                        storage_reads += 1;
                    }
                }
                
                if storage_reads >= 2 && !has_ratio_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_interest_distribution_unfair(&self) -> Option<usize> {
        // Pattern: Interest calc with fixed multiplier instead of actual tranche sizes
        // MUL (fixed rate) → DIV → SSTORE without SLOAD (tranche balance)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 {  // MUL (interest)
                let mut has_division = false;
                let mut loads_tranche_balance = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        has_division = true;
                    }
                    
                    if self.bytecode[j] == 0x54 {  // SLOAD (tranche balance)
                        loads_tranche_balance = true;
                    }
                    
                    // Fixed rate without considering sizes
                    if has_division && !loads_tranche_balance && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_junior_griefing(&self) -> Option<usize> {
        // Pattern: Senior withdrawal without checking remaining junior balance
        // SUB (senior withdraw) → SSTORE without LT check on junior minimum
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x03 {  // SUB (withdrawal)
                let mut has_withdrawal = false;
                let mut checks_junior_min = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (update balance)
                        has_withdrawal = true;
                    }
                    
                    // Check for junior balance validation
                    if self.bytecode[j] == 0x54 {  // SLOAD (junior balance)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (min check)
                                checks_junior_min = true;
                            }
                        }
                    }
                    
                    if has_withdrawal && !checks_junior_min {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_loss_allocation_rounding(&self) -> Option<usize> {
        // Pattern: Loss division without proper rounding or remainder tracking
        // SUB (loss) → DIV (allocate) without ADD (round up) or MOD tracking
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x03 {  // SUB (calculate loss)
                let mut has_division = false;
                let mut has_rounding = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 {  // DIV
                        has_division = true;
                    }
                    
                    // Rounding: ADD after DIV
                    if has_division && self.bytecode[j] == 0x01 {  // ADD
                        has_rounding = true;
                    }
                    
                    // Or MOD for remainder tracking
                    if self.bytecode[j] == 0x06 {  // MOD
                        has_rounding = true;
                    }
                    
                    if has_division && !has_rounding && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::KatanaFinance,
                severity: v.severity,
                description: format!(
                    "Katana Tranche {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waterfall_ordering() {
        let bytecode = vec![
            0x60, 0x64, // PUSH1 100 (senior payment)
            0x55, // SSTORE (pay senior)
            0x60, 0x32, // PUSH1 50 (junior payment)
            0x55, // SSTORE (pay junior - no ordering check)
        ];
        
        let detector = KatanaTrancheDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, KatanaVulnerabilityType::WaterfallOrderingManipulation)));
    }

    #[test]
    fn test_loss_rounding() {
        let bytecode = vec![
            0x03, // SUB (calculate loss)
            0x60, 0x02, // PUSH1 2
            0x04, // DIV (split loss)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no rounding)
        ];
        
        let detector = KatanaTrancheDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, KatanaVulnerabilityType::LossAllocationRounding)));
    }
}
