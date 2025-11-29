// MEV Extraction Vulnerability Detector
// Detects when users are systematically losing value to MEV bots (not a "hack" but significant value extraction)

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEVExtractionVulnerability {
    pub vulnerability_type: MEVExtractionType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub expected_mev_per_tx: u128,      // Expected MEV extracted per transaction
    pub annual_user_loss: u128,          // Estimated annual loss to users
    pub affected_functions: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MEVExtractionType {
    NoSlippageProtection,     // Users can be sandwiched
    NoDeadlineCheck,          // Transactions can be delayed
    PredictableOrderFlow,     // Order flow is predictable
    FrontrunVulnerable,       // Critical operations can be frontrun
    BackrunVulnerable,        // Operations create profitable backrun opportunities
    TimeDelayExploit,         // Delayed execution creates MEV
}

pub struct MEVExtractionDetector {
    bytecode: Vec<u8>,
}

impl MEVExtractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<MEVExtractionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_no_slippage_protection());
        vulnerabilities.extend(self.detect_no_deadline_check());
        vulnerabilities.extend(self.detect_predictable_order_flow());
        vulnerabilities.extend(self.detect_frontrun_vulnerable());

        vulnerabilities
    }

    /// Detect swaps without slippage protection
    fn detect_no_slippage_protection(&self) -> Vec<MEVExtractionVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: swap() function that doesn't check minAmountOut
        // Look for: External call to Uniswap/DEX without amount check

        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for swap pattern
            if i + 30 <= self.bytecode.len() && self.is_swap_function(&self.bytecode[i..i+30]) {
                // Check if it validates minimum output amount
                if i + 50 <= self.bytecode.len() && !self.has_slippage_check(&self.bytecode[i..i+50]) {
                    vulns.push(MEVExtractionVulnerability {
                        vulnerability_type: MEVExtractionType::NoSlippageProtection,
                        severity: SecuritySeverity::High,
                        description: "Swap function lacks slippage protection - users will be sandwiched by MEV bots".to_string(),
                        expected_mev_per_tx: 20_000_000_000_000_000u128, // 0.02 ETH per swap
                        annual_user_loss: 10_000_000_000_000_000_000_000u128, // $10M/year
                        affected_functions: vec!["swap".to_string(), "swapExactTokensForTokens".to_string()],
                        remediation: "Add minAmountOut parameter and check: require(amountOut >= minAmountOut)".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detect transactions without deadline check
    fn detect_no_deadline_check(&self) -> Vec<MEVExtractionVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: swap() without deadline parameter
        // Allows transactions to sit in mempool indefinitely

        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_swap_function(&self.bytecode[i..i+30]) {
                if !self.has_deadline_check(&self.bytecode[i..i+40]) {
                    vulns.push(MEVExtractionVulnerability {
                        vulnerability_type: MEVExtractionType::NoDeadlineCheck,
                        severity: SecuritySeverity::Medium,
                        description: "No deadline check - transactions can be delayed until unfavorable".to_string(),
                        expected_mev_per_tx: 10_000_000_000_000_000u128, // 0.01 ETH
                        annual_user_loss: 5_000_000_000_000_000_000_000u128, // $5M/year
                        affected_functions: vec!["swap".to_string()],
                        remediation: "Add deadline parameter: require(block.timestamp <= deadline)".to_string(),
                    });
                }
            }
        }

        vulns
    }

    /// Detect predictable order flow
    fn detect_predictable_order_flow(&self) -> Vec<MEVExtractionVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Events emitted before state changes (frontrunnable)
        // LOG before SSTORE allows frontrunning

        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] >= 0xA0 && self.bytecode[i] <= 0xA4 {  // LOG opcodes
                // Check if SSTORE comes after
                if self.has_sstore_after(i, 20) {
                    vulns.push(MEVExtractionVulnerability {
                        vulnerability_type: MEVExtractionType::PredictableOrderFlow,
                        severity: SecuritySeverity::Medium,
                        description: "Event emitted before state change - creates frontrunning opportunity".to_string(),
                        expected_mev_per_tx: 5_000_000_000_000_000u128,
                        annual_user_loss: 2_000_000_000_000_000_000_000u128,
                        affected_functions: vec!["various".to_string()],
                        remediation: "Emit events AFTER state changes to reduce frontrunning window".to_string(),
                    });
                    break;
                }
            }
        }

        vulns
    }

    /// Detect frontrun-vulnerable operations
    fn detect_frontrun_vulnerable(&self) -> Vec<MEVExtractionVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: approve() or similar that can be frontrun
        // CALLER, PUSH(approval), SSTORE without nonce/deadline

        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.is_approve_pattern(&self.bytecode[i..i+15]) {
                if !self.has_nonce_check(&self.bytecode[i..i+30]) {
                    vulns.push(MEVExtractionVulnerability {
                        vulnerability_type: MEVExtractionType::FrontrunVulnerable,
                        severity: SecuritySeverity::High,
                        description: "approve() can be frontrun - attacker can use old approval before new one".to_string(),
                        expected_mev_per_tx: 50_000_000_000_000_000u128, // 0.05 ETH
                        annual_user_loss: 20_000_000_000_000_000_000_000u128, // $20M/year
                        affected_functions: vec!["approve".to_string()],
                        remediation: "Use increaseAllowance/decreaseAllowance or EIP-2612 permit()".to_string(),
                    });
                }
            }
        }

        vulns
    }

    // === HELPER METHODS ===

    fn is_swap_function(&self, bytecode: &[u8]) -> bool {
        // Look for pattern indicating DEX swap
        // CALL to Uniswap router or similar
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0xF1 || bytecode[i] == 0xF2 {  // CALL or CALLCODE
                return true;
            }
        }
        false
    }

    fn has_slippage_check(&self, bytecode: &[u8]) -> bool {
        // Look for: amountOut >= minAmountOut check
        // Pattern: PUSH(amount), PUSH(minAmount), LT, ISZERO, JUMPI (require)
        for i in 0..bytecode.len().saturating_sub(10) {
            if bytecode[i] == 0x10 || bytecode[i] == 0x12 {  // LT or SLT
                // Check if followed by ISZERO and JUMPI (require pattern)
                if i + 2 < bytecode.len() && 
                   bytecode[i+1] == 0x15 &&  // ISZERO
                   bytecode[i+2] == 0x57 {   // JUMPI
                    return true;
                }
            }
        }
        false
    }

    fn has_deadline_check(&self, bytecode: &[u8]) -> bool {
        // Look for: block.timestamp <= deadline
        // Pattern: TIMESTAMP, PUSH(deadline), GT (or similar)
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0x42 {  // TIMESTAMP
                // Check if used in comparison
                if i + 3 < bytecode.len() && 
                   (bytecode[i+2] == 0x11 || bytecode[i+2] == 0x10) {  // GT or LT
                    return true;
                }
            }
        }
        false
    }

    fn has_sstore_after(&self, offset: usize, range: usize) -> bool {
        let end = (offset + range).min(self.bytecode.len());
        for i in offset..end {
            if self.bytecode[i] == 0x55 {  // SSTORE
                return true;
            }
        }
        false
    }

    fn is_approve_pattern(&self, bytecode: &[u8]) -> bool {
        // Pattern: CALLER, PUSH, PUSH, SSTORE (approval storage update)
        bytecode.len() >= 6 &&
        bytecode[0] == 0x33 &&  // CALLER
        (bytecode[1] == 0x60 || bytecode[1] == 0x61) &&  // PUSH
        bytecode[bytecode.len()-1] == 0x55  // SSTORE
    }

    fn has_nonce_check(&self, bytecode: &[u8]) -> bool {
        // Look for nonce increment (SLOAD, PUSH1 1, ADD, SSTORE pattern)
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0x54 &&      // SLOAD
               i + 3 < bytecode.len() &&
               bytecode[i+1] == 0x60 &&    // PUSH1
               bytecode[i+2] == 0x01 &&    // 1
               bytecode[i+3] == 0x01 {     // ADD
                return true;
            }
        }
        false
    }
}

/// Calculate total MEV extraction impact
pub fn calculate_mev_impact(vulnerabilities: &[MEVExtractionVulnerability]) -> MEVImpactReport {
    let total_annual_loss: u128 = vulnerabilities.iter()
        .map(|v| v.annual_user_loss)
        .sum();

    let total_per_tx: u128 = vulnerabilities.iter()
        .map(|v| v.expected_mev_per_tx)
        .sum();

    MEVImpactReport {
        total_vulnerabilities: vulnerabilities.len(),
        expected_mev_per_transaction: total_per_tx,
        estimated_annual_user_loss: total_annual_loss,
        affected_user_percentage: if vulnerabilities.is_empty() { 0.0 } else { 80.0 }, // Estimate
        recommendation: if total_annual_loss > 1_000_000_000_000_000_000_000u128 {
            "CRITICAL: Users losing >$1M/year to MEV. Add slippage + deadline protection immediately.".to_string()
        } else if total_annual_loss > 100_000_000_000_000_000_000u128 {
            "HIGH: Significant MEV extraction. Recommend adding protections.".to_string()
        } else {
            "LOW: MEV risk is manageable.".to_string()
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MEVImpactReport {
    pub total_vulnerabilities: usize,
    pub expected_mev_per_transaction: u128,
    pub estimated_annual_user_loss: u128,
    pub affected_user_percentage: f64,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_no_slippage() {
        // Bytecode with CALL but no amount check
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL (swap)
            // No LT/GT check for minAmountOut
        ];
        
        let detector = MEVExtractionDetector::new(bytecode);
        let vulns = detector.detect_no_slippage_protection();
        
        assert!(vulns.len() > 0, "Should detect missing slippage protection");
    }

    #[test]
    fn test_mev_impact_calculation() {
        let vulns = vec![
            MEVExtractionVulnerability {
                vulnerability_type: MEVExtractionType::NoSlippageProtection,
                severity: SecuritySeverity::High,
                description: "test".to_string(),
                expected_mev_per_tx: 10_000_000_000_000_000u128,
                annual_user_loss: 1_000_000_000_000_000_000_000u128,
                affected_functions: vec![],
                remediation: "test".to_string(),
            }
        ];

        let report = calculate_mev_impact(&vulns);
        assert!(report.estimated_annual_user_loss > 0);
        assert!(report.total_vulnerabilities == 1);
    }
}
