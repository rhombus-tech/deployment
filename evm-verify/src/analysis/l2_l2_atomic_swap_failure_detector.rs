// L2→L2 Atomic Swap Failure Detector
// Detects multi-hop settlement failures in cross-rollup atomic swaps

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2AtomicSwapVulnerability {
    pub location: usize,
    pub vulnerability_type: L2AtomicSwapFailureType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum L2AtomicSwapFailureType {
    PartialSettlementFailure,      // One leg settles, other fails
    TimeLockMismatch,               // Asymmetric timelock windows
    ReorgVulnerability,             // L2 reorg breaks atomicity
    BridgeDelayExploitation,        // Message delay causes swap failure
    HashLockCollision,              // Preimage collision in HTLC
    MultiHopRoutingFailure,         // Intermediate hop fails
}

pub struct L2AtomicSwapDetector {
    bytecode: Vec<u8>,
}

impl L2AtomicSwapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<L2AtomicSwapVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_partial_settlement_failure() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::PartialSettlementFailure,
                severity: SecuritySeverity::Critical,
                description: "Atomic swap lacks full rollback mechanism. If one leg fails after \
                             the other settles, funds are lost without recovery path.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_timelock_mismatch() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::TimeLockMismatch,
                severity: SecuritySeverity::High,
                description: "Timelock windows asymmetric across L2s. One side can claim while \
                             the other is still locked, breaking atomicity.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_reorg_vulnerability() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::ReorgVulnerability,
                severity: SecuritySeverity::High,
                description: "Swap settlement not finalized before proceeding. L2 reorg can \
                             reverse one leg after the other completes.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_bridge_delay_exploitation() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::BridgeDelayExploitation,
                severity: SecuritySeverity::High,
                description: "Bridge message delay not accounted for in timelock. Message can \
                             arrive after refund period causing double-spend.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_hashlock_collision() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::HashLockCollision,
                severity: SecuritySeverity::Medium,
                description: "Hash lock uses weak hash or insufficient entropy. Preimage \
                             collision possible allowing unauthorized swap completion.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_multihop_routing_failure() {
            vulnerabilities.push(L2AtomicSwapVulnerability {
                location: loc,
                vulnerability_type: L2AtomicSwapFailureType::MultiHopRoutingFailure,
                severity: SecuritySeverity::Critical,
                description: "Multi-hop route lacks intermediate failure handling. Single hop \
                             failure leaves funds locked across multiple chains.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_partial_settlement_failure(&self) -> Option<usize> {
        // Pattern: Settlement on one chain without verification of other chain
        // CALL to settle without checking counterparty settlement
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (settle swap leg)
                let mut has_settlement = true;
                let mut checks_counterparty = false;
                
                // Check for counterparty settlement verification
                for j in (i.saturating_sub(25))..i {
                    // STATICCALL to check other chain's state
                    if self.bytecode[j] == 0xFA {
                        checks_counterparty = true;
                    }
                }
                
                if has_settlement && !checks_counterparty {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_timelock_mismatch(&self) -> Option<usize> {
        // Pattern: Timelock comparison without accounting for cross-chain delays
        // Two different timelock values without coordination
        
        let mut timelock_values = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_comparison = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_comparison = true;
                        timelock_values.push(i);
                    }
                }
            }
        }
        
        // Multiple timelocks without verification they're coordinated
        if timelock_values.len() >= 2 {
            return Some(timelock_values[0]);
        }
        
        None
    }

    fn detect_reorg_vulnerability(&self) -> Option<usize> {
        // Pattern: Settlement without finality check
        // Immediate execution without waiting for finalization
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (record settlement)
                let mut is_settlement = false;
                let mut checks_finality = false;
                
                // Check if this is swap settlement (multiple SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                is_settlement = sstore_count >= 2;
                
                // Check for finality verification (block confirmations)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x43 {  // NUMBER (block number)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (confirmations check)
                                checks_finality = true;
                            }
                        }
                    }
                }
                
                if is_settlement && !checks_finality {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_bridge_delay_exploitation(&self) -> Option<usize> {
        // Pattern: Timelock without bridge delay buffer
        // Refund available before cross-chain message can arrive
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_refund = false;
                let mut has_delay_buffer = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Refund logic
                    if self.bytecode[j] == 0xF1 {  // CALL (refund)
                        has_refund = true;
                    }
                    
                    // Delay buffer: additional time beyond basic timeout
                    // Look for addition to timelock value
                    if self.bytecode[j] == 0x01 {  // ADD (buffer time)
                        has_delay_buffer = true;
                    }
                }
                
                if has_refund && !has_delay_buffer {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_hashlock_collision(&self) -> Option<usize> {
        // Pattern: Weak hash function for HTLC
        // Using short hash or single SHA3 without salt
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x20 {  // SHA3 (hash lock)
                let mut has_preimage_check = false;
                let mut has_salt = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Preimage verification
                    if self.bytecode[j] == 0x14 {  // EQ (hash comparison)
                        has_preimage_check = true;
                    }
                }
                
                // Check for salt in hash input (more than one input parameter)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (combine inputs)
                        has_salt = true;
                    }
                }
                
                if has_preimage_check && !has_salt {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_multihop_routing_failure(&self) -> Option<usize> {
        // Pattern: Sequential swaps without failure recovery
        // Multiple CALL operations without rollback on failure
        
        let mut call_count = 0;
        let mut has_rollback = false;
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (hop)
                call_count += 1;
                
                // Check for rollback mechanism after call
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Check return value and revert on failure
                    if self.bytecode[j] == 0x15 {  // ISZERO (check failure)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD {  // REVERT (rollback)
                                has_rollback = true;
                            }
                        }
                    }
                }
            }
        }
        
        // Multiple hops without rollback
        if call_count >= 2 && !has_rollback {
            return Some(0);
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("L2AtomicSwap{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "L2 Atomic Swap {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement full rollback mechanisms, coordinated timelocks, finality checks, \
                             bridge delay buffers, and multi-hop failure handling".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_settlement_failure() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL (settle without checking counterparty)
        ];
        
        let detector = L2AtomicSwapDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, L2AtomicSwapFailureType::PartialSettlementFailure)));
    }

    #[test]
    fn test_reorg_vulnerability() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (settlement)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (more settlement - no finality check)
        ];
        
        let detector = L2AtomicSwapDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, L2AtomicSwapFailureType::ReorgVulnerability)));
    }
}
