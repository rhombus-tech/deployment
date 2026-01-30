// Vertex Protocol Off-Chain Matching Detector
// Detects off-chain matching manipulation in hybrid order book systems

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VertexProtocolMatchingVulnerability {
    pub location: usize,
    pub vulnerability_type: VertexMatchingType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VertexMatchingType {
    OffChainManipulation,            // Off-chain matching engine manipulation
    MatchingEngineCollusion,         // Operator colludes with traders
    OrderPriorityManipulation,       // Manipulate order priority off-chain
    SettlementDelayExploit,          // Delay settlement for price advantage
    MatchingProofInvalid,            // Invalid matching proof accepted
    CrossChainArbitrageExploit,      // Exploit cross-chain settlement timing
}

pub struct VertexProtocolMatchingDetector {
    bytecode: Vec<u8>,
}

impl VertexProtocolMatchingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VertexProtocolMatchingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_off_chain_manipulation() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::OffChainManipulation,
                severity: SecuritySeverity::Critical,
                description: "Off-chain matching results not cryptographically verified on-chain. \
                             Operator can manipulate matches without detection.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_matching_engine_collusion() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::MatchingEngineCollusion,
                severity: SecuritySeverity::Critical,
                description: "Matching engine operator lacks fraud proofs. Collusion with traders \
                             enables front-running and price manipulation without accountability.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_order_priority_manipulation() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::OrderPriorityManipulation,
                severity: SecuritySeverity::High,
                description: "Order priority not enforced by on-chain verification. Off-chain engine \
                             can reorder trades for MEV extraction or favoritism.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_settlement_delay_exploit() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::SettlementDelayExploit,
                severity: SecuritySeverity::High,
                description: "Settlement timing controllable by operator. Selective delays enable \
                             price oracle arbitrage and loss socialization attacks.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_matching_proof_invalid() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::MatchingProofInvalid,
                severity: SecuritySeverity::Critical,
                description: "Matching proof validation insufficient. Invalid or forged proofs \
                             accepted enabling unauthorized trade execution.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_cross_chain_arbitrage_exploit() {
            vulnerabilities.push(VertexProtocolMatchingVulnerability {
                location: loc,
                vulnerability_type: VertexMatchingType::CrossChainArbitrageExploit,
                severity: SecuritySeverity::High,
                description: "Cross-chain settlement synchronization vulnerable. Operator exploits \
                             timing differences across chains for risk-free arbitrage.".to_string(),
                confidence: 0.86,
            });
        }

        vulnerabilities
    }

    fn detect_off_chain_manipulation(&self) -> Option<usize> {
        // Pattern: Settlement execution without cryptographic proof
        // Batch settlement accepted without signature verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (execute settlement)
                let mut is_batch_settlement = false;
                let mut has_proof_verification = false;
                
                // Check if batch settlement (multiple balance updates)
                let mut sstore_count = 1;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                is_batch_settlement = sstore_count >= 3;
                
                // Check for cryptographic proof verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x01 {  // ECRECOVER (signature)
                        has_proof_verification = true;
                    }
                    if self.bytecode[j] == 0x20 {  // SHA3 (merkle proof)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify proof)
                                has_proof_verification = true;
                            }
                        }
                    }
                }
                
                if is_batch_settlement && !has_proof_verification {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_matching_engine_collusion(&self) -> Option<usize> {
        // Pattern: Operator-signed settlements without fraud proof system
        // Single signature authority without challenge mechanism
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER (operator signature)
                let mut authorizes_settlement = false;
                let mut has_fraud_proof = false;
                
                // Check if signature authorizes settlement
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (execute)
                        authorizes_settlement = true;
                    }
                }
                
                // Check for fraud proof mechanism (challenge period)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (delay for challenges)
                                has_fraud_proof = true;
                            }
                        }
                    }
                }
                
                if authorizes_settlement && !has_fraud_proof {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_order_priority_manipulation(&self) -> Option<usize> {
        // Pattern: Settlement order not verified against timestamps
        // Off-chain determined order accepted without validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (settlement data)
                let mut contains_ordering = false;
                let mut validates_timestamps = false;
                
                // Check if settlement contains ordering information
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (apply ordering)
                        contains_ordering = true;
                    }
                }
                
                // Check for timestamp validation (FIFO enforcement)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (timestamp ordering check)
                                validates_timestamps = true;
                            }
                        }
                    }
                }
                
                if contains_ordering && !validates_timestamps {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_settlement_delay_exploit(&self) -> Option<usize> {
        // Pattern: Settlement timing fully controlled by operator
        // No maximum delay enforcement
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (settle)
                let mut is_operator_call = false;
                let mut has_delay_limit = false;
                
                // Check if operator-only function
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (operator check)
                                is_operator_call = true;
                            }
                        }
                    }
                }
                
                // Check for maximum delay enforcement
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (time since order)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (under max delay)
                                        has_delay_limit = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_operator_call && !has_delay_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_matching_proof_invalid(&self) -> Option<usize> {
        // Pattern: Proof verification with insufficient validation
        // Signature checked but not proof completeness
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER (proof signature)
                let mut verifies_signature = false;
                let mut validates_completeness = false;
                
                // Check if signature verification
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (check signer)
                        verifies_signature = true;
                    }
                }
                
                // Check for proof completeness (all fields present)
                for j in (i.saturating_sub(25))..i {
                    // Multiple CALLDATALOAD indicating structured proof
                    let mut field_count = 0;
                    for k in j..(j+20).min(self.bytecode.len()) {
                        if self.bytecode[k] == 0x35 {  // CALLDATALOAD
                            field_count += 1;
                        }
                    }
                    
                    // Check field count validation
                    if field_count >= 5 {  // Complex proof structure
                        for k in j..(j+25).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (validate count)
                                validates_completeness = true;
                            }
                        }
                    }
                }
                
                if verifies_signature && !validates_completeness {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cross_chain_arbitrage_exploit(&self) -> Option<usize> {
        // Pattern: Cross-chain settlement without synchronization
        // Multiple chain interactions without atomic guarantees
        
        let mut external_calls = 0;
        let mut has_atomicity_check = false;
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL/STATICCALL
                external_calls += 1;
                
                // Check for atomicity enforcement (revert all if one fails)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 {  // ISZERO (check failure)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD {  // REVERT (rollback)
                                has_atomicity_check = true;
                            }
                        }
                    }
                }
            }
        }
        
        // Multiple external calls without atomicity
        if external_calls >= 2 && !has_atomicity_check {
            return Some(0);
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("VertexProtocolMatching{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Vertex Protocol Matching {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement cryptographic proof verification for off-chain matching, \
                             fraud proof system with challenge periods, FIFO timestamp validation, \
                             maximum settlement delay limits, complete proof validation, and atomic \
                             cross-chain settlement guarantees".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_off_chain_manipulation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (settlement)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (more settlement)
            0x60, 0x02, // PUSH1 2
            0x55, // SSTORE (batch without proof)
        ];
        
        let detector = VertexProtocolMatchingDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VertexMatchingType::OffChainManipulation)));
    }

    #[test]
    fn test_matching_engine_collusion() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x01, // ECRECOVER (operator sig)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (execute without fraud proof period)
        ];
        
        let detector = VertexProtocolMatchingDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, VertexMatchingType::MatchingEngineCollusion)));
    }
}
