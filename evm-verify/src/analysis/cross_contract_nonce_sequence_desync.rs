/// Cross-Contract Nonce/Sequence Desynchronization Detector
///
/// Detects vulnerabilities where nonce or sequence number mismatches between
/// protocols enable replay attacks or transaction ordering exploits.
///
/// Examples:
/// - Cross-L2 message replay via nonce desync (Optimism→Arbitrum)
/// - Bridge nonce mismanagement enabling double-spend
/// - Gasless transaction replay across protocols (Permit2)
///
/// Real exploits: Nomad Bridge ($190M), Wormhole ($325M)
/// Risk: $100B+ in cross-L2 and bridge activity

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractNonceSequenceDesyncVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub desync_type: NonceDesyncType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NonceDesyncType {
    /// Nonce not synchronized across protocols
    NonceDesynchronization,
    /// Sequence number mismatch
    SequenceNumberMismatch,
    /// Cross-chain nonce replay
    CrossChainNonceReplay,
    /// Missing nonce validation
    MissingNonceValidation,
    /// Nonce increment timing vulnerability
    NonceIncrementTiming,
}

pub struct CrossContractNonceSequenceDesyncAnalyzer;

impl CrossContractNonceSequenceDesyncAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractNonceSequenceDesyncVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_nonce_desynchronization(bytecode) {
            vulnerabilities.push(CrossContractNonceSequenceDesyncVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Nonce management not synchronized with external protocol nonces".to_string(),
                location: "Nonce handling".to_string(),
                desync_type: NonceDesyncType::NonceDesynchronization,
                impact: "Nonce mismatch enables replay attacks across protocols".to_string(),
            });
        }

        if self.has_missing_nonce_validation(bytecode) {
            vulnerabilities.push(CrossContractNonceSequenceDesyncVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Cross-protocol messages processed without nonce validation".to_string(),
                location: "Message validation".to_string(),
                desync_type: NonceDesyncType::MissingNonceValidation,
                impact: "Messages can be replayed without detection".to_string(),
            });
        }

        if self.has_sequence_number_mismatch(bytecode) {
            vulnerabilities.push(CrossContractNonceSequenceDesyncVulnerability {
                severity: SecuritySeverity::High,
                description: "Sequence numbers not validated against external protocol state".to_string(),
                location: "Sequence validation".to_string(),
                desync_type: NonceDesyncType::SequenceNumberMismatch,
                impact: "Out-of-order execution enables state manipulation".to_string(),
            });
        }

        if self.has_nonce_increment_timing_vuln(bytecode) {
            vulnerabilities.push(CrossContractNonceSequenceDesyncVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Nonce incremented before external call completion".to_string(),
                location: "Nonce increment".to_string(),
                desync_type: NonceDesyncType::NonceIncrementTiming,
                impact: "Nonce race condition in cross-protocol operations".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_nonce_desynchronization(&self, bytecode: &[u8]) -> bool {
        // Look for: nonce usage + external call without sync check
        bytecode.windows(50).any(|window| {
            window.contains(&0x54) && // SLOAD (nonce)
            window.contains(&0xf1) && // External CALL
            !window.contains(&0x14)   // No EQ (no nonce comparison)
        })
    }

    fn has_missing_nonce_validation(&self, bytecode: &[u8]) -> bool {
        // Look for: external call with data but no nonce validation
        bytecode.windows(50).any(|window| {
            window.contains(&0x37) && // CALLDATACOPY (message data)
            window.contains(&0xf1) && // CALL
            !window.contains(&0x54) && // No SLOAD (no nonce check)
            !window.contains(&0x14)    // No EQ
        })
    }

    fn has_sequence_number_mismatch(&self, bytecode: &[u8]) -> bool {
        // Look for: sequence/counter without external validation
        bytecode.windows(50).any(|window| {
            window.contains(&0x01) && // ADD (increment)
            window.contains(&0x55) && // SSTORE (save sequence)
            window.contains(&0xfa) && // External query
            !window.contains(&0x14)   // No EQ (no validation)
        })
    }

    fn has_nonce_increment_timing_vuln(&self, bytecode: &[u8]) -> bool {
        // Look for: nonce increment before external call completes
        bytecode.windows(40).any(|window| {
            let sstore_pos = window.iter().position(|&op| op == 0x55); // SSTORE (nonce increment)
            let call_pos = window.iter().position(|&op| op == 0xf1);   // CALL
            
            matches!((sstore_pos, call_pos), (Some(s), Some(c)) if s < c)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractNonceSequenceDesyncVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractNonceSequenceDesync,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Nonce/Sequence Desync: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement strict nonce synchronization and validation", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_nonce_validation() {
        let analyzer = CrossContractNonceSequenceDesyncAnalyzer::new();
        
        let bytecode = vec![
            0x37, // CALLDATACOPY (message)
            0xf1, // CALL
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
