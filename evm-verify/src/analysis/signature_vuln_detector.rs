/// Enhanced Signature Vulnerability Detector
/// Detects ECDSA malleability, permit issues, and signature replay

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVulnerability {
    pub vulnerability_type: SignatureIssue,
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureIssue {
    /// ECDSA signature malleability (s value not checked)
    ECDSAMalleability,
    /// EIP-2612 permit frontrunning
    PermitFrontrunning,
    /// Missing deadline validation
    MissingDeadline,
    /// Nonce not incremented
    NonceNotIncremented,
    /// Chain ID not validated
    MissingChainID,
}

pub struct SignatureVulnDetector {
    bytecode: Vec<u8>,
}

impl SignatureVulnDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SignatureVulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_ecdsa_malleability());
        vulns.extend(self.detect_permit_issues());
        vulns.extend(self.detect_missing_deadline());
        vulns.extend(self.detect_nonce_issues());
        vulns
    }

    /// Detect ECDSA signature malleability (s value attack)
    fn detect_ecdsa_malleability(&self) -> Vec<SignatureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: ecrecover (0x01 precompile) without s value validation
        while pc < self.bytecode.len() {
            // Look for CALL to precompile 0x01 (ecrecover)
            if self.is_ecrecover_call(pc) {
                // Check if s value is validated (must be <= secp256k1n/2)
                if !self.has_s_value_check_near(pc) {
                    vulns.push(SignatureVulnerability {
                        vulnerability_type: SignatureIssue::ECDSAMalleability,
                        severity: SecuritySeverity::Critical,
                        description: "ecrecover without s value validation - signature malleability".to_string(),
                        exploit_scenario: "ECDSA malleability attack:\n\
                            1. Valid signature (r, s, v)\n\
                            2. Attacker creates (r, s', v') where s' = secp256k1n - s\n\
                            3. Both signatures are valid for same message!\n\
                            4. Signature can be replayed with different s value\n\
                            5. Bypass nonce checks, double-spend\n\
                            \n\
                            Real impact: Bitcoin, Ethereum transactions".to_string(),
                        remediation: "Validate s value (EIP-2):\n\
                            require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, 'Invalid s');\n\
                            \n\
                            Or use OpenZeppelin ECDSA library.".to_string(),
                        pc,
                    });
                }
            }

            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }

        vulns
    }

    /// Detect EIP-2612 permit frontrunning
    fn detect_permit_issues(&self) -> Vec<SignatureVulnerability> {
        let mut vulns = Vec::new();
        
        // Look for permit() function selector: 0xd505accf
        if self.has_permit_function() {
            // Check if nonce is properly validated
            if !self.has_nonce_validation() {
                vulns.push(SignatureVulnerability {
                    vulnerability_type: SignatureIssue::PermitFrontrunning,
                    severity: SecuritySeverity::High,
                    description: "permit() function vulnerable to frontrunning".to_string(),
                    exploit_scenario: "Permit frontrunning:\n\
                        1. User signs permit for spender A, amount 100\n\
                        2. User later wants to change to spender B\n\
                        3. User signs new permit for spender B\n\
                        4. Spender A sees transaction in mempool\n\
                        5. Spender A frontruns with old permit\n\
                        6. Spender A gets approval, uses it\n\
                        7. Then new permit executes, spender B also approved\n\
                        8. Double approval = funds stolen".to_string(),
                    remediation: "Use Permit2 or implement permit cancellation:\n\
                        mapping(address => mapping(uint256 => bool)) public usedNonces;\n\
                        \n\
                        function cancelPermit(uint256 nonce) external {\n\
                        usedNonces[msg.sender][nonce] = true;\n\
                        }".to_string(),
                    pc: 0,
                });
            }
        }

        vulns
    }

    /// Detect missing deadline validation
    fn detect_missing_deadline(&self) -> Vec<SignatureVulnerability> {
        let mut vulns = Vec::new();

        if self.has_permit_function() || self.has_signature_validation() {
            // Check for TIMESTAMP comparison
            if !self.has_timestamp_check() {
                vulns.push(SignatureVulnerability {
                    vulnerability_type: SignatureIssue::MissingDeadline,
                    severity: SecuritySeverity::Medium,
                    description: "Signature validation without deadline - can be replayed indefinitely".to_string(),
                    exploit_scenario: "Missing deadline:\n\
                        1. User signs transaction with no expiry\n\
                        2. Signature valid forever\n\
                        3. Attacker holds signature\n\
                        4. Years later, uses signature when profitable\n\
                        5. User loses funds from ancient permission".to_string(),
                    remediation: "Add deadline parameter:\n\
                        require(block.timestamp <= deadline, 'Signature expired');".to_string(),
                    pc: 0,
                });
            }
        }

        vulns
    }

    /// Detect nonce not incremented
    fn detect_nonce_issues(&self) -> Vec<SignatureVulnerability> {
        let mut vulns = Vec::new();

        if self.has_signature_validation() {
            // Look for nonce increment (SLOAD + ADD + SSTORE)
            let has_nonce_increment = self.bytecode.windows(10).any(|w| {
                w.iter().any(|&b| b == 0x54) && // SLOAD
                w.iter().any(|&b| b == 0x01) && // ADD  
                w.iter().any(|&b| b == 0x55)    // SSTORE
            });

            if !has_nonce_increment {
                vulns.push(SignatureVulnerability {
                    vulnerability_type: SignatureIssue::NonceNotIncremented,
                    severity: SecuritySeverity::Critical,
                    description: "Signature validation without nonce increment - replay attack".to_string(),
                    exploit_scenario: "Nonce replay:\n\
                        1. User signs: transfer 1 ETH, nonce=5\n\
                        2. Transaction executes\n\
                        3. Nonce not incremented (still 5!)\n\
                        4. Attacker replays same signature\n\
                        5. Transfers another 1 ETH\n\
                        6. Repeat until drained".to_string(),
                    remediation: "Increment nonce after use:\n\
                        nonces[signer]++;\n\
                        \n\
                        Or mark signature as used:\n\
                        usedSignatures[hash] = true;".to_string(),
                    pc: 0,
                });
            }
        }

        vulns
    }

    fn is_ecrecover_call(&self, pc: usize) -> bool {
        // Pattern: PUSH1 0x01 (ecrecover address) followed by CALL/STATICCALL
        if pc + 3 < self.bytecode.len() {
            (self.bytecode[pc] == 0x60 && self.bytecode[pc+1] == 0x01) &&
            (self.bytecode[pc+2] == 0xF1 || self.bytecode[pc+2] == 0xFA)
        } else {
            false
        }
    }

    fn has_s_value_check_near(&self, pc: usize) -> bool {
        let start = pc.saturating_sub(50);
        let end = (pc + 50).min(self.bytecode.len());
        
        // Look for comparison with secp256k1n/2
        // 0x7FFFFFFF... pattern
        self.bytecode[start..end].windows(4).any(|w| 
            w[0] == 0x7F && w[1] == 0xFF && w[2] == 0xFF && w[3] == 0xFF
        )
    }

    fn has_permit_function(&self) -> bool {
        // permit() selector: 0xd505accf
        self.bytecode.windows(4).any(|w| 
            w[0] == 0xd5 && w[1] == 0x05 && w[2] == 0xac && w[3] == 0xcf
        )
    }

    fn has_signature_validation(&self) -> bool {
        // Look for ecrecover or signature checks
        self.bytecode.iter().any(|&b| b == 0x01) && // ecrecover precompile
        self.bytecode.iter().any(|&b| b == 0xF1)    // CALL
    }

    fn has_nonce_validation(&self) -> bool {
        // Look for nonce SLOAD
        self.bytecode.iter().any(|&b| b == 0x54)
    }

    fn has_timestamp_check(&self) -> bool {
        // Look for TIMESTAMP opcode
        self.bytecode.iter().any(|&b| b == 0x42)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecdsa_malleability() {
        let bytecode = vec![
            0x60, 0x01,  // PUSH1 0x01 (ecrecover)
            0xF1,        // CALL
            // No s value check!
        ];
        let detector = SignatureVulnDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SignatureIssue::ECDSAMalleability)));
    }
}
