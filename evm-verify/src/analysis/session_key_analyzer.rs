/// Session Key Vulnerability Analyzer for Smart Account Security (ERC-4337)
/// Detects vulnerabilities in session key management for account abstraction
/// Critical for: Smart wallets, session-based authentication, permission management

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionKeyVulnerabilityType {
    MissingRevocation,           // No mechanism to revoke session keys
    PermissionEscalation,        // Session key can gain unauthorized permissions
    KeyRotationBug,              // Unsafe key rotation implementation
    ExpirationBypass,            // Can bypass expiration checks
    UnauthorizedDelegation,      // Session key can delegate to unauthorized addresses
    InsufficientPermissionCheck, // Weak permission validation
    ReplayAfterRevocation,       // Revoked keys can still be replayed
    TimestampManipulation,       // Expiration relies on manipulable timestamp
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyVulnerability {
    pub vulnerability_type: SessionKeyVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct SessionKeyAnalyzer {
    bytecode: Vec<u8>,
}

impl SessionKeyAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_revocation());
        vulnerabilities.extend(self.detect_permission_escalation());
        vulnerabilities.extend(self.detect_key_rotation_bugs());
        vulnerabilities.extend(self.detect_expiration_bypass());
        vulnerabilities.extend(self.detect_unauthorized_delegation());
        vulnerabilities.extend(self.detect_timestamp_manipulation());

        vulnerabilities
    }

    fn detect_missing_revocation(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Session key signatures: addSessionKey, executeWithSessionKey
        let session_key_sigs = [
            &[0x8d, 0x80, 0xff, 0x0a][..], // addSessionKey(address)
            &[0x9d, 0xf6, 0x2e, 0x0c][..], // executeWithSessionKey(...)
        ];

        // Revocation signatures: revokeSessionKey, removeSessionKey
        let revoke_sigs = [
            &[0x63, 0x74, 0x0e, 0x5a][..], // revokeSessionKey(address)
            &[0xa1, 0x4f, 0x1e, 0x8c][..], // removeSessionKey(address)
        ];

        let has_session_key = session_key_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == *sig)
        });

        let has_revocation = revoke_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == *sig)
        });

        if has_session_key && !has_revocation {
            vulnerabilities.push(SessionKeyVulnerability {
                vulnerability_type: SessionKeyVulnerabilityType::MissingRevocation,
                severity: SecuritySeverity::Critical,
                location: 0,
                description: "Session key system lacks revocation mechanism. Once added, session keys cannot be removed, creating permanent attack surface.".to_string(),
                remediation: "Implement revokeSessionKey() function with proper access controls to allow key removal.".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_permission_escalation(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for session key execution without permission checks
        let execute_sig = [0x9d, 0xf6, 0x2e, 0x0c]; // executeWithSessionKey

        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i..].starts_with(&execute_sig) {
                // Check for CALLER followed by SLOAD (permission check)
                let has_permission_check = self.bytecode[i..i + 50].windows(3).any(|w| {
                    w[0] == 0x33 && // CALLER
                    w[1] == 0x54    // SLOAD
                });

                // Check for admin check bypass
                let has_admin_check = self.bytecode[i..i + 50].windows(5).any(|w| {
                    w.contains(&0x33) && // CALLER
                    w.contains(&0x14)    // EQ (comparison)
                });

                if !has_permission_check && !has_admin_check {
                    vulnerabilities.push(SessionKeyVulnerability {
                        vulnerability_type: SessionKeyVulnerabilityType::PermissionEscalation,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Session key execution lacks permission validation. Any session key can execute any action.".to_string(),
                        remediation: "Add permission bitmap checks: require(sessionKeyPermissions[key] & requiredPermission != 0)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_key_rotation_bugs(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // rotateSessionKey or updateSessionKey
        let rotate_sigs = [
            &[0xa5, 0x7e, 0xc3, 0x4f][..],
            &[0xb8, 0x1c, 0x2f, 0x9a][..],
        ];

        for sig in rotate_sigs.iter() {
            for i in 0..self.bytecode.len().saturating_sub(60) {
                if self.bytecode[i..].starts_with(sig) {
                    // Check if old key is invalidated (SSTORE with zero)
                    let invalidates_old_key = self.bytecode[i..i + 60].windows(3).any(|w| {
                        w[0] == 0x60 && w[1] == 0x00 && // PUSH1 0
                        w[2] == 0x55    // SSTORE
                    });

                    // Check for reentrancy guard
                    let has_reentrancy_guard = self.bytecode[i..i + 30].windows(2).any(|w| {
                        w[0] == 0x54 && // SLOAD (lock check)
                        w[1] == 0x15    // ISZERO
                    });

                    if !invalidates_old_key {
                        vulnerabilities.push(SessionKeyVulnerability {
                            vulnerability_type: SessionKeyVulnerabilityType::KeyRotationBug,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Key rotation doesn't properly invalidate old key. Both old and new keys remain active.".to_string(),
                            remediation: "Ensure old key is deleted: delete sessionKeys[oldKey] before adding new key.".to_string(),
                        });
                    }

                    if !has_reentrancy_guard {
                        vulnerabilities.push(SessionKeyVulnerability {
                            vulnerability_type: SessionKeyVulnerabilityType::KeyRotationBug,
                            severity: SecuritySeverity::Medium,
                            location: i,
                            description: "Key rotation lacks reentrancy protection. Attacker could interrupt rotation.".to_string(),
                            remediation: "Add nonReentrant modifier to key rotation functions.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_expiration_bypass(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for expiration checks in session key execution
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Check for TIMESTAMP usage (block.timestamp)
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Look for GT or LT comparison nearby
                let has_comparison = self.bytecode[i..i + 10].iter().any(|&op| {
                    op == 0x10 || // LT
                    op == 0x11    // GT
                });

                if has_comparison {
                    // Check if there's a REVERT after failed check
                    let has_revert = self.bytecode[i..i + 20].iter().any(|&op| {
                        op == 0xfd || // REVERT
                        op == 0x57    // JUMPI (conditional jump)
                    });

                    // Check for overflow protection
                    let has_overflow_check = self.bytecode[i..i + 30].windows(2).any(|w| {
                        w[0] == 0x10 && // LT (overflow check)
                        w[1] == 0x15    // ISZERO
                    });

                    if !has_revert {
                        vulnerabilities.push(SessionKeyVulnerability {
                            vulnerability_type: SessionKeyVulnerabilityType::ExpirationBypass,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Expiration check doesn't revert on failure. Expired keys can still be used.".to_string(),
                            remediation: "Add require(block.timestamp < expirationTime, 'Session key expired')".to_string(),
                        });
                    }

                    if !has_overflow_check {
                        vulnerabilities.push(SessionKeyVulnerability {
                            vulnerability_type: SessionKeyVulnerabilityType::ExpirationBypass,
                            severity: SecuritySeverity::Medium,
                            location: i,
                            description: "Expiration time arithmetic lacks overflow protection. Could be set to max uint256.".to_string(),
                            remediation: "Use SafeMath for expiration calculations or check for reasonable bounds.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_unauthorized_delegation(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // delegateSessionKey or addDelegatedKey
        let delegate_sigs = [
            &[0xc7, 0x5e, 0x9a, 0x3f][..],
            &[0xd4, 0x8c, 0x1b, 0x7e][..],
        ];

        for sig in delegate_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for delegation depth limit
                let has_depth_check = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x10) && // LT (depth < max)
                        w.contains(&0x54)    // SLOAD (depth counter)
                    });

                // Check for whitelist verification
                let has_whitelist = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(4)
                    .any(|w| {
                        w[0] == 0x54 && // SLOAD
                        w[1] == 0x15    // ISZERO
                    });

                if !has_depth_check {
                    vulnerabilities.push(SessionKeyVulnerability {
                        vulnerability_type: SessionKeyVulnerabilityType::UnauthorizedDelegation,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Session key delegation lacks depth limit. Recursive delegation could create infinite chains.".to_string(),
                        remediation: "Limit delegation depth: require(delegationDepth < MAX_DEPTH, 'Too deep')".to_string(),
                    });
                }

                if !has_whitelist {
                    vulnerabilities.push(SessionKeyVulnerability {
                        vulnerability_type: SessionKeyVulnerabilityType::UnauthorizedDelegation,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Session key can delegate to any address without whitelist check.".to_string(),
                        remediation: "Restrict delegation to whitelisted addresses or require owner approval.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_timestamp_manipulation(&self) -> Vec<SessionKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for TIMESTAMP (0x42) used in security-critical operations
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if it's used for expiration (GT/LT comparison)
                let is_expiration_check = self.bytecode[i..i + 10].iter().any(|&op| {
                    op == 0x10 || op == 0x11 // LT or GT
                });

                if is_expiration_check {
                    // Check for block.number as backup
                    let has_block_number_backup = self.bytecode[i..i + 30].iter().any(|&op| {
                        op == 0x43 // NUMBER (block.number)
                    });

                    if !has_block_number_backup {
                        vulnerabilities.push(SessionKeyVulnerability {
                            vulnerability_type: SessionKeyVulnerabilityType::TimestampManipulation,
                            severity: SecuritySeverity::Medium,
                            location: i,
                            description: "Expiration relies solely on block.timestamp (±15 seconds manipulable by miners).".to_string(),
                            remediation: "Use block.number for critical timeouts or accept ±15s variance as acceptable.".to_string(),
                        });
                    }
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
    fn test_detect_missing_revocation() {
        // Bytecode with addSessionKey but no revokeSessionKey
        let bytecode = vec![
            0x8d, 0x80, 0xff, 0x0a, // addSessionKey signature
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE
        ];

        let analyzer = SessionKeyAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, SessionKeyVulnerabilityType::MissingRevocation)
        }));
    }

    #[test]
    fn test_detect_permission_escalation() {
        // Bytecode with executeWithSessionKey but no permission check
        let bytecode = vec![
            0x9d, 0xf6, 0x2e, 0x0c, // executeWithSessionKey
            0x60, 0x00, // PUSH1 0
            0xf1, // CALL (executes action without checking permissions)
        ];

        let analyzer = SessionKeyAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, SessionKeyVulnerabilityType::PermissionEscalation)
        }));
    }

    #[test]
    fn test_safe_session_key_system() {
        // Bytecode with proper session key management
        let bytecode = vec![
            0x8d, 0x80, 0xff, 0x0a, // addSessionKey
            0x63, 0x74, 0x0e, 0x5a, // revokeSessionKey
            0x9d, 0xf6, 0x2e, 0x0c, // executeWithSessionKey
            0x33, // CALLER
            0x54, // SLOAD (permission check)
            0x42, // TIMESTAMP (expiration check)
            0x10, // LT
            0x57, // JUMPI (revert if expired)
        ];

        let analyzer = SessionKeyAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        // Should have minimal or no high-severity vulnerabilities
        let critical_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();

        assert!(critical_vulns.is_empty());
    }
}
