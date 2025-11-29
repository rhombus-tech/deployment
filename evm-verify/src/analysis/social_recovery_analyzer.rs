/// Social Recovery Security Analyzer for Smart Wallet Recovery Mechanisms
/// Detects vulnerabilities in guardian-based account recovery systems
/// Critical for: Social recovery wallets, multi-sig recovery, guardian systems

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SocialRecoveryVulnerabilityType {
    GuardianManipulation,       // Guardians can be manipulated or replaced maliciously
    ThresholdBypass,            // Recovery threshold can be bypassed
    GuardianCollusion,          // Insufficient protection against guardian collusion
    RecoveryDelayBypass,        // Time-lock delays can be bypassed
    UnauthorizedGuardianAdd,    // Guardians can be added without proper authorization
    RecoveryReentrancy,         // Reentrancy in recovery process
    GuardianRemovalAbuse,       // Guardians can be removed without safeguards
    WeakThresholdSetting,       // Recovery threshold too low (e.g., 1-of-5)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialRecoveryVulnerability {
    pub vulnerability_type: SocialRecoveryVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct SocialRecoveryAnalyzer {
    bytecode: Vec<u8>,
}

impl SocialRecoveryAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_guardian_manipulation());
        vulnerabilities.extend(self.detect_threshold_bypass());
        vulnerabilities.extend(self.detect_guardian_collusion_risks());
        vulnerabilities.extend(self.detect_recovery_delay_bypass());
        vulnerabilities.extend(self.detect_recovery_reentrancy());
        vulnerabilities.extend(self.detect_weak_threshold());

        vulnerabilities
    }

    fn detect_guardian_manipulation(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Guardian management signatures
        let guardian_sigs = [
            &[0x7d, 0x3e, 0x3d, 0xeb][..], // addGuardian(address)
            &[0x46, 0x8c, 0x96, 0xae][..], // removeGuardian(address)
            &[0xf8, 0xdc, 0x5d, 0xd9][..], // replaceGuardian(address,address)
        ];

        for sig in guardian_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for owner-only restriction
                let has_owner_check = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x33) && // CALLER
                        w.contains(&0x14) && // EQ
                        w.contains(&0x57)    // JUMPI (revert if not owner)
                    });

                // Check for time-lock on guardian changes
                let has_timelock = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x42) && // TIMESTAMP
                        w.contains(&0x10)    // LT (time check)
                    });

                if !has_owner_check {
                    vulnerabilities.push(SocialRecoveryVulnerability {
                        vulnerability_type: SocialRecoveryVulnerabilityType::GuardianManipulation,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Guardian management lacks owner authorization. Anyone can modify guardians.".to_string(),
                        remediation: "Add onlyOwner modifier: require(msg.sender == owner, 'Not authorized')".to_string(),
                    });
                }

                if !has_timelock {
                    vulnerabilities.push(SocialRecoveryVulnerability {
                        vulnerability_type: SocialRecoveryVulnerabilityType::UnauthorizedGuardianAdd,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Guardian changes take effect immediately. No time-lock for users to react.".to_string(),
                        remediation: "Add 24-48 hour delay: require(block.timestamp >= changeTime + DELAY)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_threshold_bypass(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Recovery execution signatures
        let recovery_sigs = [
            &[0xe4, 0x3c, 0x64, 0xb8][..], // executeRecovery(...)
            &[0x58, 0x89, 0xdc, 0x3c][..], // confirmRecovery(...)
        ];

        for sig in recovery_sigs.iter() {
            for i in 0..self.bytecode.len().saturating_sub(80) {
                if self.bytecode[i..].starts_with(sig) {
                    // Check for threshold validation (count >= threshold)
                    let has_threshold_check = self.bytecode[i..i + 80].windows(5).any(|w| {
                        w.contains(&0x10) && // LT (count check)
                        w.contains(&0x54) && // SLOAD (threshold value)
                        w.contains(&0x57)    // JUMPI (revert if insufficient)
                    });

                    // Check for guardian verification loop
                    let has_guardian_verification = self.bytecode[i..i + 80].windows(6).any(|w| {
                        w.contains(&0x54) && // SLOAD (guardian mapping)
                        w.contains(&0x14) && // EQ (verify guardian)
                        w.contains(&0x15)    // ISZERO (check result)
                    });

                    // Check for duplicate signature prevention
                    let has_duplicate_check = self.bytecode[i..i + 80].windows(5).any(|w| {
                        w.contains(&0x54) && // SLOAD (check if already signed)
                        w.contains(&0x15) && // ISZERO
                        w.contains(&0x57)    // JUMPI (revert if duplicate)
                    });

                    if !has_threshold_check {
                        vulnerabilities.push(SocialRecoveryVulnerability {
                            vulnerability_type: SocialRecoveryVulnerabilityType::ThresholdBypass,
                            severity: SecuritySeverity::Critical,
                            location: i,
                            description: "Recovery execution doesn't verify threshold. Recovery can proceed with insufficient approvals.".to_string(),
                            remediation: "Enforce threshold: require(approvalCount >= threshold, 'Insufficient approvals')".to_string(),
                        });
                    }

                    if !has_guardian_verification {
                        vulnerabilities.push(SocialRecoveryVulnerability {
                            vulnerability_type: SocialRecoveryVulnerabilityType::ThresholdBypass,
                            severity: SecuritySeverity::Critical,
                            location: i,
                            description: "Recovery doesn't verify guardian status. Non-guardians can approve recovery.".to_string(),
                            remediation: "Verify guardian: require(isGuardian[signer], 'Not a guardian')".to_string(),
                        });
                    }

                    if !has_duplicate_check {
                        vulnerabilities.push(SocialRecoveryVulnerability {
                            vulnerability_type: SocialRecoveryVulnerabilityType::ThresholdBypass,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Recovery lacks duplicate signature prevention. One guardian can vote multiple times.".to_string(),
                            remediation: "Mark guardian as voted: require(!hasVoted[guardian]); hasVoted[guardian] = true".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_guardian_collusion_risks(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for threshold settings
        let set_threshold_sigs = [
            &[0x96, 0x0b, 0xfe, 0x04][..], // setThreshold(uint256)
            &[0xc4, 0xd6, 0x6d, 0xe8][..], // changeThreshold(uint256)
        ];

        for sig in set_threshold_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for minimum threshold validation
                let has_minimum_check = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x10) && // LT (threshold > MIN)
                        w.contains(&0x60)    // PUSH1 (minimum value like 2 or 3)
                    });

                // Check for guardian count relationship (threshold <= guardian_count)
                let has_count_check = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x54) && // SLOAD (guardian count)
                        w.contains(&0x11) && // GT (threshold <= count)
                        w.contains(&0x57)    // JUMPI
                    });

                if !has_minimum_check {
                    vulnerabilities.push(SocialRecoveryVulnerability {
                        vulnerability_type: SocialRecoveryVulnerabilityType::GuardianCollusion,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Threshold can be set to 1, making single guardian compromise fatal.".to_string(),
                        remediation: "Enforce minimum: require(threshold >= 2 || threshold >= guardianCount / 2)".to_string(),
                    });
                }

                if !has_count_check {
                    vulnerabilities.push(SocialRecoveryVulnerability {
                        vulnerability_type: SocialRecoveryVulnerabilityType::GuardianCollusion,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Threshold can exceed guardian count, making recovery impossible.".to_string(),
                        remediation: "Validate: require(threshold <= guardianCount, 'Invalid threshold')".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_recovery_delay_bypass(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Recovery initiation and execution
        let init_sig = [0xa3, 0x58, 0x22, 0xa8]; // initiateRecovery
        let exec_sig = [0xe4, 0x3c, 0x64, 0xb8]; // executeRecovery

        if let Some(exec_pos) = self.bytecode.windows(4).position(|w| w == &exec_sig) {
            // Check for time delay enforcement
            let has_delay_check = self.bytecode[exec_pos..exec_pos.saturating_add(60).min(self.bytecode.len())]
                .windows(10)
                .any(|w| {
                    w.contains(&0x42) && // TIMESTAMP
                    w.contains(&0x01) && // ADD (initiationTime + delay)
                    w.contains(&0x10) && // LT (current >= required)
                    w.contains(&0x57)    // JUMPI (revert if too early)
                });

            // Check for cancellation mechanism
            let has_cancellation = self.bytecode.windows(4).any(|w| {
                w == &[0x74, 0x5a, 0x1c, 0xd6] // cancelRecovery
            });

            if !has_delay_check {
                vulnerabilities.push(SocialRecoveryVulnerability {
                    vulnerability_type: SocialRecoveryVulnerabilityType::RecoveryDelayBypass,
                    severity: SecuritySeverity::High,
                    location: exec_pos,
                    description: "Recovery can execute immediately after initiation. No time for legitimate owner to react.".to_string(),
                    remediation: "Add delay: require(block.timestamp >= initiationTime + RECOVERY_DELAY)".to_string(),
                });
            }

            if !has_cancellation {
                vulnerabilities.push(SocialRecoveryVulnerability {
                    vulnerability_type: SocialRecoveryVulnerabilityType::RecoveryDelayBypass,
                    severity: SecuritySeverity::Medium,
                    location: exec_pos,
                    description: "No mechanism to cancel malicious recovery attempts.".to_string(),
                    remediation: "Add cancelRecovery() function callable by owner or sufficient guardians.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_recovery_reentrancy(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        let recovery_sigs = [
            &[0xe4, 0x3c, 0x64, 0xb8][..], // executeRecovery
            &[0xa3, 0x58, 0x22, 0xa8][..], // initiateRecovery
        ];

        for sig in recovery_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for reentrancy guard (nonReentrant pattern)
                let has_reentrancy_guard = self.bytecode[pos..pos.saturating_add(40).min(self.bytecode.len())]
                    .windows(5)
                    .any(|w| {
                        w.contains(&0x54) && // SLOAD (lock status)
                        w.contains(&0x15) && // ISZERO (check not locked)
                        w.contains(&0x57)    // JUMPI (revert if locked)
                    });

                // Check for external calls (CALL, DELEGATECALL)
                let has_external_call = self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())]
                    .iter()
                    .any(|&op| op == 0xf1 || op == 0xf4);

                if has_external_call && !has_reentrancy_guard {
                    vulnerabilities.push(SocialRecoveryVulnerability {
                        vulnerability_type: SocialRecoveryVulnerabilityType::RecoveryReentrancy,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Recovery process makes external calls without reentrancy protection.".to_string(),
                        remediation: "Add nonReentrant modifier or implement checks-effects-interactions pattern.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_weak_threshold(&self) -> Vec<SocialRecoveryVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for threshold initialization or setting
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Pattern: PUSH1 1 (threshold = 1) followed by SSTORE
            if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x01 {
                if i + 10 < self.bytecode.len() && self.bytecode[i..i + 10].contains(&0x55) {
                    // Check if this is threshold-related (near guardian operations)
                    let near_guardian_ops = self.bytecode[i.saturating_sub(50)..i.saturating_add(50).min(self.bytecode.len())]
                        .windows(4)
                        .any(|w| {
                            w == &[0x7d, 0x3e, 0x3d, 0xeb] || // addGuardian
                            w == &[0x96, 0x0b, 0xfe, 0x04]    // setThreshold
                        });

                    if near_guardian_ops {
                        vulnerabilities.push(SocialRecoveryVulnerability {
                            vulnerability_type: SocialRecoveryVulnerabilityType::WeakThresholdSetting,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Recovery threshold set to 1. Single guardian compromise enables complete account takeover.".to_string(),
                            remediation: "Use minimum threshold of 2 or 50% of guardian count, whichever is higher.".to_string(),
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
    fn test_detect_guardian_manipulation() {
        let bytecode = vec![
            0x7d, 0x3e, 0x3d, 0xeb, // addGuardian
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no owner check)
        ];

        let analyzer = SocialRecoveryAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, SocialRecoveryVulnerabilityType::GuardianManipulation)
        }));
    }

    #[test]
    fn test_detect_threshold_bypass() {
        let bytecode = vec![
            0xe4, 0x3c, 0x64, 0xb8, // executeRecovery
            0xf1, // CALL (executes without threshold check)
        ];

        let analyzer = SocialRecoveryAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, SocialRecoveryVulnerabilityType::ThresholdBypass)
        }));
    }

    #[test]
    fn test_safe_social_recovery() {
        let bytecode = vec![
            0x7d, 0x3e, 0x3d, 0xeb, // addGuardian
            0x33, // CALLER
            0x14, // EQ (owner check)
            0x57, // JUMPI
            0xe4, 0x3c, 0x64, 0xb8, // executeRecovery
            0x54, // SLOAD (threshold)
            0x10, // LT (count >= threshold)
            0x57, // JUMPI
            0x42, // TIMESTAMP (delay check)
            0x10, // LT
            0x57, // JUMPI
        ];

        let analyzer = SocialRecoveryAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        let critical_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();

        assert!(critical_vulns.is_empty());
    }
}
