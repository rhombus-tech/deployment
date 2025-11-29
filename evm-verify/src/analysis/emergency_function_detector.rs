// Emergency Function Abuse Detector
// Detects pause/unpause, emergency withdraw, and circuit breaker vulnerabilities
// Historical: Multiple rug pulls, admin key compromises, emergency function abuse

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyFunctionVulnerability {
    pub vulnerability_type: EmergencyFunctionType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyFunctionType {
    PauseWithoutTimelock,           // Pause can be triggered instantly
    UnpauseWithoutDelay,            // Unpause has no delay
    EmergencyWithdrawAllFunds,      // Admin can withdraw all funds
    CircuitBreakerBypass,           // Circuit breaker can be disabled
    PauseWithoutMultisig,           // Single admin can pause
    NoEmergencyRateLimiting,        // Emergency functions have no cooldown
    EmergencyMintUnlimited,         // Emergency mint with no cap
    AdminKeyCompromiseRisk,         // Single key controls emergency
    NoGovernanceForEmergency,       // Emergency not governed
    EmergencyFunctionReentrancy,    // Emergency function vulnerable to reentrancy
    PermanentPauseRisk,             // Contract can be permanently paused
    EmergencyWithoutAuditLog,       // Emergency actions not logged
}

pub struct EmergencyFunctionDetector {
    bytecode: Vec<u8>,
}

impl EmergencyFunctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_pause_without_timelock());
        vulnerabilities.extend(self.detect_emergency_withdraw());
        vulnerabilities.extend(self.detect_single_admin_control());
        vulnerabilities.extend(self.detect_circuit_breaker_bypass());
        vulnerabilities.extend(self.detect_emergency_mint());
        vulnerabilities.extend(self.detect_permanent_pause_risk());

        vulnerabilities
    }

    fn detect_pause_without_timelock(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for pause() function signature
        let pause_sigs = [
            &[0x84, 0x56, 0xcb, 0x59][..], // pause()
            &[0x02, 0x32, 0x9a, 0x29][..], // _pause()
        ];

        for sig in &pause_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                // Check if there's timelock check (TIMESTAMP, SUB, LT pattern)
                let function_section = &self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())];
                
                let has_timelock = function_section.windows(3).any(|w| {
                    w[0] == 0x42 || // TIMESTAMP
                    w[0] == 0x43    // NUMBER (block number timelock)
                });

                if !has_timelock {
                    vulnerabilities.push(EmergencyFunctionVulnerability {
                        vulnerability_type: EmergencyFunctionType::PauseWithoutTimelock,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Pause function has no timelock or delay".to_string(),
                        exploit_scenario: "Admin can instantly pause contract, blocking all user operations without warning".to_string(),
                        remediation: "Add timelock: propose pause -> wait period -> execute pause".to_string(),
                    });
                }

                // Check for event emission (LOG opcodes)
                let emits_event = function_section.iter().any(|&b| {
                    b >= 0xa0 && b <= 0xa4 // LOG0-LOG4
                });

                if !emits_event {
                    vulnerabilities.push(EmergencyFunctionVulnerability {
                        vulnerability_type: EmergencyFunctionType::EmergencyWithoutAuditLog,
                        severity: SecuritySeverity::Medium,
                        location: pos,
                        description: "Emergency pause function does not emit event".to_string(),
                        exploit_scenario: "Pause actions are not logged, making abuse detection difficult".to_string(),
                        remediation: "Emit event: emit Paused(msg.sender, block.timestamp)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_emergency_withdraw(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for emergency withdraw patterns
        let emergency_sigs = [
            &[0x5c, 0x97, 0x5a, 0xbb][..], // emergencyWithdraw()
            &[0xe9, 0xfa, 0xd8, 0xee][..], // rescue()
        ];

        for sig in &emergency_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())];
                
                // Check if it sends entire balance (SELFBALANCE opcode)
                let withdraws_all = function_section.contains(&0x47); // SELFBALANCE
                
                // Check if there's access control (CALLER check)
                let has_access_control = function_section.contains(&0x33); // CALLER

                if withdraws_all {
                    vulnerabilities.push(EmergencyFunctionVulnerability {
                        vulnerability_type: EmergencyFunctionType::EmergencyWithdrawAllFunds,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Emergency function can withdraw all contract funds".to_string(),
                        exploit_scenario: "Compromised admin key allows instant theft of all user funds with no recourse".to_string(),
                        remediation: "Add multi-sig requirement, timelock, or percentage limits on emergency withdrawals".to_string(),
                    });
                }

                if has_access_control {
                    // Check if it's single-sig (just CALLER check, no additional checks)
                    let check_count = function_section.iter().filter(|&&b| b == 0x33).count();
                    
                    if check_count == 1 {
                        vulnerabilities.push(EmergencyFunctionVulnerability {
                            vulnerability_type: EmergencyFunctionType::AdminKeyCompromiseRisk,
                            severity: SecuritySeverity::High,
                            location: pos,
                            description: "Single admin key controls emergency withdrawal".to_string(),
                            exploit_scenario: "Single private key compromise results in total loss of funds".to_string(),
                            remediation: "Require multi-sig: 2-of-3 or 3-of-5 signatures for emergency actions".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_single_admin_control(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count emergency functions controlled by single admin
        let pause_sig = &[0x84, 0x56, 0xcb, 0x59][..]; // pause()
        let unpause_sig = &[0x3f, 0x4b, 0xa8, 0x3a][..]; // unpause()
        
        let has_pause = self.bytecode.windows(pause_sig.len()).any(|w| w == pause_sig);
        let has_unpause = self.bytecode.windows(unpause_sig.len()).any(|w| w == unpause_sig);

        if has_pause && has_unpause {
            // Check if either uses multi-sig (multiple CALLER or SIGNER checks)
            let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
            
            // Heuristic: if fewer than 3 CALLER checks, likely single-sig
            if caller_count < 3 {
                vulnerabilities.push(EmergencyFunctionVulnerability {
                    vulnerability_type: EmergencyFunctionType::PauseWithoutMultisig,
                    severity: SecuritySeverity::High,
                    location: 0,
                    description: "Pause/unpause controlled by single administrator".to_string(),
                    exploit_scenario: "Single compromised key can permanently pause contract or manipulate pause state".to_string(),
                    remediation: "Implement multi-sig governance for emergency functions".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_circuit_breaker_bypass(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for function that can disable circuit breaker
        // Pattern: CALLER check followed by SSTORE to paused flag
        let pause_sig = &[0x84, 0x56, 0xcb, 0x59][..]; // pause()
        
        if let Some(pos) = self.bytecode.windows(pause_sig.len()).position(|w| w == pause_sig) {
            // Check if there's a corresponding unpause without checks
            let unpause_sig = &[0x3f, 0x4b, 0xa8, 0x3a][..]; // unpause()
            
            if let Some(unpause_pos) = self.bytecode.windows(unpause_sig.len()).position(|w| w == unpause_sig) {
                let unpause_section = &self.bytecode[unpause_pos..unpause_pos.saturating_add(30).min(self.bytecode.len())];
                
                // Check if unpause has delay or conditions
                let has_delay = unpause_section.windows(2).any(|w| {
                    w[0] == 0x42 || // TIMESTAMP
                    w[0] == 0x43    // NUMBER
                });

                if !has_delay {
                    vulnerabilities.push(EmergencyFunctionVulnerability {
                        vulnerability_type: EmergencyFunctionType::CircuitBreakerBypass,
                        severity: SecuritySeverity::Medium,
                        location: unpause_pos,
                        description: "Circuit breaker (pause) can be immediately disabled".to_string(),
                        exploit_scenario: "Admin can bypass security pause instantly, negating its protective purpose".to_string(),
                        remediation: "Add mandatory delay: unpause must wait X hours after pause".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_emergency_mint(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for emergency mint function
        let mint_sigs = [
            &[0x40, 0xc1, 0x0f, 0x19][..], // mint(address,uint256)
            &[0xa0, 0x71, 0x23, 0x73][..], // emergencyMint()
        ];

        for sig in &mint_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(40).min(self.bytecode.len())];
                
                // Check if there's a cap check (LT, GT comparison)
                let has_cap = function_section.windows(2).any(|w| {
                    w[0] == 0x10 || // LT
                    w[0] == 0x11 || // GT
                    w[0] == 0x12    // SLT
                });

                if !has_cap {
                    vulnerabilities.push(EmergencyFunctionVulnerability {
                        vulnerability_type: EmergencyFunctionType::EmergencyMintUnlimited,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Emergency mint function has no supply cap".to_string(),
                        exploit_scenario: "Admin can mint unlimited tokens, causing hyperinflation and destroying token value".to_string(),
                        remediation: "Add max emergency mint cap: require(amount <= MAX_EMERGENCY_MINT)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_permanent_pause_risk(&self) -> Vec<EmergencyFunctionVulnerability> {
        let mut vulnerabilities = Vec::new();

        let pause_sig = &[0x84, 0x56, 0xcb, 0x59][..]; // pause()
        let unpause_sig = &[0x3f, 0x4b, 0xa8, 0x3a][..]; // unpause()
        
        let has_pause = self.bytecode.windows(pause_sig.len()).any(|w| w == pause_sig);
        let has_unpause = self.bytecode.windows(unpause_sig.len()).any(|w| w == unpause_sig);

        if has_pause && !has_unpause {
            vulnerabilities.push(EmergencyFunctionVulnerability {
                vulnerability_type: EmergencyFunctionType::PermanentPauseRisk,
                severity: SecuritySeverity::Critical,
                location: 0,
                description: "Contract has pause() but no unpause() function".to_string(),
                exploit_scenario: "Once paused, contract is permanently frozen with no way to resume operations".to_string(),
                remediation: "Implement unpause() function with appropriate access control and timelock".to_string(),
            });
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pause_without_timelock() {
        let mut bytecode = vec![0x00; 50];
        bytecode[10..14].copy_from_slice(&[0x84, 0x56, 0xcb, 0x59]); // pause()
        bytecode[20] = 0x55; // SSTORE (set paused = true)
        // No TIMESTAMP (0x42) for timelock
        
        let detector = EmergencyFunctionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EmergencyFunctionType::PauseWithoutTimelock)));
    }

    #[test]
    fn test_detect_emergency_withdraw_all() {
        let mut bytecode = vec![0x00; 50];
        bytecode[10..14].copy_from_slice(&[0x5c, 0x97, 0x5a, 0xbb]); // emergencyWithdraw()
        bytecode[20] = 0x47; // SELFBALANCE
        bytecode[25] = 0xf1; // CALL (send all funds)
        
        let detector = EmergencyFunctionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EmergencyFunctionType::EmergencyWithdrawAllFunds)));
    }

    #[test]
    fn test_detect_permanent_pause() {
        let mut bytecode = vec![0x00; 50];
        bytecode[10..14].copy_from_slice(&[0x84, 0x56, 0xcb, 0x59]); // pause()
        // No unpause function
        
        let detector = EmergencyFunctionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EmergencyFunctionType::PermanentPauseRisk)));
    }
}
