/// UserOperation Validation Detector (EIP-4337 Account Abstraction)
/// Detects vulnerabilities in smart account UserOperation validation
/// that can lead to bundler exploits, paymaster bypass, and signature replay
///
/// EIP-4337 brings new attack surface: validateUserOp, paymasters, bundlers

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpVulnerability {
    pub vulnerability_type: UserOpIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserOpIssueType {
    WeakUserOpValidation,          // validateUserOp doesn't check critical fields
    PaymasterBypass,               // Paymaster can be tricked into paying
    NonceReuse,                    // Nonce validation insufficient
    SignatureReplayAA,             // AA signature can be replayed
    MissingStorageAccess,          // Storage accessed outside validation
    GasGriefingViaUserOp,          // Bundler can grief via gas manipulation
}

pub struct UserOperationValidator {
    bytecode: Vec<u8>,
}

impl UserOperationValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UserOpVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an EIP-4337 contract
        if !self.is_eip4337_contract() {
            return vulnerabilities;
        }

        // Pattern 1: Weak validateUserOp implementation
        vulnerabilities.extend(self.detect_weak_validation());

        // Pattern 2: Paymaster bypass opportunities
        vulnerabilities.extend(self.detect_paymaster_issues());

        // Pattern 3: Nonce management issues
        vulnerabilities.extend(self.detect_nonce_issues());

        // Pattern 4: Storage access violations
        vulnerabilities.extend(self.detect_storage_violations());

        vulnerabilities
    }

    fn is_eip4337_contract(&self) -> bool {
        // EIP-4337 function selectors:
        // - validateUserOp: 0x3a871cdd
        // - validatePaymasterUserOp: 0xf465c77e
        // - executeUserOp: 0xb61d27f6
        
        let eip4337_selectors = [
            [0x3a, 0x87, 0x1c, 0xdd], // validateUserOp
            [0xf4, 0x65, 0xc7, 0x7e], // validatePaymasterUserOp
            [0xb6, 0x1d, 0x27, 0xf6], // execute
        ];

        eip4337_selectors.iter().any(|sel| {
            self.bytecode.windows(4).any(|w| w == sel)
        })
    }

    fn detect_weak_validation(&self) -> Vec<UserOpVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(validate_pc) = self.find_validate_user_op() {
            // Check critical validations
            let checks_signature = self.has_signature_check_in_range(validate_pc, 200);
            let checks_nonce = self.has_nonce_check_in_range(validate_pc, 200);
            let checks_sender = self.has_sender_check_in_range(validate_pc, 200);
            
            if !checks_signature {
                vulnerabilities.push(UserOpVulnerability {
                    vulnerability_type: UserOpIssueType::WeakUserOpValidation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.85,
                    description:
                        "validateUserOp() doesn't verify signature. Anyone can submit UserOps \
                        for this account without authorization.".to_string(),
                    exploit_scenario:
                        "Account Takeover:\n\
                         1. Attacker creates malicious UserOp\n\
                         2. No signature check in validateUserOp\n\
                         3. Bundler executes UserOp\n\
                         4. Attacker controls account\n\
                         5. Drains all funds\n\n\
                         Fix: Always verify signature in validateUserOp".to_string(),
                    location: validate_pc,
                });
            }

            if !checks_nonce {
                vulnerabilities.push(UserOpVulnerability {
                    vulnerability_type: UserOpIssueType::NonceReuse,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description:
                        "validateUserOp() doesn't validate nonce. UserOps can be replayed.".to_string(),
                    exploit_scenario:
                        "Replay Attack:\n\
                         1. User signs valid UserOp (transfer 100 USDC)\n\
                         2. No nonce increment\n\
                         3. Attacker replays same UserOp\n\
                         4. Transfer executes multiple times\n\
                         5. User loses more than intended".to_string(),
                    location: validate_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_paymaster_issues(&self) -> Vec<UserOpVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(paymaster_pc) = self.find_validate_paymaster() {
            // Check if paymaster validation is strong enough
            let has_limit_check = self.has_spending_limit(paymaster_pc, 200);
            let has_whitelist = self.has_whitelist_check(paymaster_pc, 200);
            
            if !has_limit_check && !has_whitelist {
                vulnerabilities.push(UserOpVulnerability {
                    vulnerability_type: UserOpIssueType::PaymasterBypass,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description:
                        "Paymaster validation lacks spending limits or whitelist. Can be \
                        exploited to drain paymaster funds.".to_string(),
                    exploit_scenario:
                        "Paymaster Drain:\n\
                         1. Attacker creates expensive UserOps\n\
                         2. Paymaster agrees to pay (weak validation)\n\
                         3. Attacker submits thousands of UserOps\n\
                         4. Paymaster pays for all gas\n\
                         5. Paymaster funds drained\n\n\
                         Fix: Implement spending limits and user whitelisting".to_string(),
                    location: paymaster_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_nonce_issues(&self) -> Vec<UserOpVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for nonce handling
        let has_nonce_storage = self.has_nonce_storage();
        let has_nonce_increment = self.has_nonce_increment();
        
        if has_nonce_storage && !has_nonce_increment {
            vulnerabilities.push(UserOpVulnerability {
                vulnerability_type: UserOpIssueType::NonceReuse,
                severity: SecuritySeverity::High,
                confidence: 0.70,
                description:
                    "Contract stores nonces but doesn't increment them properly. \
                    Allows UserOp replay attacks.".to_string(),
                exploit_scenario:
                    "Nonce Bypass:\n\
                     1. UserOp nonce checked against storage\n\
                     2. Nonce not incremented after use\n\
                     3. Same nonce can be used again\n\
                     4. Replay attack succeeds".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn detect_storage_violations(&self) -> Vec<UserOpVulnerability> {
        let mut vulnerabilities = Vec::new();

        // EIP-4337 rules: validateUserOp can only access:
        // 1. Account's own storage
        // 2. Associated storage (predictable addresses)
        
        if let Some(validate_pc) = self.find_validate_user_op() {
            // Check if validateUserOp accesses external contract storage
            let has_external_sload = self.has_external_storage_access(validate_pc, 300);
            
            if has_external_sload {
                vulnerabilities.push(UserOpVulnerability {
                    vulnerability_type: UserOpIssueType::MissingStorageAccess,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description:
                        "validateUserOp may access external storage. Violates EIP-4337 rules \
                        and makes bundler simulation unreliable.".to_string(),
                    exploit_scenario:
                        "Bundler Griefing:\n\
                         1. validateUserOp reads external storage\n\
                         2. Storage changes between simulation and execution\n\
                         3. UserOp fails on-chain after bundler simulated success\n\
                         4. Bundler loses gas\n\
                         5. Bundler bans the account".to_string(),
                    location: validate_pc,
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn find_validate_user_op(&self) -> Option<usize> {
        let selector = [0x3a, 0x87, 0x1c, 0xdd]; // validateUserOp
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn find_validate_paymaster(&self) -> Option<usize> {
        let selector = [0xf4, 0x65, 0xc7, 0x7e]; // validatePaymasterUserOp
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn has_signature_check_in_range(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for ecrecover (signature verification)
        for i in start..end.saturating_sub(5) {
            if self.bytecode[i] == 0x60 && // PUSH1
               self.bytecode[i + 1] == 0x01 && // 1 (ecrecover)
               self.bytecode[i..i+5].contains(&0xFA) { // STATICCALL
                return true;
            }
        }
        false
    }

    fn has_nonce_check_in_range(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for: SLOAD, EQ, JUMPI (nonce comparison)
        for i in start..end.saturating_sub(3) {
            if self.bytecode[i] == 0x54 && // SLOAD
               self.bytecode[i + 1] == 0x14 && // EQ
               self.bytecode[i + 2] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_sender_check_in_range(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for CALLER or msg.sender check
        self.bytecode[start..end].contains(&0x33) // CALLER
    }

    fn has_spending_limit(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for LT or GT (limit comparison)
        self.bytecode[start..end].iter()
            .any(|&op| op == 0x10 || op == 0x11)
    }

    fn has_whitelist_check(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for mapping access (whitelist check)
        for i in start..end.saturating_sub(3) {
            if self.bytecode[i] == 0x54 && // SLOAD (read mapping)
               self.bytecode[i + 1] == 0x15 && // ISZERO
               self.bytecode[i + 2] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_nonce_storage(&self) -> bool {
        // Nonce typically stored in slot 0 or 1
        // Look for SLOAD with small constant
        self.bytecode.windows(3).any(|w| {
            w[0] == 0x60 && // PUSH1
            w[1] <= 0x05 && // Small slot number
            w[2] == 0x54    // SLOAD
        })
    }

    fn has_nonce_increment(&self) -> bool {
        // Look for: SLOAD, ADD 1, SSTORE pattern
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x54 && // SLOAD
               self.bytecode[i + 1] == 0x60 && // PUSH1
               self.bytecode[i + 2] == 0x01 && // 1
               self.bytecode[i + 3] == 0x01 && // ADD
               self.bytecode[i + 4] == 0x55 { // SSTORE
                return true;
            }
        }
        false
    }

    fn has_external_storage_access(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for STATICCALL before SLOAD (external storage read)
        for i in start..end.saturating_sub(10) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                // Check if followed by storage operation
                if self.bytecode[i..i+10].contains(&0x54) { // SLOAD
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_validation() {
        let bytecode = vec![
            0x3a, 0x87, 0x1c, 0xdd, // validateUserOp selector
            // No ecrecover (0x01, 0xFA) = no signature check
            0x00, // STOP
        ];
        
        let validator = UserOperationValidator::new(bytecode);
        let vulns = validator.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect weak validation");
    }
}
