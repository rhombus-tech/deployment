use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc1404RestrictedTokenVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc1404RestrictedTokenDetector {
    bytecode: Vec<u8>,
}

impl Erc1404RestrictedTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc1404RestrictedTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-1404 defines restricted tokens with detectTransferRestriction()
        // Detect transfer restriction bypass
        if let Some(location) = self.has_restriction_bypass() {
            vulnerabilities.push(Erc1404RestrictedTokenVulnerability {
                vulnerability_type: "ERC-1404 Transfer Restriction Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Token transfer without calling detectTransferRestriction(). Restricted tokens could be transferred to unauthorized addresses. Implement mandatory restriction checks returning error codes.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing restriction code validation
        if let Some(location) = self.has_missing_code_validation() {
            vulnerabilities.push(Erc1404RestrictedTokenVulnerability {
                vulnerability_type: "ERC-1404 Missing Restriction Code Check".to_string(),
                location,
                severity: "High".to_string(),
                description: "detectTransferRestriction() return code not validated before transfer. Non-zero error codes should prevent transfers. Check restriction code == 0 before proceeding.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect restriction logic manipulation
        if let Some(location) = self.has_restriction_manipulation() {
            vulnerabilities.push(Erc1404RestrictedTokenVulnerability {
                vulnerability_type: "ERC-1404 Restriction Logic Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Transfer restriction logic can be modified without governance. Restrictions could be disabled allowing unauthorized transfers. Implement immutable restrictions or multi-sig governance.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_restriction_bypass(&self) -> Option<usize> {
        // Pattern: Balance update without prior detectTransferRestriction call
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (balance update)
                // Look for restriction check (STATICCALL or internal call)
                let mut has_restriction_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // STATICCALL to detectTransferRestriction
                    if self.bytecode[j] == 0xfa { // STATICCALL
                        has_restriction_check = true;
                        break;
                    }
                    // Or internal JUMP to restriction logic
                    if self.bytecode[j] == 0x56 || self.bytecode[j] == 0x57 { // JUMP/JUMPI
                        // Check if followed by restriction-like logic
                        for k in j+1..(j+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT comparisons
                                has_restriction_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_restriction_check {
                    // Verify this is a transfer (two balance updates)
                    for j in i+1..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Second SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_missing_code_validation(&self) -> Option<usize> {
        // Pattern: STATICCALL (detectTransferRestriction) without return value check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL
                // Check if return value is validated (ISZERO check)
                let mut has_return_validation = false;
                
                for j in i+1..i+20.min(self.bytecode.len()) {
                    // Look for ISZERO (checking if code == 0)
                    if self.bytecode[j] == 0x15 { // ISZERO
                        has_return_validation = true;
                        break;
                    }
                    // Or direct EQ comparison
                    if self.bytecode[j] == 0x14 { // EQ
                        has_return_validation = true;
                        break;
                    }
                }
                
                if !has_return_validation {
                    // Check if followed by transfer logic (SSTORE)
                    for j in i+1..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (transfer proceeding)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_restriction_manipulation(&self) -> Option<usize> {
        // Pattern: Restriction logic storage write without governance
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (restriction rules)
                // Check for governance/owner check
                let mut has_governance_check = false;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (owner check)
                                has_governance_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_governance_check {
                    // Check if this looks like restriction configuration
                    // (multiple related SSTOREs or whitelist patterns)
                    let mut config_pattern = false;
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x20 { // SHA3 (mapping key)
                            config_pattern = true;
                        }
                    }
                    for j in i+1..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Multiple SSTOREs
                            config_pattern = true;
                        }
                    }
                    if config_pattern {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
