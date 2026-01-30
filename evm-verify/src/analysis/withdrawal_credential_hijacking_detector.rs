use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalCredentialHijackingVulnerability {
    pub location: usize,
    pub hijacking_type: CredentialHijackingType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialHijackingType {
    WithdrawalAddressOverwrite,      // Overwrite withdrawal credentials
    CredentialChangeWithoutDelay,    // Change credentials without timelock
    UnauthorizedCredentialUpdate,    // Update credentials without proper auth
    FrontRunningCredentialChange,    // Front-run legitimate credential updates
    MaliciousCredentialInjection,    // Inject malicious withdrawal address
    CredentialStorageManipulation,   // Manipulate credential storage directly
}

pub struct WithdrawalCredentialHijackingDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalCredentialHijackingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WithdrawalCredentialHijackingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_withdrawal_address_overwrite() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::WithdrawalAddressOverwrite,
                severity: "Critical".to_string(),
                description: "Withdrawal credentials can be overwritten without proper validation. \
                             Attacker can change withdrawal address to steal staked funds. Critical \
                             for validator withdrawal security.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_credential_change_without_delay() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::CredentialChangeWithoutDelay,
                severity: "Critical".to_string(),
                description: "Withdrawal credential changes lack mandatory delay period. Allows \
                             instant hijacking without time for intervention. Should require \
                             multi-day delay for security.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_unauthorized_credential_update() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::UnauthorizedCredentialUpdate,
                severity: "Critical".to_string(),
                description: "Withdrawal credentials can be updated without proper authorization. \
                             Missing access control allows anyone to change withdrawal address.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_frontrunning_credential_change() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::FrontRunningCredentialChange,
                severity: "High".to_string(),
                description: "Credential change transactions can be front-run. Attacker can observe \
                             pending credential updates and front-run with malicious address.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_malicious_credential_injection() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::MaliciousCredentialInjection,
                severity: "Critical".to_string(),
                description: "Malicious withdrawal credentials can be injected during validator setup. \
                             Insufficient validation of credential parameters allows attacker-controlled \
                             withdrawal addresses.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_credential_storage_manipulation() {
            vulnerabilities.push(WithdrawalCredentialHijackingVulnerability {
                location: loc,
                hijacking_type: CredentialHijackingType::CredentialStorageManipulation,
                severity: "Critical".to_string(),
                description: "Direct storage manipulation of withdrawal credentials possible. Storage \
                             slots containing credentials lack proper protection against unauthorized \
                             writes.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_withdrawal_address_overwrite(&self) -> Option<usize> {
        // SSTORE to credential storage without validation
        // Pattern: withdrawal credential slot (common: 0x00..01 for BLS, 0x00..02 for execution)
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x7f && i + 32 < self.bytecode.len() { // PUSH32
                // Check if it's a credential-like slot
                let is_credential_slot = self.bytecode[i + 1] == 0x00 && 
                                        (self.bytecode[i + 31] == 0x01 || self.bytecode[i + 31] == 0x02);
                
                if is_credential_slot && i + 33 < self.bytecode.len() {
                    if self.bytecode[i + 33] == 0x55 { // SSTORE
                        // Check for access control
                        let mut has_auth_check = false;
                        for j in i.saturating_sub(30)..i {
                            if self.bytecode[j] == 0x33 { // CALLER check
                                has_auth_check = true;
                                break;
                            }
                        }
                        if !has_auth_check {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_credential_change_without_delay(&self) -> Option<usize> {
        // Pattern: credential update without timestamp check
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for setWithdrawalCredentials selector: 0x7b103999
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x7b103999 || selector == 0x5c19a95c { // Common credential setters
                    // Check for timestamp delay validation
                    let mut has_delay_check = false;
                    for j in i..std::cmp::min(i + 40, self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            // Check if compared with stored timestamp
                            for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                                if matches!(self.bytecode[k], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                                    has_delay_check = true;
                                    break;
                                }
                            }
                        }
                        if has_delay_check {
                            break;
                        }
                    }
                    if !has_delay_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unauthorized_credential_update(&self) -> Option<usize> {
        // Credential update without owner/admin check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (credential write)
                // Check if preceded by CALLER validation
                let mut has_caller_check = false;
                let mut has_owner_check = false;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        has_caller_check = true;
                    }
                    // Look for owner storage load
                    if self.bytecode[j] == 0x54 { // SLOAD
                        has_owner_check = true;
                    }
                }
                
                // Credential SSTORE should have both caller and owner checks
                if has_caller_check && !has_owner_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_frontrunning_credential_change(&self) -> Option<usize> {
        // Credential change without commit-reveal or similar protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Credential update selectors
                if selector == 0x7b103999 || selector == 0x5c19a95c {
                    // Check for commit hash (protection against front-running)
                    let mut has_commit_hash = false;
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        // Look for SHA3 (commit hash)
                        if self.bytecode[j] == 0x20 { // SHA3
                            has_commit_hash = true;
                            break;
                        }
                    }
                    if !has_commit_hash {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_malicious_credential_injection(&self) -> Option<usize> {
        // Validator registration without credential validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Deposit/stake selectors: 0x22895118, 0x00f714ce
                if selector == 0x22895118 || selector == 0x00f714ce {
                    // Check for credential format validation
                    let mut has_validation = false;
                    for j in i..std::cmp::min(i + 45, self.bytecode.len()) {
                        // Look for credential type check (0x00 vs 0x01)
                        if self.bytecode[j] == 0x60 && j + 1 < self.bytecode.len() {
                            if self.bytecode[j + 1] == 0x00 || self.bytecode[j + 1] == 0x01 {
                                if j + 3 < self.bytecode.len() && self.bytecode[j + 3] == 0x14 { // EQ
                                    has_validation = true;
                                    break;
                                }
                            }
                        }
                    }
                    if !has_validation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_credential_storage_manipulation(&self) -> Option<usize> {
        // Direct SSTORE to credential slots without proper gate-keeping
        let mut credential_writes = 0;
        let mut first_write = None;
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if in credential-related function
                let is_credential_context = i > 50 && {
                    let mut found_selector = false;
                    for j in i.saturating_sub(50)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            // Withdrawal-related selectors
                            if sel == 0x7b103999 || sel == 0x5c19a95c || sel == 0x3ccfd60b {
                                found_selector = true;
                                break;
                            }
                        }
                    }
                    found_selector
                };
                
                if is_credential_context {
                    credential_writes += 1;
                    if first_write.is_none() {
                        first_write = Some(i);
                    }
                    
                    // Multiple credential writes without proper checks is suspicious
                    if credential_writes > 2 {
                        return first_write;
                    }
                }
            }
        }
        None
    }
}
