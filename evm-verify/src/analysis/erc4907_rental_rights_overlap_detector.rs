use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc4907RentalOverlapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc4907RentalRightsOverlapDetector {
    bytecode: Vec<u8>,
}

impl Erc4907RentalRightsOverlapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4907RentalOverlapVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-4907 defines user rights for NFT rentals with expiration times
        // Detect overlapping rental periods without proper validation
        if let Some(location) = self.has_rental_overlap_risk() {
            vulnerabilities.push(Erc4907RentalOverlapVulnerability {
                vulnerability_type: "ERC-4907 Rental Rights Overlap".to_string(),
                location,
                severity: "High".to_string(),
                description: "NFT rental user assignment without checking existing rental expiration. Multiple users could have overlapping rental rights. Implement expiration validation before setUser().".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing expiration checks in userOf() function
        if let Some(location) = self.has_missing_expiration_check() {
            vulnerabilities.push(Erc4907RentalOverlapVulnerability {
                vulnerability_type: "ERC-4907 Missing Expiration Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "userOf() implementation missing timestamp comparison to validate rental expiration. Expired users could retain access rights. Check block.timestamp against stored expires value.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect setUser without owner/approved check
        if let Some(location) = self.has_unauthorized_rental_assignment() {
            vulnerabilities.push(Erc4907RentalOverlapVulnerability {
                vulnerability_type: "ERC-4907 Unauthorized Rental Assignment".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "setUser() allows rental assignment without verifying caller is owner or approved. Attackers can assign rental rights to arbitrary addresses. Implement proper authorization checks.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_rental_overlap_risk(&self) -> Option<usize> {
        // Pattern: Storage write (setUser) without timestamp comparison
        // ERC-4907 signature: setUser(uint256 tokenId, address user, uint64 expires)
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (setting user)
                // Look for timestamp check before SSTORE
                let mut has_expiration_check = false;
                
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Check for comparison operation
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                has_expiration_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_expiration_check {
                    // Check if this is rental-related (multiple SSTOREs for user + expires)
                    let mut has_second_sstore = false;
                    for j in i+1..i+15.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Second SSTORE (expires)
                            has_second_sstore = true;
                            break;
                        }
                    }
                    if has_second_sstore {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_missing_expiration_check(&self) -> Option<usize> {
        // Pattern: SLOAD (reading user) without subsequent TIMESTAMP comparison
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading user data)
                // Check if followed by another SLOAD (expires field)
                let mut has_expires_load = false;
                let mut has_timestamp_check = false;
                
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // Second SLOAD (expires)
                        has_expires_load = true;
                    }
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                has_timestamp_check = true;
                                break;
                            }
                        }
                    }
                }
                
                // If expires loaded but not compared with timestamp
                if has_expires_load && !has_timestamp_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_unauthorized_rental_assignment(&self) -> Option<usize> {
        // Pattern: SSTORE without CALLER authorization check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (setUser)
                // Look for authorization check (CALLER + EQ)
                let mut has_auth_check = false;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        // Look for EQ comparison (owner check)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ
                                has_auth_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_auth_check {
                    // Verify this is rental-related by checking for paired SSTORE
                    for j in i+1..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Second SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
