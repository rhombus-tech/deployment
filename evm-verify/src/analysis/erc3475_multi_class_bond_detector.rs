use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc3475BondClassVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc3475MultiClassBondDetector {
    bytecode: Vec<u8>,
}

impl Erc3475MultiClassBondDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc3475BondClassVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-3475 defines multi-class bonds with (classId, nonceId) pairs
        // Detect class ID manipulation attacks
        if let Some(location) = self.has_class_id_manipulation() {
            vulnerabilities.push(Erc3475BondClassVulnerability {
                vulnerability_type: "ERC-3475 Bond Class ID Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Bond operations allow arbitrary class ID manipulation without validation. Attackers can create or reference invalid bond classes with manipulated terms. Implement class ID whitelist and validation.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing maturity date validation
        if let Some(location) = self.has_missing_maturity_validation() {
            vulnerabilities.push(Erc3475BondClassVulnerability {
                vulnerability_type: "ERC-3475 Missing Maturity Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Bond redemption without maturity date validation. Bonds could be redeemed before maturity or with manipulated redemption values. Check block.timestamp against maturity before redeem().".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect nonce reuse vulnerability
        if let Some(location) = self.has_nonce_reuse_risk() {
            vulnerabilities.push(Erc3475BondClassVulnerability {
                vulnerability_type: "ERC-3475 Bond Nonce Reuse".to_string(),
                location,
                severity: "High".to_string(),
                description: "Bond nonce generation without proper uniqueness checks. Same (classId, nonceId) pair could be reused with different terms. Implement nonce uniqueness validation.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect class metadata manipulation
        if let Some(location) = self.has_metadata_manipulation_risk() {
            vulnerabilities.push(Erc3475BondClassVulnerability {
                vulnerability_type: "ERC-3475 Class Metadata Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Bond class metadata (symbol, values) can be changed after issuance without restrictions. Issued bonds could have terms retroactively modified. Implement immutable class metadata or governance controls.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_class_id_manipulation(&self) -> Option<usize> {
        // Pattern: CALLDATALOAD (classId parameter) used directly in SSTORE without validation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (reading classId)
                // Check if used in storage operation without validation
                let mut has_validation = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Look for bounds check (LT/GT) or whitelist check (EQ)
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 || self.bytecode[j] == 0x14 {
                        has_validation = true;
                    }
                    // If SSTORE without validation
                    if self.bytecode[j] == 0x55 && !has_validation { // SSTORE
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_missing_maturity_validation(&self) -> Option<usize> {
        // Pattern: Bond redemption (SLOAD) without timestamp comparison
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading bond data)
                // Look for value transfer (CALL) without timestamp check
                let mut has_timestamp_check = false;
                
                for j in i+1..(i+35).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT or GT
                                has_timestamp_check = true;
                                break;
                            }
                        }
                    }
                    // If CALL (redemption) without timestamp check
                    if self.bytecode[j] == 0xf1 && !has_timestamp_check { // CALL
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_nonce_reuse_risk(&self) -> Option<usize> {
        // Pattern: Nonce storage without uniqueness check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for nonce-related storage pattern
            if self.bytecode[i] == 0x55 { // SSTORE (storing nonce)
                // Check if there's a prior existence check (SLOAD + ISZERO)
                let mut has_existence_check = false;
                
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (checking if exists)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (must not exist)
                                has_existence_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_existence_check {
                    // Verify this is nonce-related by checking for class ID computation
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x1b { // ADD or SHA3
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_metadata_manipulation_risk(&self) -> Option<usize> {
        // Pattern: Metadata storage write without access control
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (metadata update)
                // Check for owner/governance check
                let mut has_access_control = false;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (owner check)
                                has_access_control = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_access_control {
                    // Check if this is metadata-related (multiple SSTOREs for symbol, values)
                    let mut sstore_count = 1;
                    for j in i+1..(i+30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {
                            sstore_count += 1;
                        }
                    }
                    if sstore_count >= 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
