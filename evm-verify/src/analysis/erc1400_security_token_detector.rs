use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc1400SecurityTokenVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc1400SecurityTokenDetector {
    bytecode: Vec<u8>,
}

impl Erc1400SecurityTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc1400SecurityTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-1400 defines security tokens with transfer restrictions
        // Detect missing transfer restriction validation
        if let Some(location) = self.has_missing_transfer_restrictions() {
            vulnerabilities.push(Erc1400SecurityTokenVulnerability {
                vulnerability_type: "ERC-1400 Missing Transfer Restrictions".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Security token transfer without canTransfer() validation. Restricted securities could be transferred to unauthorized addresses violating regulations. Implement proper restriction checks before all transfers.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect partition manipulation
        if let Some(location) = self.has_partition_manipulation_risk() {
            vulnerabilities.push(Erc1400SecurityTokenVulnerability {
                vulnerability_type: "ERC-1400 Partition Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Token partition changes without proper validation. Attackers can move tokens between partitions to bypass restrictions. Implement partition change authorization and compliance checks.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect document manipulation
        if let Some(location) = self.has_document_manipulation_risk() {
            vulnerabilities.push(Erc1400SecurityTokenVulnerability {
                vulnerability_type: "ERC-1400 Document Hash Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Security token documents (prospectus, terms) can be modified without governance. Legal terms could be changed after token issuance. Implement document immutability or multi-sig governance.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect controller bypass
        if let Some(location) = self.has_controller_bypass() {
            vulnerabilities.push(Erc1400SecurityTokenVulnerability {
                vulnerability_type: "ERC-1400 Controller Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Token operations bypass controller validation. Controllers should validate all security token operations for regulatory compliance. Implement mandatory controller checks.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_missing_transfer_restrictions(&self) -> Option<usize> {
        // Pattern: Balance update (SSTORE) without prior restriction check (STATICCALL to validator)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (balance update)
                // Look for canTransfer validation before SSTORE
                let mut has_transfer_validation = false;
                
                for j in i.saturating_sub(40)..i {
                    if self.bytecode[j] == 0xfa { // STATICCALL (canTransfer check)
                        has_transfer_validation = true;
                        break;
                    }
                }
                
                if !has_transfer_validation {
                    // Check if this is a transfer (two balance updates)
                    for j in i+1..(i+25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Second SSTORE (recipient balance)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_partition_manipulation_risk(&self) -> Option<usize> {
        // Pattern: Partition change (SSTORE) without authorization
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for partition-related storage update
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check for authorization (CALLER check)
                let mut has_auth_check = false;
                
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (authorization)
                                has_auth_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_auth_check {
                    // Check for partition signature: multiple related SSTOREs
                    let mut related_stores = 0;
                    for j in i+1..(i+30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {
                            related_stores += 1;
                        }
                    }
                    if related_stores >= 2 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_document_manipulation_risk(&self) -> Option<usize> {
        // Pattern: Document hash storage without governance check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (document hash)
                // Look for multi-sig or governance check
                let mut has_governance_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // Check for signature verification or multi-sig pattern
                    if self.bytecode[j] == 0x01 { // Signature recovery/validation
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (signature match)
                                has_governance_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_governance_check {
                    // Check if this looks like document storage (hash-like pattern)
                    for j in i.saturating_sub(10)..i {
                        if self.bytecode[j] == 0x20 { // SHA3
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_controller_bypass(&self) -> Option<usize> {
        // Pattern: Token operation without controller validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for transfer operation
            if self.bytecode[i] == 0x55 { // SSTORE (balance change)
                // Check for controller validation (STATICCALL to controller)
                let mut has_controller_check = false;
                
                for j in i.saturating_sub(40)..i {
                    if self.bytecode[j] == 0xfa { // STATICCALL (controller check)
                        has_controller_check = true;
                        break;
                    }
                }
                
                if !has_controller_check {
                    // Verify this is a token operation (balance updates)
                    for j in i+1..(i+30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // Second balance update
                            // Check if there's any validation logic
                            let mut has_any_validation = false;
                            for k in i.saturating_sub(30)..i {
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                    has_any_validation = true;
                                }
                            }
                            if !has_any_validation {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
