use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5058LockableNftVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5058LockableNftDetector {
    bytecode: Vec<u8>,
}

impl Erc5058LockableNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5058LockableNftVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5058 defines lockable NFTs with lock/unlock functionality
        // Detect lock bypass vulnerabilities
        if let Some(location) = self.has_lock_bypass() {
            vulnerabilities.push(Erc5058LockableNftVulnerability {
                vulnerability_type: "ERC-5058 NFT Lock Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "NFT transfer possible while locked. Lock state not checked before transfer allowing locked NFTs to be moved. Verify isLocked() returns false before all transfers.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect unauthorized unlock
        if let Some(location) = self.has_unauthorized_unlock() {
            vulnerabilities.push(Erc5058LockableNftVulnerability {
                vulnerability_type: "ERC-5058 Unauthorized Unlock".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "unlock() callable by non-approved addresses. Attackers can unlock any NFT to steal or transfer it. Implement proper authorization checking owner/approved status.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect lock expiration bypass
        if let Some(location) = self.has_lock_expiration_bypass() {
            vulnerabilities.push(Erc5058LockableNftVulnerability {
                vulnerability_type: "ERC-5058 Lock Expiration Bypass".to_string(),
                location,
                severity: "High".to_string(),
                description: "Lock expiration time not validated. Expired locks should auto-unlock but contract doesn't check timestamp. Implement automatic expiration in lock status queries.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_lock_bypass(&self) -> Option<usize> {
        // Pattern: Transfer (SSTORE balance change) without lock status check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (owner change/transfer)
                // Look for lock status check before transfer
                let mut has_lock_check = false;
                
                for j in i.saturating_sub(30)..i {
                    // Check for SLOAD of lock status
                    if self.bytecode[j] == 0x54 { // SLOAD (reading lock status)
                        // Check if followed by ISZERO (checking if unlocked)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (must be unlocked)
                                has_lock_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_lock_check {
                    // Verify this is an NFT transfer (token ID involved)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (tokenId)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_unauthorized_unlock(&self) -> Option<usize> {
        // Pattern: Lock status change (SSTORE) without authorization check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (changing lock status)
                // Look for owner/approved check
                let mut has_auth_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // Check for CALLER comparison
                    if self.bytecode[j] == 0x33 { // CALLER
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (owner check)
                                has_auth_check = true;
                                break;
                            }
                        }
                    }
                    // Or getApproved check (STATICCALL)
                    if self.bytecode[j] == 0xfa { // STATICCALL (isApprovedForAll)
                        has_auth_check = true;
                    }
                }
                
                if !has_auth_check {
                    // Verify this looks like lock/unlock operation
                    // (writes boolean-like value)
                    for j in i.saturating_sub(10)..i {
                        if self.bytecode[j] == 0x60 { // PUSH1
                            if j + 1 < self.bytecode.len() {
                                let val = self.bytecode[j + 1];
                                if val == 0 || val == 1 { // Boolean values
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_lock_expiration_bypass(&self) -> Option<usize> {
        // Pattern: Lock status read (SLOAD) without expiration time check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 { // SLOAD (reading lock status)
                // Check if expiration is also loaded
                let mut has_expiration_load = false;
                let mut has_timestamp_check = false;
                
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // Second SLOAD (expiration time)
                        has_expiration_load = true;
                    }
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_timestamp_check = true;
                                break;
                            }
                        }
                    }
                }
                
                // If lock has expiration but not checked against timestamp
                if has_expiration_load && !has_timestamp_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
