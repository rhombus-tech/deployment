use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5169TokenMetadataVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5169TokenMetadataDetector {
    bytecode: Vec<u8>,
}

impl Erc5169TokenMetadataDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5169TokenMetadataVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5169 defines client script URIs for token metadata
        // Detect metadata URI manipulation
        if let Some(location) = self.has_uri_manipulation() {
            vulnerabilities.push(Erc5169TokenMetadataVulnerability {
                vulnerability_type: "ERC-5169 Metadata URI Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Script URI can be changed without governance controls. Malicious scripts could be injected to steal user credentials or funds. Implement URI immutability or multi-sig governance.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing URI validation
        if let Some(location) = self.has_missing_uri_validation() {
            vulnerabilities.push(Erc5169TokenMetadataVulnerability {
                vulnerability_type: "ERC-5169 Missing URI Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "setScriptURI() accepts arbitrary URIs without validation. Malicious or non-HTTPS URIs could be set. Validate URI format and enforce HTTPS for security.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect script execution without integrity check
        if let Some(location) = self.has_missing_integrity_check() {
            vulnerabilities.push(Erc5169TokenMetadataVulnerability {
                vulnerability_type: "ERC-5169 Missing Script Integrity Check".to_string(),
                location,
                severity: "High".to_string(),
                description: "Client scripts loaded without subresource integrity (SRI) hashes. Scripts could be modified on CDN or via MITM attacks. Store and verify script hashes.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_uri_manipulation(&self) -> Option<usize> {
        // Pattern: URI storage write (SSTORE) without governance check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (URI storage)
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
                    // Verify this looks like URI storage (string/bytes data)
                    for j in i.saturating_sub(15)..i {
                        // URI storage often involves MSTORE/MLOAD (memory operations)
                        if self.bytecode[j] == 0x52 || self.bytecode[j] == 0x51 { // MSTORE/MLOAD
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_missing_uri_validation(&self) -> Option<usize> {
        // Pattern: SSTORE URI without validation checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if URI validation logic exists before SSTORE
                let mut has_validation = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for validation patterns:
                    // - Length check (MLOAD for string length)
                    // - Format validation (multiple comparisons)
                    if self.bytecode[j] == 0x51 { // MLOAD (length check)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_validation = true;
                            }
                        }
                    }
                }
                
                if !has_validation {
                    // Check if this looks like URI-related operation
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x37 { // CALLDATACOPY (URI data)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_missing_integrity_check(&self) -> Option<usize> {
        // Pattern: URI storage without corresponding hash storage
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (URI)
                // Check if hash is also stored (SRI check)
                let mut has_hash_storage = false;
                
                for j in i+1..i+40.min(self.bytecode.len()) {
                    // Look for SHA3 (hash calculation)
                    if self.bytecode[j] == 0x20 { // SHA3
                        // Followed by SSTORE (storing hash)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 { // SSTORE
                                has_hash_storage = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_hash_storage {
                    // Verify this is URI-related
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x37 || self.bytecode[j] == 0x52 { // CALLDATACOPY or MSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
