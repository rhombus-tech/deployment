use crate::bytecode::SecurityFinding;

pub struct DynamicNftMetadataDetector {
    bytecode: Vec<u8>,
}

impl DynamicNftMetadataDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_metadata_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Dynamic NFT metadata can be manipulated by unauthorized parties at PC {}. \
                    Attackers can alter traits, rarity, or display properties post-mint.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_metadata_freezing_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "NFT metadata freezing mechanism can be bypassed at PC {}. \
                    Metadata intended to be immutable remains mutable.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_oracle_metadata_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Dynamic metadata relies on manipulable oracle at PC {}. \
                    NFT properties can be influenced by oracle manipulation.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_metadata_manipulation(&self) -> Option<usize> {
        // Look for metadata updates without proper access control
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setTokenURI, updateMetadata, setTraits selectors
                if matches!(selector, [0xa2, 0x2c, 0xb4, 0x65] | [0xb1, 0x3d, _, _] | [0xc2, 0x4e, _, _]) {
                    let mut has_owner_check = false;
                    let mut has_role_check = false;
                    let mut validates_token_ownership = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for owner/admin validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (owner address)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                has_owner_check = true;
                            }
                        }
                        // Check for role-based access control
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x20 && // KECCAK256 (role mapping)
                               j + 7 < self.bytecode.len() &&
                               self.bytecode[j + 6] == 0x54 && // SLOAD
                               j + 9 < self.bytecode.len() &&
                               self.bytecode[j + 8] == 0x15 { // ISZERO
                                has_role_check = true;
                            }
                        }
                        // Check for token ownership validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (tokenId)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x54 && // SLOAD (token owner)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x33 && // CALLER
                               j + 10 < self.bytecode.len() &&
                               self.bytecode[j + 9] == 0x14 { // EQ
                                validates_token_ownership = true;
                            }
                        }
                    }
                    
                    if !has_owner_check && !has_role_check && !validates_token_ownership {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_metadata_freezing_bypass(&self) -> Option<usize> {
        // Look for frozen metadata that can still be modified
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // freezeMetadata, lockURI, setImmutable selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut sets_frozen_flag = false;
                    let mut updates_can_override = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check if frozen flag is set
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && // PUSH1 0x01
                               self.bytecode[j + 1] == 0x01 &&
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x55 { // SSTORE
                                sets_frozen_flag = true;
                            }
                        }
                        // Check if there's logic to override frozen state
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (frozen flag)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x15 && // ISZERO (inverting)
                               j + 7 < self.bytecode.len() &&
                               self.bytecode[j + 6] == 0x55 { // SSTORE (overriding)
                                updates_can_override = true;
                            }
                        }
                    }
                    
                    // Look ahead to see if metadata updates check frozen flag
                    let mut metadata_checks_frozen = false;
                    for k in i.saturating_add(60)..i.saturating_add(150).min(self.bytecode.len()) {
                        if k + 4 < self.bytecode.len() && self.bytecode[k] == 0x63 {
                            let check_selector = &self.bytecode[k + 1..k + 5];
                            // setTokenURI selector
                            if matches!(check_selector, [0xa2, 0x2c, 0xb4, 0x65]) {
                                // Check if it loads frozen flag
                                for m in k..k.saturating_add(30).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x54 && // SLOAD (frozen)
                                       m + 2 < self.bytecode.len() &&
                                       self.bytecode[m + 1] == 0x15 { // ISZERO (require not frozen)
                                        metadata_checks_frozen = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    if sets_frozen_flag && (!metadata_checks_frozen || updates_can_override) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_oracle_metadata_exploit(&self) -> Option<usize> {
        // Look for dynamic metadata based on external oracles
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // tokenURI, getMetadata selectors
                if matches!(selector, [0xc8, 0x7b, 0x56, 0xdd] | [0xa1, 0x3e, _, _]) {
                    let mut loads_oracle_data = false;
                    let mut validates_oracle_source = false;
                    let mut has_fallback_metadata = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for external oracle call
                        if j + 4 < self.bytecode.len() {
                            if (self.bytecode[j] == 0xfa || // STATICCALL
                                self.bytecode[j] == 0xf1) { // CALL
                                loads_oracle_data = true;
                            }
                        }
                        // Check for oracle address validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (oracle address)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x14 { // EQ (checking approved oracle)
                                validates_oracle_source = true;
                            }
                        }
                        // Check for fallback/default metadata
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x57 && // JUMPI (conditional)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 { // SLOAD (default URI)
                                has_fallback_metadata = true;
                            }
                        }
                    }
                    
                    if loads_oracle_data && (!validates_oracle_source || !has_fallback_metadata) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
