use crate::bytecode::SecurityFinding;

pub struct NftRarityManipulationDetector {
    bytecode: Vec<u8>,
}

impl NftRarityManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_mutable_metadata() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "NFT metadata can be modified after minting at PC {}, enabling rarity manipulation. \
                    Token URI or attributes can be changed to inflate perceived value.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_centralized_rarity_oracle() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "NFT rarity determined by centralized oracle without verification at PC {}. \
                    Single admin can manipulate rarity scores.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_trait_injection() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "NFT traits can be added after minting without proper access control at PC {}. \
                    Rare traits can be injected to manipulate value.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_mutable_metadata(&self) -> Option<usize> {
        // Look for setTokenURI or updateMetadata functions without immutability
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setTokenURI, updateMetadata, setBaseURI selectors
                if matches!(selector, [0x16, 0x2f, 0x4d, 0xe8] | [0x8d, 0x4c, _, _] | [0x55, 0xf8, 0x04, 0xb3]) {
                    let mut has_lock_check = false;
                    let mut has_frozen_flag = false;
                    let mut stores_uri = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for frozen/locked flag
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check if loading frozen state and comparing
                                for k in j..j + 5 {
                                    if self.bytecode[k] == 0x15 { // ISZERO (checking if not frozen)
                                        has_frozen_flag = true;
                                    }
                                }
                            }
                        }
                        // Check for timelock on modifications
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_lock_check = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (storing new URI)
                            stores_uri = true;
                        }
                    }
                    
                    if stores_uri && !has_lock_check && !has_frozen_flag {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_centralized_rarity_oracle(&self) -> Option<usize> {
        // Look for rarity calculation functions relying on single oracle
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getRarity, calculateRarity, rarityScore selectors
                if matches!(selector, [0x7a, 0x3e, _, _] | [0x8b, 0x4f, _, _] | [0x9c, 0x6d, _, _]) {
                    let mut has_single_oracle = false;
                    let mut has_multi_source = false;
                    let mut has_onchain_calculation = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for external oracle call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getRarityFromOracle, fetchRarity selectors
                            if matches!(sub_selector, [0xa1, 0x2e, _, _] | [0xb3, 0x4f, _, _]) {
                                has_single_oracle = true;
                            }
                        }
                        // Check for multiple oracle aggregation (multiple STATICCALL)
                        if j + 30 < self.bytecode.len() {
                            let mut staticcall_count = 0;
                            for k in j..j + 30 {
                                if self.bytecode[k] == 0xfa { // STATICCALL
                                    staticcall_count += 1;
                                }
                            }
                            if staticcall_count >= 2 {
                                has_multi_source = true;
                            }
                        }
                        // Check for onchain calculation (trait counting, etc.)
                        if j + 10 < self.bytecode.len() {
                            let mut has_loop = false;
                            let mut has_counter = false;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x5b { // JUMPDEST (loop)
                                    has_loop = true;
                                }
                                if self.bytecode[k] == 0x01 { // ADD (counter increment)
                                    has_counter = true;
                                }
                            }
                            if has_loop && has_counter {
                                has_onchain_calculation = true;
                            }
                        }
                    }
                    
                    if has_single_oracle && !has_multi_source && !has_onchain_calculation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_trait_injection(&self) -> Option<usize> {
        // Look for trait addition functions without proper access control
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // addTrait, setTrait, updateAttributes selectors
                if matches!(selector, [0x6a, 0x2b, _, _] | [0x7c, 0x4d, _, _] | [0x8e, 0x5f, _, _]) {
                    let mut has_owner_check = false;
                    let mut has_timelock = false;
                    let mut stores_trait = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        // Check for ownership verification
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD
                               j + 2 < self.bytecode.len() && self.bytecode[j + 2] == 0x33 && // CALLER
                               j + 3 < self.bytecode.len() && self.bytecode[j + 3] == 0x14 { // EQ
                                has_owner_check = true;
                            }
                        }
                        // Check for modification timelock
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (mint timestamp)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                has_timelock = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE
                            stores_trait = true;
                        }
                    }
                    
                    if stores_trait && !has_owner_check && !has_timelock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
