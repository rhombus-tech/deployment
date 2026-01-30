use crate::bytecode::SecurityFinding;

pub struct ConnextAmarokRouterDetector {
    bytecode: Vec<u8>,
}

impl ConnextAmarokRouterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_router_whitelist_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Connext Amarok router whitelist check missing at PC {}. \
                    Unauthorized routers can process cross-chain messages and steal funds.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_domain_authentication_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Domain authentication not enforced at PC {}. \
                    Messages from unauthorized chains can be executed.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_slippage_protection_missing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Cross-chain swap lacks slippage protection at PC {}. \
                    Users vulnerable to sandwich attacks during bridge transfers.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_router_whitelist_bypass(&self) -> Option<usize> {
        // Look for Connext router calls without whitelist validation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // xcall, execute, handle selectors (Amarok functions)
                if matches!(selector, [0xd4, 0x2f, _, _] | [0xe1, 0x3c, _, _] | [0xf2, 0x4d, _, _]) {
                    let mut has_router_validation = false;
                    let mut has_whitelist_check = false;
                    let mut loads_router_registry = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for router address extraction
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (router address)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 { // SLOAD (loading from registry)
                                loads_router_registry = true;
                            }
                        }
                        // Check for whitelist comparison
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0x14 && // EQ (comparing router)
                               j + 2 < self.bytecode.len() &&
                               self.bytecode[j + 1] == 0x15 { // ISZERO (checking if approved)
                                has_whitelist_check = true;
                            }
                        }
                        // Check for approved router mapping lookup
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256 (mapping key)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                has_router_validation = true;
                            }
                        }
                    }
                    
                    if !has_router_validation && !has_whitelist_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_domain_authentication_bypass(&self) -> Option<usize> {
        // Look for cross-domain message handling without domain verification
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // handle, reconcile, process selectors
                if matches!(selector, [0xf2, 0x4d, _, _] | [0xa1, 0x3e, _, _] | [0xb2, 0x5f, _, _]) {
                    let mut checks_origin_domain = false;
                    let mut validates_domain_whitelist = false;
                    let mut extracts_domain_id = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for domain ID extraction from message
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x1c { // SHR (extracting domain from packed data)
                                extracts_domain_id = true;
                            }
                        }
                        // Check for domain validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (approved domains)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x14 { // EQ (comparing domain)
                                checks_origin_domain = true;
                            }
                        }
                        // Check for domain whitelist lookup
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x54 && // SLOAD
                               j + 7 < self.bytecode.len() &&
                               self.bytecode[j + 6] == 0x15 { // ISZERO
                                validates_domain_whitelist = true;
                            }
                        }
                    }
                    
                    if extracts_domain_id && !checks_origin_domain && !validates_domain_whitelist {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_slippage_protection_missing(&self) -> Option<usize> {
        // Look for xcall swaps without minimum amount checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // xcall, xcallIntoLocal selectors
                if matches!(selector, [0xd4, 0x2f, _, _] | [0xe5, 0x6c, _, _]) {
                    let mut has_amount_in = false;
                    let mut has_min_amount_check = false;
                    let mut executes_swap = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for amount parameter
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 { // CALLDATALOAD
                                has_amount_in = true;
                            }
                        }
                        // Check for minimum amount comparison
                        if j + 6 < self.bytecode.len() {
                            if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) && // LT or GT
                               j + 2 < self.bytecode.len() &&
                               self.bytecode[j + 1] == 0x15 { // ISZERO (require check)
                                has_min_amount_check = true;
                            }
                        }
                        // Check if actually performing swap
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // swap, swapExact selectors
                            if matches!(sub_selector, [0x38, 0xed, 0x17, 0x39] | [0x12, 0x2e, _, _]) {
                                executes_swap = true;
                            }
                        }
                    }
                    
                    if has_amount_in && executes_swap && !has_min_amount_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
