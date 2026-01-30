use serde::{Serialize, Deserialize};
use crate::bytecode::SecurityFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Permit2Vulnerability {
    PatternDetected,
    SecurityIssue,
}

pub struct Permit2Detector {
    bytecode: Vec<u8>,
}

impl Permit2Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_signature_replay() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Permit2 signature can be replayed across different contexts at PC {}. \
                    Missing nonce or domain separator validation enables signature reuse.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_unlimited_approval_risk() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Permit2 allows unlimited token approvals without expiration at PC {}. \
                    Users exposed to permanent approval risks.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_witness_data_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Permit2 witness data not properly validated at PC {}. \
                    Attacker can manipulate auxiliary data in permit signatures.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        findings
    }

    fn detect_signature_replay(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // permit, permitTransferFrom, permitWitnessTransferFrom selectors
                if matches!(selector, [0xd5, 0x05, 0xac, 0xcf] | [0x30, 0xf2, 0x8b, 0x7a] | [0x13, 0x7c, 0x29, 0xfe]) {
                    let mut has_nonce_check = false;
                    let mut has_domain_separator = false;
                    let mut uses_signature = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for nonce validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (loading nonce)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x01 && // ADD (incrementing nonce)
                               self.bytecode[j + 4] == 0x55 { // SSTORE (storing new nonce)
                                has_nonce_check = true;
                            }
                        }
                        // Check for domain separator usage
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // DOMAIN_SEPARATOR() selector
                            if matches!(sub_selector, [0x36, 0x56, 0x61, 0x0d]) {
                                has_domain_separator = true;
                            }
                        }
                        // Check for ecrecover usage
                        if j + 2 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 { // PUSH1 0x01
                                uses_signature = true;
                            }
                        }
                    }
                    
                    if uses_signature && (!has_nonce_check || !has_domain_separator) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unlimited_approval_risk(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // approve, permit selectors
                if matches!(selector, [0x09, 0x5e, 0xa7, 0xb3] | [0xd5, 0x05, 0xac, 0xcf]) {
                    let mut sets_approval = false;
                    let mut has_expiration = false;
                    let mut has_amount_limit = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (setting approval)
                            sets_approval = true;
                        }
                        // Check for deadline/expiration validation
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 3 < self.bytecode.len() &&
                               (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) { // LT or GT
                                has_expiration = true;
                            }
                        }
                        // Check for uint256.max detection (unlimited approval)
                        if j + 2 < self.bytecode.len() {
                            if self.bytecode[j] == 0x7f { // PUSH32 (checking for max uint256)
                                has_amount_limit = true;
                            }
                        }
                    }
                    
                    if sets_approval && !has_expiration && has_amount_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_witness_data_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // permitWitnessTransferFrom selector
                if matches!(selector, [0x13, 0x7c, 0x29, 0xfe]) {
                    let mut has_witness_data = false;
                    let mut validates_witness = false;
                    let mut hashes_witness = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for witness data loading (CALLDATALOAD)
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD
                            has_witness_data = true;
                        }
                        // Check for witness hash validation
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256
                               j + 2 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x14 { // EQ (comparing hash)
                                validates_witness = true;
                                hashes_witness = true;
                            }
                        }
                    }
                    
                    if has_witness_data && !validates_witness {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Permit2Vulnerability> {
        self.detect().into_iter().map(|_| Permit2Vulnerability::SecurityIssue).collect()
    }
}
