use crate::bytecode::SecurityFinding;

pub struct KAnonymityViolationDetector {
    bytecode: Vec<u8>,
}

impl KAnonymityViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_identity_linkage() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Data anonymization can be defeated through linkage attacks at PC {}. \
                    Insufficient k-anonymity allows user de-identification through attribute correlation.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_quasi_identifier_exposure() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Quasi-identifiers exposed without adequate generalization at PC {}. \
                    Combination of attributes enables user re-identification.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_temporal_correlation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Temporal data patterns violate k-anonymity at PC {}. \
                    Time-series analysis can link pseudonymous transactions to real identities.",
                    pc
                ),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_identity_linkage(&self) -> Option<usize> {
        // Look for data storage without anonymization
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // storeUserData, recordTransaction, submitData selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut stores_multiple_attributes = false;
                    let mut applies_anonymization = false;
                    let mut checks_uniqueness_set = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Count stored attributes
                        let mut sstore_count = 0;
                        for k in j..j.saturating_add(30).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 { // SSTORE
                                sstore_count += 1;
                            }
                        }
                        if sstore_count >= 3 {
                            stores_multiple_attributes = true;
                        }
                        
                        // Check for anonymization function
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // generalize, suppress, hash selectors
                            if matches!(sub_selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0x20, _, _, _]) {
                                applies_anonymization = true;
                            }
                        }
                        
                        // Check for uniqueness set validation (k-anonymity check)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (anonymity set size)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking minimum k)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                checks_uniqueness_set = true;
                            }
                        }
                    }
                    
                    if stores_multiple_attributes && !applies_anonymization && !checks_uniqueness_set {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_quasi_identifier_exposure(&self) -> Option<usize> {
        // Look for attribute combinations that enable re-identification
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getUserProfile, getAttributes, queryData selectors
                if matches!(selector, [0xa2, 0x3e, _, _] | [0xb3, 0x4f, _, _] | [0xc4, 0x5d, _, _]) {
                    let mut returns_precise_data = false;
                    let mut applies_suppression = false;
                    let mut generalizes_values = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if returning precise stored values
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (raw data)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0xf3 { // RETURN (directly)
                                returns_precise_data = true;
                            }
                        }
                        
                        // Check for suppression (hiding rare values)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (value)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (rarity check)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x60 { // PUSH1 0x00 (suppress to null)
                                applies_suppression = true;
                            }
                        }
                        
                        // Check for generalization (range buckets)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x04 { // DIV (bucketing)
                                generalizes_values = true;
                            }
                        }
                    }
                    
                    if returns_precise_data && !applies_suppression && !generalizes_values {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_temporal_correlation(&self) -> Option<usize> {
        // Look for timestamp-based data that enables tracking
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // logActivity, recordEvent, trackAction selectors
                if matches!(selector, [0xa3, 0x3e, _, _] | [0xb4, 0x4f, _, _] | [0xc5, 0x5d, _, _]) {
                    let mut stores_timestamp = false;
                    let mut stores_user_id = false;
                    let mut applies_time_bucketing = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if storing timestamp
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x55 { // SSTORE
                                stores_timestamp = true;
                            }
                        }
                        
                        // Check if storing user identifier
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x55 { // SSTORE
                                stores_user_id = true;
                            }
                        }
                        
                        // Check for time bucketing (generalization)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x04 && // DIV (time bucket)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x02 { // MUL (bucket size)
                                applies_time_bucketing = true;
                            }
                        }
                    }
                    
                    if stores_timestamp && stores_user_id && !applies_time_bucketing {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
