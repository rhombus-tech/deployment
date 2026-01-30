use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMergingManipulationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct BundleMergingManipulationDetector {
    bytecode: Vec<u8>,
}

impl BundleMergingManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BundleMergingManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bundle merging attacks manipulate transaction batching
        // Detect bundle atomicity assumptions that can be broken
        if let Some(location) = self.has_bundle_atomicity_assumption() {
            vulnerabilities.push(BundleMergingManipulationVulnerability {
                vulnerability_type: "Bundle Atomicity Assumption Violation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Protocol assumes transaction bundles execute atomically without verification. Builders can split or merge bundles to extract MEV or cause state inconsistencies. Implement bundle integrity verification.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect cross-bundle state dependencies
        if let Some(location) = self.has_cross_bundle_dependency() {
            vulnerabilities.push(BundleMergingManipulationVulnerability {
                vulnerability_type: "Cross-Bundle State Dependency".to_string(),
                location,
                severity: "High".to_string(),
                description: "State transitions depend on multiple bundles executing in sequence. Attackers can manipulate bundle ordering or inject transactions between bundles. Use single atomic bundle or explicit ordering proofs.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect bundle priority manipulation
        if let Some(location) = self.has_bundle_priority_gaming() {
            vulnerabilities.push(BundleMergingManipulationVulnerability {
                vulnerability_type: "Bundle Priority Gaming".to_string(),
                location,
                severity: "High".to_string(),
                description: "Bundle execution priority based on payment without fairness guarantees. Attackers can pay incrementally more to guarantee front-running entire bundles. Implement fair bundle ordering or discrete priority tiers.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_bundle_atomicity_assumption(&self) -> Option<usize> {
        // Pattern: Multi-transaction state transitions without atomicity checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for state read that assumes previous write in same bundle
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if immediately used in critical operation
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0x55 { // CALL or SSTORE
                        // Check if there's bundle integrity verification
                        let mut verifies_bundle = false;
                        
                        for k in i.saturating_sub(40)..i {
                            // Look for bundle ID or transaction index validation
                            // Typically involves checking msg.sender or transaction context
                            if self.bytecode[k] == 0x33 { // CALLER
                                for m in k+1..(k+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 { // EQ (verifying bundle member)
                                        verifies_bundle = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !verifies_bundle {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_cross_bundle_dependency(&self) -> Option<usize> {
        // Pattern: State flag that coordinates multiple transactions
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for flag/counter that increments
            if self.bytecode[i] == 0x01 { // ADD (incrementing counter)
                // Check if followed by SSTORE
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE (saving counter)
                        // Check if this counter is used to gate operations
                        for k in j+1..(j+30).min(self.bytecode.len()).min(self.bytecode.len()) {
                            // Look for counter comparison
                            if self.bytecode[k] == 0x54 { // SLOAD (reading counter)
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 || self.bytecode[m] == 0x10 { // EQ or LT
                                        // Check if there's bundle sequence proof
                                        let mut has_sequence_proof = false;
                                        
                                        for n in i.saturating_sub(40)..m {
                                            // Look for cryptographic proof (hash, signature)
                                            if self.bytecode[n] == 0x20 || self.bytecode[n] == 0x01 { // SHA3 or ECRECOVER
                                                has_sequence_proof = true;
                                            }
                                        }
                                        
                                        if !has_sequence_proof {
                                            return Some(i);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_bundle_priority_gaming(&self) -> Option<usize> {
        // Pattern: Bundle selection based on payment amount
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for payment-based priority (comparing values)
            if self.bytecode[i] == 0x34 { // CALLVALUE
                // Check if used for priority ordering
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 { // GT or LT (priority comparison)
                        // Check if there's fairness mechanism (time-based, etc.)
                        let mut has_fairness = false;
                        
                        for k in i.saturating_sub(30)..i+30.min(self.bytecode.len()) {
                            // Look for timestamp or block-based fairness
                            if self.bytecode[k] == 0x42 || self.bytecode[k] == 0x43 { // TIMESTAMP or NUMBER
                                // Check if used in priority calculation
                                for m in k+1..(k+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x02 || self.bytecode[m] == 0x01 { // MUL or ADD
                                        has_fairness = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !has_fairness {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
