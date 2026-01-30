use serde::{Serialize, Deserialize};

/// Blob Transaction MEV Extraction Detection (EIP-4844)
/// 
/// EIP-4844 introduces blob transactions for cheaper L2 data availability.
/// New MEV opportunities:
/// 
/// 1. Blob gas price manipulation
/// 2. Blob data ordering attacks
/// 3. Cross-domain MEV (L1 blob -> L2 state)
/// 4. Blob withholding attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlobMevExtractionVulnerability {
    /// Critical: Blob data can be front-run
    BlobFrontrunRisk {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: No blob gas price protection
    MissingBlobGasProtection {
        description: String,
        location: usize,
    },
    /// High: Blob commitment not verified
    UnverifiedBlobCommitment {
        description: String,
        location: usize,
    },
    /// Medium: Blob data ordering exploitable
    ExploitableBlobOrdering {
        description: String,
        location: usize,
    },
    /// Medium: Cross-domain blob timing attack
    CrossDomainTimingRisk {
        description: String,
        location: usize,
    },
}

pub struct BlobMevExtractionDetector {
    bytecode: Vec<u8>,
}

impl BlobMevExtractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlobMevExtractionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check for BLOBHASH opcode usage (EIP-4844)
        // BLOBHASH opcode: 0x49
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x49 { // BLOBHASH
                // This contract reads blob hashes
                // Check if blob hash is used for critical decisions
                let used_in_decision = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(3)
                    .any(|w| {
                        w[0] == 0x14 && w[1] == 0x57 // EQ, JUMPI (conditional logic)
                    });
                
                if used_in_decision {
                    // Check if there's protection against MEV
                    let has_mev_protection = self.has_blob_mev_protection(i);
                    
                    if !has_mev_protection {
                        vulnerabilities.push(BlobMevExtractionVulnerability::BlobFrontrunRisk {
                            description: "Blob hash used in conditional logic without MEV protection".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
                
                // Check if blob commitment is properly verified
                let verifies_commitment = self.verifies_blob_commitment(i);
                
                if !verifies_commitment {
                    vulnerabilities.push(BlobMevExtractionVulnerability::UnverifiedBlobCommitment {
                        description: "Blob hash not cryptographically verified - can be manipulated".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 2: Check for BLOBBASEFEE opcode (EIP-4844)
        // BLOBBASEFEE opcode: 0x4a
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x4a { // BLOBBASEFEE
                // Check if blob gas price is considered in logic
                let used_in_calc = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(2)
                    .any(|w| {
                        w[0] == 0x02 || w[0] == 0x04 || w[0] == 0x10 || w[0] == 0x11
                        // MUL, DIV, LT, GT
                    });
                
                if !used_in_calc {
                    vulnerabilities.push(BlobMevExtractionVulnerability::MissingBlobGasProtection {
                        description: "Contract reads BLOBBASEFEE but doesn't use it for protection".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Check for L2 sequencer functions that process blob data
        // These are vulnerable to ordering attacks
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this processes sequencer batches
                if self.is_batch_processing_function(i) {
                    // Check for blob data ordering protection
                    let has_ordering_protection = self.has_ordering_protection(i);
                    
                    if !has_ordering_protection {
                        vulnerabilities.push(BlobMevExtractionVulnerability::ExploitableBlobOrdering {
                            description: format!(
                                "Batch processing (0x{:08x}) without blob ordering protection",
                                selector
                            ),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for cross-domain message relayers
        // Blob data on L1 affects L2 state - timing matters
        for i in 0..self.bytecode.len().saturating_sub(70) {
            // Look for cross-domain messaging patterns
            if self.is_cross_domain_relay(i) {
                // Check if there's timestamp/block protection
                let has_timing_protection = self.has_timing_protection(i);
                
                if !has_timing_protection {
                    vulnerabilities.push(BlobMevExtractionVulnerability::CrossDomainTimingRisk {
                        description: "Cross-domain relay without timing constraints - blob MEV possible".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 5: Check for blob data commitment schemes
        // Should use KZG commitments properly
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for commitment verification patterns
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                // Check if calling KZG point evaluation precompile (address 0x0A)
                let calls_kzg_precompile = self.bytecode[i.saturating_sub(20)..i]
                    .windows(2)
                    .any(|w| {
                        w[0] == 0x60 && w[1] == 0x0a // PUSH1 0x0A (KZG precompile)
                    });
                
                if calls_kzg_precompile {
                    // Verify return value is checked
                    let checks_return = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                        .windows(2)
                        .any(|w| {
                            w[0] == 0x15 || w[0] == 0x14 // ISZERO or EQ (check result)
                        });
                    
                    if !checks_return {
                        vulnerabilities.push(BlobMevExtractionVulnerability::UnverifiedBlobCommitment {
                            description: "KZG precompile called but return value not checked".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 6: Check for blob data availability windows
        // Blobs are only available for ~18 days
        let handles_blob_expiry = self.handles_blob_data_expiry();
        
        if !handles_blob_expiry {
            let uses_blobs = self.bytecode.iter().any(|&b| b == 0x49 || b == 0x4a);
            
            if uses_blobs {
                vulnerabilities.push(BlobMevExtractionVulnerability::CrossDomainTimingRisk {
                    description: "Uses blob data without handling expiry - can fail after ~18 days".to_string(),
                    location: 0,
                });
            }
        }
        
        // Pattern 7: Check for blob gas price spikes
        // Searchers can manipulate blob gas market
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x4a { // BLOBBASEFEE
                // Check if there's a maximum gas price check
                let has_max_check = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .windows(4)
                    .any(|w| {
                        // PUSH (max price), LT, ISZERO, JUMPI
                        (w[0] >= 0x60 && w[0] <= 0x7f) &&
                        w[1] == 0x10 &&
                        w[2] == 0x15 &&
                        w[3] == 0x57
                    });
                
                if !has_max_check {
                    vulnerabilities.push(BlobMevExtractionVulnerability::MissingBlobGasProtection {
                        description: "No maximum blob gas price check - vulnerable to price manipulation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_blob_mev_protection(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 60, self.bytecode.len());
        
        // Look for: commit-reveal, timelock, or signature verification
        let has_commit_reveal = self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x20); // KECCAK256 (for commitments)
        
        let has_timelock = self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x42); // TIMESTAMP
        
        has_commit_reveal || has_timelock
    }
    
    fn verifies_blob_commitment(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 40, self.bytecode.len());
        
        // Should see comparison with expected hash
        self.bytecode[location..end]
            .windows(3)
            .any(|w| {
                w[0] == 0x14 && // EQ
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (revert if not equal)
            })
    }
    
    fn is_batch_processing_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Batch processing typically has loops and multiple state updates
        let has_loop = section.windows(3).any(|w| {
            w[0] == 0x56 || w[0] == 0x57 // JUMP or JUMPI (loop back)
        });
        
        let has_multiple_sstores = section.iter().filter(|&&b| b == 0x55).count() > 3;
        
        has_loop && has_multiple_sstores
    }
    
    fn has_ordering_protection(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        
        // Look for sequence number or nonce checks
        self.bytecode[location..end]
            .windows(5)
            .any(|w| {
                // SLOAD (nonce), ADD (increment), EQ (check)
                w[0] == 0x54 &&
                w[1] == 0x01 &&
                w[3] == 0x14
            })
    }
    
    fn is_cross_domain_relay(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 70, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Cross-domain relays typically:
        // 1. Emit events (for L2)
        // 2. Make external calls
        // 3. Have specific selectors
        
        let emits_event = section.iter().any(|&b| b >= 0xa0 && b <= 0xa4);
        let has_external_call = section.iter().any(|&b| b == 0xf1);
        
        emits_event && has_external_call
    }
    
    fn has_timing_protection(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 70, self.bytecode.len());
        
        // Look for TIMESTAMP or NUMBER checks
        self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x42 || b == 0x43) // TIMESTAMP or NUMBER
    }
    
    fn handles_blob_data_expiry(&self) -> bool {
        // Look for time-based fallbacks or explicit expiry handling
        // Pattern: TIMESTAMP comparison with large value (18 days ≈ 1.5M seconds)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Look for comparison with large timeout value
                let has_large_comparison = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .windows(4)
                    .any(|w| {
                        // PUSH with large value (days worth of seconds)
                        (w[0] == 0x62 || w[0] == 0x63) && // PUSH3 or PUSH4
                        (w[1] > 0x01) // Large value
                    });
                
                if has_large_comparison {
                    return true;
                }
            }
        }
        
        false
    }
}
