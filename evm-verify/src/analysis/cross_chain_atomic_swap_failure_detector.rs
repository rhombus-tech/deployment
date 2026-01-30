use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainAtomicSwapFailureVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossChainAtomicSwapFailureDetector {
    bytecode: Vec<u8>,
}

impl CrossChainAtomicSwapFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainAtomicSwapFailureVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_htlc_preimage_exposure());
        vulnerabilities.extend(self.detect_timelock_asymmetry());
        vulnerabilities.extend(self.detect_missing_atomicity());

        vulnerabilities
    }

    fn detect_htlc_preimage_exposure(&self) -> Vec<CrossChainAtomicSwapFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // KECCAK256 hash verification (hash lock)
            if opcode == 0x20 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window_end = (pc + 80).min(self.bytecode.len());
                
                // Check for equality comparison (hash verification)
                let has_eq = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x14);
                
                // Check for value transfer after hash check
                let has_transfer = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0xF1);
                
                if has_eq && has_transfer {
                    // Check for preimage storage (SSTORE before transfer)
                    let stores_preimage = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                    
                    if stores_preimage {
                        vulns.push(CrossChainAtomicSwapFailureVulnerability {
                            pc,
                            vulnerability_type: "HTLCPreimageExposure".to_string(),
                            description: format!(
                                "HTLC at PC {} stores preimage on-chain before completion. Cross-chain race: \
                                (1) Alice reveals preimage on Chain A, (2) Bob sees it in mempool/block, \
                                (3) Bob claims on Chain B before Alice's tx confirms on A, (4) Alice gets nothing, \
                                Bob gets both sides. Use submarine sends or time-locked encryption.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_timelock_asymmetry(&self) -> Vec<CrossChainAtomicSwapFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // TIMESTAMP timelock check
            if opcode == 0x42 {
                let window_end = (pc + 40).min(self.bytecode.len());
                
                // Check for LT/GT comparison (timelock validation)
                let has_comparison = self.bytecode[(pc + 1)..window_end].iter()
                    .any(|&b| b == 0x10 || b == 0x11); // LT or GT
                
                if has_comparison {
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    
                    // Check for hash verification nearby (HTLC pattern)
                    let has_hash_check = self.bytecode[start..window_end].iter().any(|&b| b == 0x20);
                    
                    if has_hash_check {
                        // Count unique timestamp constants (should have 2: claim window + refund window)
                        let push_count = self.bytecode[start..window_end]
                            .iter()
                            .filter(|&&b| b >= 0x60 && b <= 0x7F)
                            .count();
                        
                        if push_count < 2 {
                            vulns.push(CrossChainAtomicSwapFailureVulnerability {
                                pc,
                                vulnerability_type: "TimelockAsymmetry".to_string(),
                                description: format!(
                                    "HTLC timelock at PC {} missing dual-window structure. Atomic swap needs: \
                                    (1) Claim window (Alice can claim with preimage), (2) Refund window (Bob refunds if Alice doesn't claim). \
                                    Single timelock enables: Alice claims on A after timelock, Bob can't refund on B yet. \
                                    Use: claimDeadline < refundDeadline with sufficient gap.",
                                    pc
                                ),
                                confidence: 0.80,
                            });
                        }
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_missing_atomicity(&self) -> Vec<CrossChainAtomicSwapFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // External CALL (potential cross-chain bridge call)
            if opcode == 0xF1 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window_end = (pc + 100).min(self.bytecode.len());
                
                // Check for value transfer
                let has_value = self.bytecode[start..pc].iter().any(|&b| b == 0x34); // CALLVALUE
                
                // Check for state update after call (non-atomic pattern)
                let has_sstore_after = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x55);
                
                if has_value && has_sstore_after {
                    // Check for success validation
                    let has_success_check = self.bytecode[(pc + 1)..window_end].windows(3).any(|w| {
                        w[0] == 0x15 && w[1] == 0x57 // ISZERO + JUMPI (revert if call failed)
                    });
                    
                    if !has_success_check {
                        vulns.push(CrossChainAtomicSwapFailureVulnerability {
                            pc,
                            vulnerability_type: "MissingAtomicity".to_string(),
                            description: format!(
                                "Cross-chain value transfer at PC {} without atomicity guarantee. Call can fail on \
                                destination chain but source state still updates. Creates: (1) Funds locked on source, \
                                (2) Partial execution, (3) No rollback mechanism. Add: require(call.success) or implement \
                                full 2-phase commit with refund path.",
                                pc
                            ),
                            confidence: 0.75,
                        });
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
