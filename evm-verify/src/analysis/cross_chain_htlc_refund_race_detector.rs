use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcRefundRaceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossChainHtlcRefundRaceDetector {
    bytecode: Vec<u8>,
}

impl CrossChainHtlcRefundRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HtlcRefundRaceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_simultaneous_claim_refund());
        vulnerabilities.extend(self.detect_missing_claim_priority());
        vulnerabilities.extend(self.detect_refund_race_window());

        vulnerabilities
    }

    fn detect_simultaneous_claim_refund(&self) -> Vec<HtlcRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for refund logic (TIMESTAMP check for expiry)
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for time comparison (GT or GTE for expiry)
                let has_expiry_check = window.iter().any(|&b| matches!(b, 0x11 | 0x13)); // GT, SGT
                
                if has_expiry_check {
                    // Look for transfer operation
                    let has_transfer = window.iter().any(|&b| matches!(b, 0xF1 | 0xF0)); // CALL, CREATE
                    
                    // Check for mutex/reentrancy guard to prevent race
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Look for state flag check (SLOAD -> ISZERO pattern for unclaimed flag)
                    let has_state_mutex = pre_window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x15);
                    
                    if has_transfer && !has_state_mutex {
                        vulns.push(HtlcRefundRaceVulnerability {
                            pc,
                            vulnerability_type: "SimultaneousClaimRefund".to_string(),
                            description: format!(
                                "HTLC refund at PC {} vulnerable to race with claim transaction. \
                                Missing atomic state transition prevents: simultaneous execution of claim \
                                and refund in same block, double-spending via cross-chain coordination, \
                                MEV extraction by forcing race condition. Both parties can execute at \
                                timelock boundary.",
                                pc
                            ),
                            confidence: 0.88,
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

    fn detect_missing_claim_priority(&self) -> Vec<HtlcRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for preimage verification (claim path)
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_hash_check = window.iter().any(|&b| b == 0x14); // EQ
                
                if has_hash_check {
                    // Check if claim has priority over refund even at boundary
                    // Look for strict time comparison that gives claim priority
                    let has_strict_before = window.iter().enumerate().any(|(i, &b)| {
                        b == 0x10 && i + 1 < window.len() // LT (strictly before expiry)
                    });
                    
                    let has_timestamp = window.iter().any(|&b| b == 0x42);
                    
                    // If using GTE instead of LT for claim validation
                    if has_timestamp && !has_strict_before {
                        vulns.push(HtlcRefundRaceVulnerability {
                            pc,
                            vulnerability_type: "MissingClaimPriority".to_string(),
                            description: format!(
                                "HTLC claim at PC {} lacks priority mechanism over refund. \
                                Using inclusive time bounds allows: ambiguous state at timelock expiry, \
                                both claim and refund valid simultaneously, miner/sequencer manipulation \
                                to choose winner. Should enforce claim priority with strict LT comparison \
                                and state-based mutex.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_refund_race_window(&self) -> Vec<HtlcRefundRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut refund_paths = 0;
        let mut claim_paths = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Count refund paths (TIMESTAMP + GT/GTE)
            if opcode == 0x42 {
                let window_end = (pc + 20).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0x11 | 0x13)) {
                    refund_paths += 1;
                }
            }
            
            // Count claim paths (KECCAK256 + EQ)
            if opcode == 0x20 {
                let window_end = (pc + 20).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().any(|&b| b == 0x14) {
                    claim_paths += 1;
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If multiple refund/claim paths without proper coordination
        if refund_paths > 0 && claim_paths > 0 {
            // Check for shared state management
            let mut sstore_count = 0;
            let mut sload_count = 0;
            
            for &byte in &self.bytecode {
                if byte == 0x55 { sstore_count += 1; }
                if byte == 0x54 { sload_count += 1; }
            }
            
            // Low state operations suggest missing coordination
            if sstore_count < 2 || sload_count < 2 {
                vulns.push(HtlcRefundRaceVulnerability {
                    pc: 0,
                    vulnerability_type: "RefundRaceWindow".to_string(),
                    description: format!(
                        "Contract has {} claim paths and {} refund paths with insufficient state coordination \
                        ({} SSTORE, {} SLOAD). Vulnerable to: cross-chain race attacks where both parties \
                        attempt execution at timelock expiry, blockchain reorganization exploitation, \
                        and MEV-driven transaction ordering manipulation. Missing atomic claim/refund mutex.",
                        claim_paths, refund_paths, sstore_count, sload_count
                    ),
                    confidence: 0.79,
                });
            }
        }

        vulns
    }
}
